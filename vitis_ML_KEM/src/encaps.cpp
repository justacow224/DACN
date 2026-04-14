#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <cstring>
#include <stdint.h>

// --- EXTERN DECLARATIONS ---
extern void keccak_f1600(uint64_t state[25]);
extern void sha3_256_1184bytes(uint8 input[1184], uint8 output[32]);
extern void sha3_512_64bytes(uint8 input[64], uint8 output[64]);
extern void shake256_33bytes(uint8 input[33], uint64_t output_64[16]);

extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void ntt(int16 poly[256]);
extern void inv_ntt(int16 poly[256]);
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);
extern void parse_ntt(hls::stream<uint8>& in_bytes, int16 a_hat[KYBER_N]);

extern void poly_frombytes(uint8 input[384], int16 coeffs[KYBER_N]);
extern void poly_frommsg(uint8 msg[32], int16 coeffs[KYBER_N]);
extern void poly_compress_u(int16 coeffs[KYBER_N], uint8 output[320]);
extern void poly_compress_v(int16 coeffs[KYBER_N], uint8 output[128]);

#define PK_SIZE 1184
#define CT_SIZE 1088
#define PK_SIZE_128  (PK_SIZE / 16)   
#define RAND_SIZE_128 (32 / 16)      
#define CT_SIZE_128  (CT_SIZE / 16)   
#define SS_SIZE_128  (32 / 16)       

void ml_kem_encaps(
    ap_uint<128> pk_in[PK_SIZE_128],
    ap_uint<128> randomness_m_in[RAND_SIZE_128],
    ap_uint<128> ct_out[CT_SIZE_128],
    ap_uint<128> ss_out[SS_SIZE_128]
) {
    #pragma HLS INTERFACE m_axi port=pk_in bundle=gmem0 depth=74
    #pragma HLS INTERFACE m_axi port=randomness_m_in bundle=gmem0 depth=2
    #pragma HLS INTERFACE m_axi port=ct_out bundle=gmem1 depth=68
    #pragma HLS INTERFACE m_axi port=ss_out bundle=gmem1 depth=2
    #pragma HLS INTERFACE s_axilite port=return

    #pragma HLS ALLOCATION function instances=keccak_f1600 limit=1
    #pragma HLS ALLOCATION function instances=ntt limit=1
    #pragma HLS ALLOCATION function instances=inv_ntt limit=1
    #pragma HLS ALLOCATION function instances=poly_pointwise limit=1

    int16 t_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=2 cyclic factor=2

    int16 r_hat[KYBER_K][KYBER_N]; 
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=2 cyclic factor=2

    int16 u_poly[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=2 cyclic factor=2

    int16 v_poly[KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=v_poly cyclic factor=2

    uint8 pk_local[PK_SIZE];
    #pragma HLS ARRAY_PARTITION variable=pk_local cyclic factor=16
    uint8 ct_local[CT_SIZE];
    #pragma HLS ARRAY_PARTITION variable=ct_local cyclic factor=16

    // --- UNPACK INPUTS ---
    Unpack_PK_In: for(int i = 0; i < PK_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = pk_in[i];
        for(int j = 0; j < 16; j++) {
            pk_local[i*16 + j] = (uint8)chunk((j*8)+7, j*8);
        }
    }

    uint8 randomness_m[32];
    #pragma HLS ARRAY_PARTITION variable=randomness_m complete
    Unpack_Rand_In: for(int i = 0; i < RAND_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = randomness_m_in[i];
        for(int j = 0; j < 16; j++) {
            randomness_m[i*16 + j] = (uint8)chunk((j*8)+7, j*8);
        }
    }

    // 1. Hashing
    uint8 h_pk[32];
    #pragma HLS ARRAY_PARTITION variable=h_pk complete
    sha3_256_1184bytes(pk_local, h_pk);

    uint8 g_in[64];
    #pragma HLS ARRAY_PARTITION variable=g_in complete
    
    for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        g_in[i] = randomness_m[i];
        g_in[32+i] = h_pk[i];
    }
    
    uint8 Kr[64]; 
    #pragma HLS ARRAY_PARTITION variable=Kr complete
    sha3_512_64bytes(g_in, Kr);
    
    uint8 ss_local[32];
    #pragma HLS ARRAY_PARTITION variable=ss_local complete
    for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        ss_local[i] = Kr[i];
    }

    // --- TỐI ƯU ĐỊNH TUYẾN: Trạm đệm giải nén Khóa công khai ---
    uint8 rho[32];
    #pragma HLS ARRAY_PARTITION variable=rho complete
    
    for(int i=0; i<KYBER_K; i++) {
        // TỐI ƯU: Chuyển sang complete để triệt tiêu cảnh báo Port Conflict
        uint8 temp_pk_chunk[384];
        #pragma HLS ARRAY_PARTITION variable=temp_pk_chunk complete
        
        for(int w=0; w<24; w++) { // 384 / 16 = 24
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) {
                temp_pk_chunk[w*16 + j] = pk_local[i*384 + w*16 + j];
            }
        }
        poly_frombytes(temp_pk_chunk, t_hat[i]);
    }
    
    for(int i=0; i<2; i++) {
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) rho[i*16+j] = pk_local[1152 + i*16 + j];
    }

    // 2. GEN NOISE
    Gen_R_Loop: for(int i=0; i<KYBER_K; i++) {
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = Kr[32+k];
        prf_in[32] = (uint8)i;
        
        uint64_t cbd_input[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_input complete
        shake256_33bytes(prf_in, cbd_input);
        
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];

        int16 poly_temp[256];
        #pragma HLS ARRAY_PARTITION variable=poly_temp cyclic factor=2
        cbd_eta2(cbd_ap, poly_temp);
        ntt(poly_temp);
        
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            r_hat[i][k] = poly_temp[k];
            r_hat[i][k+1] = poly_temp[k+1];
        }
    }

    Gen_E1_Loop: for(int i=0; i<KYBER_K; i++) {
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = Kr[32+k];
        prf_in[32] = (uint8)(i + 3); 
        
        uint64_t cbd_input[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_input complete
        shake256_33bytes(prf_in, cbd_input);
        
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];

        cbd_eta2(cbd_ap, u_poly[i]); 
    }

    int16 e2[256];
    #pragma HLS ARRAY_PARTITION variable=e2 cyclic factor=2
    {
        uint8 prf_in[33];
        for(int k=0; k<32; k++) prf_in[k] = Kr[32+k];
        prf_in[32] = 6;
        uint64_t cbd_input[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_input complete
        shake256_33bytes(prf_in, cbd_input);
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];
        cbd_eta2(cbd_ap, e2);
    }

    // 3. STREAMING MATRIX MULTIPLY
    Calc_U_Loop: for(int i=0; i<KYBER_K; i++) {
        
        int16 acc[256];
        #pragma HLS ARRAY_PARTITION variable=acc cyclic factor=2
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            acc[k] = 0;
            acc[k+1] = 0;
        }
        
        for(int j=0; j<KYBER_K; j++) {
            ap_uint<64> xof_in[5];
            #pragma HLS ARRAY_PARTITION variable=xof_in complete
            for(int w=0; w<4; w++) {
                #pragma HLS UNROLL
                uint64_t val = 0;
                for(int b=0; b<8; b++) val |= ((uint64_t)rho[w*8+b] << (b*8));
                xof_in[w] = val;
            }
            xof_in[4] = (uint64_t)i | ((uint64_t)j << 8);

            hls::stream<uint8> strm;
            #pragma HLS STREAM variable=strm depth=16
            
            int16 A_poly_temp[256];
            #pragma HLS ARRAY_PARTITION variable=A_poly_temp cyclic factor=2
            
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_poly_temp);
            
            int16 prod[256];
            #pragma HLS ARRAY_PARTITION variable=prod cyclic factor=2
            poly_pointwise(A_poly_temp, r_hat[j], prod);
            
            for(int k=0; k<256; k+=2) {
                #pragma HLS PIPELINE II=1
                ap_int<16> sum0 = (ap_int<16>)acc[k] + prod[k];
                if(sum0 >= KYBER_Q) sum0 -= KYBER_Q;
                acc[k] = (int16)sum0;

                ap_int<16> sum1 = (ap_int<16>)acc[k+1] + prod[k+1];
                if(sum1 >= KYBER_Q) sum1 -= KYBER_Q;
                acc[k+1] = (int16)sum1;
            }
        }
        
        inv_ntt(acc);
        
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val0 = (ap_int<16>)acc[k] + u_poly[i][k];
            if(val0 >= KYBER_Q) val0 -= KYBER_Q;
            if(val0 < 0) val0 += KYBER_Q;
            u_poly[i][k] = (int16)val0;

            ap_int<16> val1 = (ap_int<16>)acc[k+1] + u_poly[i][k+1];
            if(val1 >= KYBER_Q) val1 -= KYBER_Q;
            if(val1 < 0) val1 += KYBER_Q;
            u_poly[i][k+1] = (int16)val1;
        }
    }

    // 4. Calc v
    {
        int16 v_acc[256];
        #pragma HLS ARRAY_PARTITION variable=v_acc cyclic factor=2
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            v_acc[k] = 0;
            v_acc[k+1] = 0;
        }

        for(int i=0; i<KYBER_K; i++) {
            int16 prod[256];
            #pragma HLS ARRAY_PARTITION variable=prod cyclic factor=2
            poly_pointwise(t_hat[i], r_hat[i], prod);
            for(int k=0; k<256; k+=2) {
                #pragma HLS PIPELINE II=1
                ap_int<16> sum0 = (ap_int<16>)v_acc[k] + prod[k];
                if(sum0 >= KYBER_Q) sum0 -= KYBER_Q;
                v_acc[k] = (int16)sum0;

                ap_int<16> sum1 = (ap_int<16>)v_acc[k+1] + prod[k+1];
                if(sum1 >= KYBER_Q) sum1 -= KYBER_Q;
                v_acc[k+1] = (int16)sum1;
            }
        }
        inv_ntt(v_acc);

        int16 m_poly[256];
        #pragma HLS ARRAY_PARTITION variable=m_poly cyclic factor=2
        poly_frommsg(randomness_m, m_poly);
        
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val0 = (ap_int<16>)v_acc[k] + e2[k] + m_poly[k];
            if(val0 >= KYBER_Q) val0 -= KYBER_Q;
            if(val0 < 0) val0 += KYBER_Q;
            v_poly[k] = (int16)val0;

            ap_int<16> val1 = (ap_int<16>)v_acc[k+1] + e2[k+1] + m_poly[k+1];
            if(val1 >= KYBER_Q) val1 -= KYBER_Q;
            if(val1 < 0) val1 += KYBER_Q;
            v_poly[k+1] = (int16)val1;
        }
    }

    // 5. Pack Output
    for(int i=0; i<KYBER_K; i++) {
        // TỐI ƯU: Đổi sang complete 
        uint8 temp_ct_chunk[320];
        #pragma HLS ARRAY_PARTITION variable=temp_ct_chunk complete
        
        poly_compress_u(u_poly[i], temp_ct_chunk);

        for(int w=0; w<20; w++) { // 320 / 16 = 20
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) {
                ct_local[i*320 + w*16 + j] = temp_ct_chunk[w*16 + j];
            }
        }
    }
    
    uint8 temp_v_chunk[128];
    #pragma HLS ARRAY_PARTITION variable=temp_v_chunk complete
    poly_compress_v(v_poly, temp_v_chunk);
    
    for(int w=0; w<8; w++) { // 128 / 16 = 8
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) {
            ct_local[KYBER_K*320 + w*16 + j] = temp_v_chunk[w*16 + j];
        }
    }

    Pack_CT_Out: for(int i = 0; i < CT_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = 0;
        for(int j = 0; j < 16; j++) {
            chunk((j*8)+7, j*8) = ct_local[i*16 + j];
        }
        ct_out[i] = chunk;
    }

    Pack_SS_Out: for(int i = 0; i < SS_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = 0;
        for(int j = 0; j < 16; j++) {
            chunk((j*8)+7, j*8) = ss_local[i*16 + j];
        }
        ss_out[i] = chunk;
    }
}