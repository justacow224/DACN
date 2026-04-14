#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <cstring>
#include <stdint.h>

// --- EXTERN DECLARATIONS ---
extern void keccak_f1600(uint64_t state[25]); 
extern void sha3_512_64bytes(uint8 input[64], uint8 output[64]);
extern void sha3_512_1120bytes(uint8 input[1120], uint8 output[64]);
extern void shake256_33bytes(uint8 input[33], uint64_t output_64[16]);

extern void ntt(int16 poly[256]);
extern void inv_ntt(int16 poly[256]);
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);
extern void parse_ntt(hls::stream<uint8>& in_bytes, int16 a_hat[KYBER_N]);

extern void poly_frombytes(uint8 input[384], int16 coeffs[KYBER_N]);
extern void poly_frommsg(uint8 msg[32], int16 coeffs[KYBER_N]);
extern void poly_decompress_u(uint8 input[320], int16 coeffs[KYBER_N]);
extern void poly_decompress_v(uint8 input[128], int16 coeffs[KYBER_N]);
extern void poly_compress_u(int16 coeffs[KYBER_N], uint8 output[320]);
extern void poly_compress_v(int16 coeffs[KYBER_N], uint8 output[128]);

#define SK_SIZE 2400
#define CT_SIZE 1088
#define SS_SIZE 32

#define SK_SIZE_128 (SK_SIZE / 16)   // 150
#define CT_SIZE_128 (CT_SIZE / 16)   // 68
#define SS_SIZE_128 (SS_SIZE / 16)   // 2

void ml_kem_decaps(
    ap_uint<128> sk_in[SK_SIZE_128],
    ap_uint<128> ct_in[CT_SIZE_128],
    ap_uint<128> ss_out[SS_SIZE_128]
) {
    #pragma HLS INTERFACE m_axi port=sk_in bundle=gmem0 depth=150
    #pragma HLS INTERFACE m_axi port=ct_in bundle=gmem1 depth=68
    #pragma HLS INTERFACE m_axi port=ss_out bundle=gmem2 depth=2
    #pragma HLS INTERFACE s_axilite port=return

    #pragma HLS ALLOCATION function instances=keccak_f1600 limit=1
    #pragma HLS ALLOCATION function instances=ntt limit=1
    #pragma HLS ALLOCATION function instances=inv_ntt limit=1
    #pragma HLS ALLOCATION function instances=poly_pointwise limit=1

    int16 s_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=2 cyclic factor=2

    int16 u_poly[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=2 cyclic factor=2

    int16 v_poly[KYBER_N]; 
    #pragma HLS ARRAY_PARTITION variable=v_poly cyclic factor=2

    uint8 sk_local[SK_SIZE];
    #pragma HLS ARRAY_PARTITION variable=sk_local cyclic factor=16
    uint8 ct_local[CT_SIZE];
    #pragma HLS ARRAY_PARTITION variable=ct_local cyclic factor=16

    // --- UNPACK INPUTS ---
    Unpack_SK_In: for(int i = 0; i < SK_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = sk_in[i];
        for(int j = 0; j < 16; j++) {
            sk_local[i*16 + j] = (uint8)chunk((j*8)+7, j*8);
        }
    }

    Unpack_CT_In: for(int i = 0; i < CT_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = ct_in[i];
        for(int j = 0; j < 16; j++) {
            ct_local[i*16 + j] = (uint8)chunk((j*8)+7, j*8);
        }
    }

    // --- TỐI ƯU DECODE ---
    Unpack_SK_Loop: for(int i=0; i<KYBER_K; i++) {
        // FIXED: Dùng factor=16 để căn lề hoàn hảo (Perfect Alignment) với sk_local
        uint8 temp_sk_chunk[384];
        #pragma HLS ARRAY_PARTITION variable=temp_sk_chunk cyclic factor=16
        for(int w=0; w<24; w++) { // 384/16 = 24
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) temp_sk_chunk[w*16+j] = sk_local[i*384 + w*16+j];
        }
        poly_frombytes(temp_sk_chunk, s_hat[i]);
    }
    Unpack_CT_Loop: for(int i=0; i<KYBER_K; i++) {
        // FIXED: factor=16
        uint8 temp_ct_chunk[320];
        #pragma HLS ARRAY_PARTITION variable=temp_ct_chunk cyclic factor=16
        for(int w=0; w<20; w++) { // 320/16 = 20
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) temp_ct_chunk[w*16+j] = ct_local[i*320 + w*16+j];
        }
        poly_decompress_u(temp_ct_chunk, u_poly[i]);
    }
    
    // FIXED: factor=16
    uint8 temp_ct_v[128];
    #pragma HLS ARRAY_PARTITION variable=temp_ct_v cyclic factor=16
    for(int w=0; w<8; w++) { // 128/16 = 8
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) temp_ct_v[w*16+j] = ct_local[KYBER_K*320 + w*16+j];
    }
    poly_decompress_v(temp_ct_v, v_poly);

    // --- DECRYPT ---
    int16 u_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_hat dim=2 cyclic factor=2

    NTT_U_Loop: for(int i=0; i<KYBER_K; i++) {
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            u_hat[i][k] = u_poly[i][k];
            u_hat[i][k+1] = u_poly[i][k+1];
        }
        ntt(u_hat[i]); 
    }

    int16 res_acc[KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=res_acc cyclic factor=2
    
    int16 prod_matrix[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=prod_matrix dim=1 complete
    #pragma HLS ARRAY_PARTITION variable=prod_matrix dim=2 cyclic factor=2
    
    Pointwise_Loop: for(int i=0; i<KYBER_K; i++) {
        poly_pointwise(s_hat[i], u_hat[i], prod_matrix[i]);
    }

    Sum_Loop: for(int k=0; k<256; k+=2) {
        #pragma HLS PIPELINE II=1 
        ap_int<16> sum0 = 0;
        ap_int<16> sum1 = 0;
        for(int i=0; i<KYBER_K; i++) {
            sum0 += prod_matrix[i][k];
            sum1 += prod_matrix[i][k+1];
        }
        while(sum0 >= KYBER_Q) sum0 -= KYBER_Q;
        if(sum0 < 0) sum0 += KYBER_Q; 
        res_acc[k] = (int16)sum0;

        while(sum1 >= KYBER_Q) sum1 -= KYBER_Q;
        if(sum1 < 0) sum1 += KYBER_Q; 
        res_acc[k+1] = (int16)sum1;
    }
    inv_ntt(res_acc);

    uint8 m_prime[32];
    // Giữ complete cho các mảng siêu nhỏ (<= 64 bytes)
    #pragma HLS ARRAY_PARTITION variable=m_prime complete 
    Recover_Msg_Loop: for(int i=0; i<32; i++) {
        uint8 byte = 0;
        for(int j=0; j<8; j++) {
            #pragma HLS PIPELINE II=1
            int idx = (int)(i*8+j); 
            int16 val = res_acc[idx] - v_poly[idx];
            if (val < 0) val += KYBER_Q;
            if (val > (int16)((KYBER_Q+2)/4) && val < (int16)(3*KYBER_Q/4)) 
                byte |= (uint8)(1 << j);
        }
        m_prime[i] = byte;
    }

    // --- RE-ENCRYPT ---
    uint8 g_in[64];
    #pragma HLS ARRAY_PARTITION variable=g_in complete 
    for(int i=0; i<2; i++) {
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) {
            g_in[i*16+j] = m_prime[i*16+j];
            g_in[32+i*16+j] = sk_local[2336 + i*16+j]; 
        }
    }
    
    uint8 Kr_prime[64];
    #pragma HLS ARRAY_PARTITION variable=Kr_prime complete
    sha3_512_64bytes(g_in, Kr_prime); 
    
    uint8 seed_r_prime[32];
    #pragma HLS ARRAY_PARTITION variable=seed_r_prime complete
    for(int i=0; i<2; i++) {
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) seed_r_prime[i*16+j] = Kr_prime[32 + i*16+j];
    }

    uint8 rho[32];
    #pragma HLS ARRAY_PARTITION variable=rho complete
    int16 t_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=2 cyclic factor=2
    
    // TỐI ƯU COPY PK
    for(int i=0; i<KYBER_K; i++) {
        // FIXED: factor=16
        uint8 temp_pk_chunk[384];
        #pragma HLS ARRAY_PARTITION variable=temp_pk_chunk cyclic factor=16
        for(int w=0; w<24; w++) { // 384/16 = 24
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) temp_pk_chunk[w*16+j] = sk_local[1152 + i*384 + w*16+j];
        }
        poly_frombytes(temp_pk_chunk, t_hat[i]);
    }
    for(int i=0; i<2; i++) {
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) rho[i*16+j] = sk_local[1152 + 1152 + i*16+j]; // 2304
    }

    int16 r_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=1 complete
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=2 cyclic factor=2
    
    int16 u_prime[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_prime dim=1 complete
    #pragma HLS ARRAY_PARTITION variable=u_prime dim=2 cyclic factor=2

    for(int i=0; i<KYBER_K; i++) {
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            u_prime[i][k] = 0;
            u_prime[i][k+1] = 0;
        }
    }

    // --- FUSED MATRIX GEN & MULTIPLICATION ---
    Fused_Gen_Loop: for(int j=0; j<KYBER_K; j++) {
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = (uint8)j; 
        
        uint64_t cbd_out_r[16];
        shake256_33bytes(prf_in, cbd_out_r);
        
        int16 temp_r[256];
        #pragma HLS ARRAY_PARTITION variable=temp_r cyclic factor=2
        cbd_eta2((ap_uint<64>*)cbd_out_r, temp_r);
        ntt(temp_r);
        
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            r_hat[j][k] = temp_r[k];
            r_hat[j][k+1] = temp_r[k+1];
        }

        Parallel_Row_Loop: for(int i=0; i<KYBER_K; i++) {
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
            
            int16 A_ji[256];
            #pragma HLS ARRAY_PARTITION variable=A_ji cyclic factor=2
            
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_ji);
            
            int16 prod[256];
            #pragma HLS ARRAY_PARTITION variable=prod cyclic factor=2
            poly_pointwise(A_ji, temp_r, prod); 
            
            for(int k=0; k<256; k+=2) {
                #pragma HLS PIPELINE II=1
                ap_int<16> sum0 = (ap_int<16>)u_prime[i][k] + prod[k];
                if(sum0 >= KYBER_Q) sum0 -= KYBER_Q;
                u_prime[i][k] = (int16)sum0;

                ap_int<16> sum1 = (ap_int<16>)u_prime[i][k+1] + prod[k+1];
                if(sum1 >= KYBER_Q) sum1 -= KYBER_Q;
                u_prime[i][k+1] = (int16)sum1;
            }
        }
    }

    Finalize_U_Loop: for(int i=0; i<KYBER_K; i++) {
        inv_ntt(u_prime[i]);
        
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = (uint8)(3 + i); 
        
        uint64_t cbd_out_e1[16];
        shake256_33bytes(prf_in, cbd_out_e1);
        int16 e1_i[256];
        #pragma HLS ARRAY_PARTITION variable=e1_i cyclic factor=2
        cbd_eta2((ap_uint<64>*)cbd_out_e1, e1_i);
        
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val0 = (ap_int<16>)u_prime[i][k] + e1_i[k];
            if(val0 >= KYBER_Q) val0 -= KYBER_Q;
            u_prime[i][k] = (int16)val0;

            ap_int<16> val1 = (ap_int<16>)u_prime[i][k+1] + e1_i[k+1];
            if(val1 >= KYBER_Q) val1 -= KYBER_Q;
            u_prime[i][k+1] = (int16)val1;
        }
    }

    // Calc v_prime
    int16 v_prime[256];
    #pragma HLS ARRAY_PARTITION variable=v_prime cyclic factor=2
    
    int16 e2[256];
    #pragma HLS ARRAY_PARTITION variable=e2 cyclic factor=2
    {
        uint8 prf_in[33];
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = 6;
        uint64_t cbd_out[16];
        shake256_33bytes(prf_in, cbd_out);
        cbd_eta2((ap_uint<64>*)cbd_out, e2);
    }
    
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
        int16 m_poly_new[256];
        #pragma HLS ARRAY_PARTITION variable=m_poly_new cyclic factor=2
        poly_frommsg(m_prime, m_poly_new);
        
        for(int k=0; k<256; k+=2) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val0 = (ap_int<16>)v_acc[k] + e2[k] + m_poly_new[k];
            if(val0 >= KYBER_Q) val0 -= KYBER_Q;
            if(val0 < 0) val0 += KYBER_Q;
            v_prime[k] = (int16)val0;

            ap_int<16> val1 = (ap_int<16>)v_acc[k+1] + e2[k+1] + m_poly_new[k+1];
            if(val1 >= KYBER_Q) val1 -= KYBER_Q;
            if(val1 < 0) val1 += KYBER_Q;
            v_prime[k+1] = (int16)val1;
        }
    }

    // --- TỐI ƯU COMPARE ---
    uint8 fail = 0;
    for(int i=0; i<KYBER_K; i++) {
        // FIXED: factor=16
        uint8 cmp_buf[320];
        #pragma HLS ARRAY_PARTITION variable=cmp_buf cyclic factor=16
        poly_compress_u(u_prime[i], cmp_buf);
        
        for(int w=0; w<20; w++) { // 320/16 = 20
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) {
                if (ct_local[i*320 + w*16 + j] != cmp_buf[w*16 + j]) fail = 1;
            }
        }
    }
    
    // FIXED: factor=16
    uint8 v_cmp_buf[128];
    #pragma HLS ARRAY_PARTITION variable=v_cmp_buf cyclic factor=16
    poly_compress_v(v_prime, v_cmp_buf);
    
    for(int w=0; w<8; w++) { // 128/16 = 8
        #pragma HLS PIPELINE II=1
        for(int j=0; j<16; j++) {
            if (ct_local[KYBER_K*320 + w*16 + j] != v_cmp_buf[w*16 + j]) fail = 1;
        }
    }

    uint8 ss_local[32];
    #pragma HLS ARRAY_PARTITION variable=ss_local complete
    if (fail == 0) {
        for(int i=0; i<2; i++) {
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) ss_local[i*16+j] = Kr_prime[i*16+j];
        }
    } else {
        // FIXED: factor=16
        uint8 fail_input[1120]; 
        #pragma HLS ARRAY_PARTITION variable=fail_input cyclic factor=16
        
        for(int w=0; w<2; w++) { // z: 32 bytes
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) fail_input[w*16+j] = sk_local[2368 + w*16+j]; 
        }
        for(int w=0; w<68; w++) { // ct: 1088 bytes
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) fail_input[32 + w*16+j] = ct_local[w*16+j]; 
        }
        
        uint8 fail_hash[64];
        #pragma HLS ARRAY_PARTITION variable=fail_hash complete
        sha3_512_1120bytes(fail_input, fail_hash);
        
        for(int i=0; i<2; i++) {
            #pragma HLS PIPELINE II=1
            for(int j=0; j<16; j++) ss_local[i*16+j] = fail_hash[i*16+j]; 
        }
    }

    // --- PACK OUTPUTS ---
    Pack_SS_Out: for(int i = 0; i < SS_SIZE_128; i++) {
        #pragma HLS PIPELINE II=1
        ap_uint<128> chunk = 0;
        for(int j = 0; j < 16; j++) {
            chunk((j*8)+7, j*8) = ss_local[i*16 + j];
        }
        ss_out[i] = chunk;
    }
}