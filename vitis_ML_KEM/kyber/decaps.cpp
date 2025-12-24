#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <cstring>

// --- EXTERN DECLARATIONS ---
// (Giữ nguyên phần khai báo extern như cũ)
extern void keccak_f1600(uint64_t state[25]); 
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

extern void sha3_512_64bytes(uint8 input[64], uint8 output[64]);
extern void sha3_256_hash(uint8* input, int in_len, uint8 output[32]);
extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);

#define SK_SIZE 2400
#define CT_SIZE 1088
#define SS_SIZE 32

void ml_kem_decaps(
    uint8 sk_in[SK_SIZE],
    uint8 ct_in[CT_SIZE],
    uint8 ss_out[SS_SIZE]
) {
    // --- 1. AXI INTERFACE OPTIMIZED ---
    // Thêm max_widen_bitwidth=128 để mở rộng bus dữ liệu
    #pragma HLS INTERFACE m_axi port=sk_in bundle=gmem0 depth=2400 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=ct_in bundle=gmem0 depth=1088 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=ss_out bundle=gmem1 depth=32 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return

    // --- 2. RESOURCE ALLOCATION (2-LANE SAFE) ---
    #pragma HLS ALLOCATION function instances=keccak_f1600 limit=2
    #pragma HLS ALLOCATION function instances=ntt limit=2
    #pragma HLS ALLOCATION function instances=inv_ntt limit=2
    #pragma HLS ALLOCATION function instances=poly_pointwise limit=2
    
    #pragma HLS ALLOCATION function instances=poly_compress_u limit=2
    #pragma HLS ALLOCATION function instances=poly_decompress_u limit=2

    // --- 3. BUFFER PARTITIONING ---
    // Factor=2 cho các mảng hệ số để khớp với NTT factor=2
    
    int16 s_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=2 cyclic factor=2 // Khớp với NTT

    int16 u_poly[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=2 cyclic factor=2

    int16 v_poly[KYBER_N]; // Scalar
    #pragma HLS ARRAY_PARTITION variable=v_poly cyclic factor=2

    // --- 1. UNPACK ---
    Unpack_SK_Loop: for(int i=0; i<KYBER_K; i++) {
        // Tự động nhanh hơn nhờ AXI 128-bit
        poly_frombytes(&sk_in[i*384], s_hat[i]);
    }

    Unpack_CT_Loop: for(int i=0; i<KYBER_K; i++) {
        poly_decompress_u(&ct_in[i*320], u_poly[i]);
    }
    poly_decompress_v(&ct_in[KYBER_K*320], v_poly);

    // --- 2. DECRYPT ---
    int16 u_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_hat dim=2 cyclic factor=2

    NTT_U_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL factor=2 
        for(int k=0; k<KYBER_N; k++) {
            #pragma HLS PIPELINE II=1
            u_hat[i][k] = u_poly[i][k];
        }
        ntt(u_hat[i]); 
    }

    int16 res_acc[KYBER_N] = {0};
    #pragma HLS ARRAY_PARTITION variable=res_acc cyclic factor=2 // Optimized acc

    int16 prod_temp[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=prod_temp dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=prod_temp dim=2 cyclic factor=2 // (NEW: Fix bottleneck)

    Pointwise_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL factor=2 
        poly_pointwise(s_hat[i], u_hat[i], prod_temp[i]);
    }

    // Sum reduction
    Sum_Loop: for(int k=0; k<KYBER_N; k++) {
        #pragma HLS PIPELINE II=1
        int32_t sum = 0;
        for(int i=0; i<KYBER_K; i++) sum += prod_temp[i][k];
        res_acc[k] = (int16)(sum % KYBER_Q);
    }
    
    inv_ntt(res_acc);

    uint8 m_prime[32];
    #pragma HLS ARRAY_PARTITION variable=m_prime complete // Register
    
    Recover_Msg_Loop: for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        uint8 byte = 0;
        for(int j=0; j<8; j++) {
            int16 val = res_acc[i*8+j] - v_poly[i*8+j];
            if (val < 0) val += KYBER_Q;
            int16 q_4 = (KYBER_Q + 2) / 4;    
            int16 q_34 = 3 * KYBER_Q / 4;     
            if (val > q_4 && val < q_34) byte |= (1 << j);
        }
        m_prime[i] = byte;
    }

    // --- 3. RE-ENCRYPT ---
    uint8 g_in[64];
    #pragma HLS ARRAY_PARTITION variable=g_in complete // Register
    for(int i=0; i<32; i++) g_in[i] = m_prime[i];
    for(int i=0; i<32; i++) g_in[32+i] = sk_in[2336+i]; 
    
    uint8 Kr_prime[64];
    #pragma HLS ARRAY_PARTITION variable=Kr_prime complete
    sha3_512_64bytes(g_in, Kr_prime); 
    
    uint8 seed_r_prime[32];
    #pragma HLS ARRAY_PARTITION variable=seed_r_prime complete
    for(int i=0; i<32; i++) seed_r_prime[i] = Kr_prime[32+i];

    int16 t_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=2 cyclic factor=2
    
    uint8* pk_ptr = &sk_in[1152];
    for(int i=0; i<KYBER_K; i++) {
        poly_frombytes(&pk_ptr[i*384], t_hat[i]);
    }
    
    uint8 rho[32];
    #pragma HLS ARRAY_PARTITION variable=rho complete
    for(int i=0; i<32; i++) rho[i] = pk_ptr[1152+i];

    int16 r_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=2 cyclic factor=2
    
    int16 e1[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=e1 dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=e1 dim=2 cyclic factor=2
    
    Gen_Noise_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL factor=2 
        
        uint8 prf_in_r[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in_r complete
        for(int k=0; k<32; k++) prf_in_r[k] = seed_r_prime[k];
        prf_in_r[32] = i; 
        
        uint64_t cbd_out_r[16];
        shake256_prf(prf_in_r, cbd_out_r);
        int16 temp_r[256];
        #pragma HLS ARRAY_PARTITION variable=temp_r cyclic factor=2
        
        cbd_eta2((ap_uint<64>*)cbd_out_r, temp_r);
        ntt(temp_r);
        for(int k=0; k<256; k++) r_hat[i][k] = temp_r[k];

        uint8 prf_in_e1[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in_e1 complete
        for(int k=0; k<32; k++) prf_in_e1[k] = seed_r_prime[k];
        prf_in_e1[32] = 3 + i;

        uint64_t cbd_out_e1[16];
        shake256_prf(prf_in_e1, cbd_out_e1);
        cbd_eta2((ap_uint<64>*)cbd_out_e1, e1[i]);
    }

    int16 e2[256];
    #pragma HLS ARRAY_PARTITION variable=e2 cyclic factor=2
    {
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = 6;
        uint64_t cbd_out[16];
        shake256_prf(prf_in, cbd_out);
        cbd_eta2((ap_uint<64>*)cbd_out, e2);
    }

    // Calc u'
    int16 u_prime[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_prime dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_prime dim=2 cyclic factor=2

    Calc_U_Prime_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL factor=2 
        
        int16 acc[256] = {0};
        #pragma HLS ARRAY_PARTITION variable=acc cyclic factor=2
        
        for(int j=0; j<KYBER_K; j++) {
            int16 A_ij[KYBER_N];
            #pragma HLS ARRAY_PARTITION variable=A_ij cyclic factor=2
            
            ap_uint<64> xof_in[5];
            #pragma HLS ARRAY_PARTITION variable=xof_in complete
            for(int w=0; w<4; w++) {
                uint64_t val = 0;
                for(int b=0; b<8; b++) val |= ((uint64_t)rho[w*8+b] << (b*8));
                xof_in[w] = val;
            }
            xof_in[4] = (uint64_t)i | ((uint64_t)j << 8); 
            
            hls::stream<uint8> strm;
            #pragma HLS STREAM variable=strm depth=256
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_ij);
            
            int16 prod[256];
            #pragma HLS ARRAY_PARTITION variable=prod cyclic factor=2
            poly_pointwise(A_ij, r_hat[j], prod);
            
            for(int k=0; k<256; k++) {
                #pragma HLS PIPELINE II=1
                acc[k] = (int16)(((int32_t)acc[k] + prod[k]) % KYBER_Q);
            }
        }
        inv_ntt(acc);
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            int32_t val = (int32_t)acc[k] + e1[i][k];
            u_prime[i][k] = (int16)((val % KYBER_Q + KYBER_Q) % KYBER_Q);
        }
    }
    
    // Calc v'
    int16 v_acc[256] = {0};
    #pragma HLS ARRAY_PARTITION variable=v_acc cyclic factor=2
    
    int16 v_prod_temp[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=v_prod_temp dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=v_prod_temp dim=2 cyclic factor=2 // (NEW)

    for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL factor=2 
        poly_pointwise(t_hat[i], r_hat[i], v_prod_temp[i]);
    }
    
    for(int k=0; k<256; k++) {
        #pragma HLS PIPELINE II=1
        int32_t sum = 0;
        for(int i=0; i<KYBER_K; i++) sum += v_prod_temp[i][k];
        v_acc[k] = (int16)(sum % KYBER_Q);
    }
    inv_ntt(v_acc);
    
    int16 m_poly_new[256];
    #pragma HLS ARRAY_PARTITION variable=m_poly_new cyclic factor=2
    poly_frommsg(m_prime, m_poly_new);
    
    int16 v_prime[256];
    #pragma HLS ARRAY_PARTITION variable=v_prime cyclic factor=2
    for(int k=0; k<256; k++) {
        #pragma HLS PIPELINE II=1
        int32_t val = (int32_t)v_acc[k] + e2[k] + m_poly_new[k];
        v_prime[k] = (int16)((val % KYBER_Q + KYBER_Q) % KYBER_Q);
    }

    // --- 4. COMPARE ---
    uint8 fail = 0;
    for(int i=0; i<KYBER_K; i++) {
        uint8 cmp_buf[320];
        // Không partition cmp_buf vì poly_compress_u trong serializer (bản cũ)
        // đang xử lý tuần tự hoặc 4-block. Để mặc định an toàn hơn.
        
        poly_compress_u(u_prime[i], cmp_buf);
        for(int k=0; k<320; k++) {
            #pragma HLS PIPELINE II=1
            if (ct_in[i*320 + k] != cmp_buf[k]) fail = 1;
        }
    }
    
    uint8 v_cmp_buf[128];
    poly_compress_v(v_prime, v_cmp_buf);
    for(int k=0; k<128; k++) {
        #pragma HLS PIPELINE II=1
        if (ct_in[KYBER_K*320 + k] != v_cmp_buf[k]) fail = 1;
    }

    if (fail == 0) {
        for(int i=0; i<32; i++) ss_out[i] = Kr_prime[i];
    } else {
        uint8 fail_input[32 + CT_SIZE];
        for(int i=0; i<32; i++) fail_input[i] = sk_in[2368+i]; 
        for(int i=0; i<CT_SIZE; i++) fail_input[32+i] = ct_in[i]; 
        
        uint8 fail_hash[64];
        sha3_512_64bytes(fail_input, fail_hash);
        for(int i=0; i<32; i++) ss_out[i] = 0xFF; 
    }
}