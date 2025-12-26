#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <cstring>

// --- EXTERN DECLARATIONS ---
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

extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);

// Local static helpers
static void sha3_512_64bytes_decaps(uint8 input[64], uint8 output[64]) {
    #pragma HLS INLINE off
    uint64_t state[25] = {0};
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    for(int i=0; i<8; i++) {
        #pragma HLS UNROLL
        uint64_t w = 0;
        for(int j=0; j<8; j++) w |= ((uint64_t)input[i*8+j] << (j*8));
        state[i] ^= w;
    }
    state[8] ^= 0x06; 
    state[8] ^= (1ULL << 63);
    keccak_f1600(state);
    for(int i=0; i<8; i++) {
        #pragma HLS UNROLL
        uint64_t w = state[i];
        for(int j=0; j<8; j++) output[i*8+j] = (uint8)(w >> (j*8));
    }
}

#define SK_SIZE 2400
#define CT_SIZE 1088
#define SS_SIZE 32

void ml_kem_decaps(
    uint8 sk_in[SK_SIZE],
    uint8 ct_in[CT_SIZE],
    uint8 ss_out[SS_SIZE]
) {
    #pragma HLS INTERFACE m_axi port=sk_in bundle=gmem0 depth=2400 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=ct_in bundle=gmem1 depth=1088 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=ss_out bundle=gmem2 depth=32 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return

    // Resources: Limit 3 for parallelism
    #pragma HLS ALLOCATION function instances=keccak_f1600 limit=3
    #pragma HLS ALLOCATION function instances=ntt limit=3
    #pragma HLS ALLOCATION function instances=inv_ntt limit=3
    #pragma HLS ALLOCATION function instances=poly_pointwise limit=3

    // Buffers Factor=2
    int16 s_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=2 cyclic factor=2

    int16 u_poly[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_poly dim=2 cyclic factor=2

    int16 v_poly[KYBER_N]; 
    #pragma HLS ARRAY_PARTITION variable=v_poly cyclic factor=2

    uint8 sk_local[SK_SIZE];
    #pragma HLS ARRAY_RESHAPE variable=sk_local cyclic factor=16
    uint8 ct_local[CT_SIZE];
    #pragma HLS ARRAY_RESHAPE variable=ct_local cyclic factor=16

    memcpy(sk_local, sk_in, SK_SIZE);
    memcpy(ct_local, ct_in, CT_SIZE);

    // --- DECODE ---
    Unpack_SK_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        poly_frombytes(&sk_local[i*384], s_hat[i]);
    }
    Unpack_CT_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        poly_decompress_u(&ct_local[i*320], u_poly[i]);
    }
    poly_decompress_v(&ct_local[KYBER_K*320], v_poly);

    // --- DECRYPT ---
    int16 u_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=u_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=u_hat dim=2 cyclic factor=2

    NTT_U_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            u_hat[i][k] = u_poly[i][k];
        }
        ntt(u_hat[i]); 
    }

    int16 res_acc[KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=res_acc cyclic factor=2
    
    int16 prod_matrix[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=prod_matrix dim=1 complete
    #pragma HLS ARRAY_PARTITION variable=prod_matrix dim=2 cyclic factor=2
    
    Pointwise_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        poly_pointwise(s_hat[i], u_hat[i], prod_matrix[i]);
    }

    Sum_Loop: for(int k=0; k<256; k++) {
        #pragma HLS PIPELINE II=2 
        ap_int<16> sum = 0;
        for(int i=0; i<KYBER_K; i++) sum += prod_matrix[i][k];
        while(sum >= KYBER_Q) sum -= KYBER_Q;
        if(sum < 0) sum += KYBER_Q; 
        res_acc[k] = (int16)sum;
    }
    inv_ntt(res_acc);

    uint8 m_prime[32];
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
    for(int i=0; i<32; i++) g_in[i] = m_prime[i];
    for(int i=0; i<32; i++) g_in[32+i] = sk_local[2336+i]; 
    
    uint8 Kr_prime[64];
    #pragma HLS ARRAY_PARTITION variable=Kr_prime complete
    sha3_512_64bytes_decaps(g_in, Kr_prime); 
    
    uint8 seed_r_prime[32];
    #pragma HLS ARRAY_PARTITION variable=seed_r_prime complete
    for(int i=0; i<32; i++) seed_r_prime[i] = Kr_prime[32+i];

    uint8* pk_ptr = &sk_local[1152];
    uint8 rho[32];
    #pragma HLS ARRAY_PARTITION variable=rho complete
    int16 t_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=2 cyclic factor=2
    
    for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        poly_frombytes(&pk_ptr[i*384], t_hat[i]);
    }
    for(int i=0; i<32; i++) rho[i] = pk_ptr[1152+i];

    int16 r_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=1 complete
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=2 cyclic factor=2
    
    int16 u_prime[KYBER_K][KYBER_N] = {0}; // Initialize to 0 for accumulation
    #pragma HLS ARRAY_PARTITION variable=u_prime dim=1 complete
    #pragma HLS ARRAY_PARTITION variable=u_prime dim=2 cyclic factor=2

    // --- FUSED MATRIX GEN & MULTIPLICATION ---
    // Outer Loop: Columns j (Sequential)
    // Inner Loop: Rows i (Parallel)
    Fused_Gen_Loop: for(int j=0; j<KYBER_K; j++) {
        
        // 1. Generate r[j] (Sequential part for this col)
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = (uint8)j; // nonce for r is 0,1,2 (same as j)
        
        uint64_t cbd_out_r[16];
        shake256_prf(prf_in, cbd_out_r);
        
        int16 temp_r[256];
        #pragma HLS ARRAY_PARTITION variable=temp_r cyclic factor=2
        cbd_eta2((ap_uint<64>*)cbd_out_r, temp_r);
        ntt(temp_r);
        
        // Store r_hat[j] for later use (v_prime)
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            r_hat[j][k] = temp_r[k];
        }

        // 2. Matrix Mult Column j: A[j][i] * r[j]
        // This runs for all rows i=0,1,2 in PARALLEL
        Parallel_Row_Loop: for(int i=0; i<KYBER_K; i++) {
            #pragma HLS UNROLL
            
            // Gen A[j][i] (Transpose logic: matrix A is row-major normally, but we gen A^T)
            // A_hat definition in standard is A[i][j].
            // We need A^T * r => u[i] += A[j][i] * r[j]
            // We generate A[j][i] on the fly.
            
            ap_uint<64> xof_in[5];
            #pragma HLS ARRAY_PARTITION variable=xof_in complete
            for(int w=0; w<4; w++) {
                #pragma HLS UNROLL
                uint64_t val = 0;
                for(int b=0; b<8; b++) val |= ((uint64_t)rho[w*8+b] << (b*8));
                xof_in[w] = val;
            }
            xof_in[4] = (uint64_t)i | ((uint64_t)j << 8); // index j, i
            
            hls::stream<uint8> strm;
            #pragma HLS STREAM variable=strm depth=256
            int16 A_ji[256];
            #pragma HLS ARRAY_PARTITION variable=A_ji cyclic factor=2
            
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_ji);
            
            int16 prod[256];
            poly_pointwise(A_ji, temp_r, prod); // Use temp_r directly
            
            // Accumulate into u_prime
            for(int k=0; k<256; k++) {
                #pragma HLS PIPELINE II=2
                ap_int<16> sum = (ap_int<16>)u_prime[i][k] + prod[k];
                while(sum >= KYBER_Q) sum -= KYBER_Q;
                u_prime[i][k] = (int16)sum;
            }
        }
    }

    // Finalize u_prime: InvNTT and Add e1
    Finalize_U_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        
        // Inverse NTT for u[i]
        inv_ntt(u_prime[i]);
        
        // Gen e1[i] and Add
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = (uint8)(3 + i); 
        
        uint64_t cbd_out_e1[16];
        shake256_prf(prf_in, cbd_out_e1);
        int16 e1_i[256];
        #pragma HLS ARRAY_PARTITION variable=e1_i cyclic factor=2
        cbd_eta2((ap_uint<64>*)cbd_out_e1, e1_i);
        
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val = (ap_int<16>)u_prime[i][k] + e1_i[k];
            while(val >= KYBER_Q) val -= KYBER_Q;
            if(val < 0) val += KYBER_Q;
            u_prime[i][k] = (int16)val;
        }
    }

    // Calc v_prime
    int16 v_prime[256];
    #pragma HLS ARRAY_PARTITION variable=v_prime cyclic factor=2
    
    // Gen e2
    int16 e2[256];
    #pragma HLS ARRAY_PARTITION variable=e2 cyclic factor=2
    {
        uint8 prf_in[33];
        for(int k=0; k<32; k++) prf_in[k] = seed_r_prime[k];
        prf_in[32] = 6;
        uint64_t cbd_out[16];
        shake256_prf(prf_in, cbd_out);
        cbd_eta2((ap_uint<64>*)cbd_out, e2);
    }
    
    // v = t*r + e2 + m
    {
        int16 v_acc[256] = {0};
        #pragma HLS ARRAY_PARTITION variable=v_acc cyclic factor=2
        for(int i=0; i<KYBER_K; i++) {
            #pragma HLS UNROLL
            int16 prod[256];
            poly_pointwise(t_hat[i], r_hat[i], prod);
            for(int k=0; k<256; k++) {
                #pragma HLS PIPELINE II=2
                ap_int<16> sum = (ap_int<16>)v_acc[k] + prod[k];
                while(sum >= KYBER_Q) sum -= KYBER_Q;
                v_acc[k] = (int16)sum;
            }
        }
        inv_ntt(v_acc);
        int16 m_poly_new[256];
        poly_frommsg(m_prime, m_poly_new);
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val = (ap_int<16>)v_acc[k] + e2[k] + m_poly_new[k];
            while(val >= KYBER_Q) val -= KYBER_Q;
            if(val < 0) val += KYBER_Q;
            v_prime[k] = (int16)val;
        }
    }

    // Compare
    uint8 fail = 0;
    for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        uint8 cmp_buf[320];
        poly_compress_u(u_prime[i], cmp_buf);
        for(int k=0; k<320; k++) {
            #pragma HLS PIPELINE II=1
            if (ct_local[(int)(i*320 + k)] != cmp_buf[k]) fail = 1;
        }
    }
    uint8 v_cmp_buf[128];
    poly_compress_v(v_prime, v_cmp_buf);
    for(int k=0; k<128; k++) {
        #pragma HLS PIPELINE II=1
        if (ct_local[(int)(KYBER_K*320 + k)] != v_cmp_buf[k]) fail = 1;
    }

    if (fail == 0) {
        for(int i=0; i<32; i++) ss_out[i] = Kr_prime[i];
    } else {
        uint8 fail_input[32 + CT_SIZE];
        for(int i=0; i<32; i++) fail_input[i] = sk_local[2368+i]; 
        for(int i=0; i<CT_SIZE; i++) fail_input[32+i] = ct_local[i]; 
        
        uint8 fail_hash[64];
        sha3_512_64bytes_decaps(fail_input, fail_hash);
        for(int i=0; i<32; i++) ss_out[i] = fail_hash[i]; 
    }
}