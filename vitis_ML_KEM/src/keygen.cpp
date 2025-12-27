#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <cstring>

// --- EXTERN DECLARATIONS ---
extern void keccak_f1600(uint64_t state[25]); 
extern void sha3_512_hash(uint8 input[33], uint8 output[64]);
extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);
extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void ntt(int16 poly[256]);
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);
extern void parse_ntt(hls::stream<uint8>& in_bytes, int16 a_hat[KYBER_N]);

static void poly_tobytes(int16 coeffs[KYBER_N], uint8 output[384]) {
    #pragma HLS INLINE
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        uint16_t t0 = coeffs[2*i];
        uint16_t t1 = coeffs[2*i+1];
        output[3*i+0] = (uint8)(t0 & 0xFF);
        output[3*i+1] = (uint8)((t0 >> 8) | ((t1 & 0x0F) << 4));
        output[3*i+2] = (uint8)(t1 >> 4);
    }
}

#define PK_SIZE_BYTES (384 * KYBER_K + 32)
#define SK_SIZE_BYTES (384 * KYBER_K)

void ml_kem_keygen(
    ap_uint<64> seed_d[4],
    ap_uint<64> seed_z[4],
    uint8 pk_out[PK_SIZE_BYTES],  
    uint8 sk_out[SK_SIZE_BYTES]   
) {
    #pragma HLS INTERFACE m_axi port=seed_d bundle=gmem0 depth=4 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=seed_z bundle=gmem0 depth=4 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=pk_out bundle=gmem1 depth=1184 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=sk_out bundle=gmem1 depth=1152 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return

    // --- CHIẾN LƯỢC LIMIT = 5 (SWEET SPOT) ---
    // 5 bộ Keccak sẽ xử lý 9 phần tử ma trận trong 2 lượt (5 song song -> 4 song song)
    // Tổng cộng sẽ có 1 bộ cho Hash/Noise + 5 bộ cho Matrix = 6 bộ vật lý được tạo ra
    #pragma HLS ALLOCATION function instances=keccak_f1600 limit=6
    #pragma HLS ALLOCATION function instances=ntt limit=6
    #pragma HLS ALLOCATION function instances=poly_pointwise limit=6

    // --- BUFFERS ---
    int16 s_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=2 cyclic factor=2

    int16 e_hat[KYBER_K][KYBER_N];
    #pragma HLS ARRAY_PARTITION variable=e_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=e_hat dim=2 cyclic factor=2

    uint8 pk_local[PK_SIZE_BYTES];
    #pragma HLS ARRAY_PARTITION variable=pk_local block factor=3 
    uint8 sk_local[SK_SIZE_BYTES];
    #pragma HLS ARRAY_PARTITION variable=sk_local block factor=3

    uint8 rho[32], sigma[32];
    #pragma HLS ARRAY_PARTITION variable=rho complete
    #pragma HLS ARRAY_PARTITION variable=sigma complete

    // Step 1: Hash G
    uint8 g_in[33];
    #pragma HLS ARRAY_PARTITION variable=g_in complete
    for(int i=0; i<4; i++) {
        #pragma HLS UNROLL
        uint64_t w = seed_d[i];
        for(int j=0; j<8; j++) g_in[i*8+j] = (uint8)(w >> (j*8));
    }
    g_in[32] = KYBER_K;

    uint8 g_out[64];
    sha3_512_hash(g_in, g_out);
    for(int i=0; i<32; i++) {
        #pragma HLS UNROLL
        rho[i]   = g_out[i];
        sigma[i] = g_out[32+i];
    }

    uint8 sigma_local[32];
    #pragma HLS ARRAY_PARTITION variable=sigma_local complete
    for(int i=0;i<32;i++) sigma_local[i] = sigma[i];

    // Step 2: Gen s & e (Unroll 3 is fine, uses 3/6 Keccaks)
    Gen_S_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = sigma_local[k];
        prf_in[32] = (uint8)i; 
        
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];

        int16 poly_temp[256];
        #pragma HLS ARRAY_PARTITION variable=poly_temp cyclic factor=2
        cbd_eta2(cbd_ap, poly_temp);
        ntt(poly_temp);
        for(int k=0; k<256; k++) s_hat[i][k] = poly_temp[k];
        poly_tobytes(s_hat[i], &sk_local[i*384]);
    }

    Gen_E_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = sigma_local[k];
        prf_in[32] = (uint8)(3 + i); 
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];
        int16 poly_temp[256];
        #pragma HLS ARRAY_PARTITION variable=poly_temp cyclic factor=2
        cbd_eta2(cbd_ap, poly_temp);
        ntt(poly_temp);
        for(int k=0; k<256; k++) e_hat[i][k] = poly_temp[k];
    }

    // Step 3: Matrix Mult with Limit=6
    Gen_PK_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL 
        
        int16 acc[256];
        #pragma HLS ARRAY_PARTITION variable=acc cyclic factor=2
        
        int16 products[KYBER_K][256];
        #pragma HLS ARRAY_PARTITION variable=products dim=1 complete
        #pragma HLS ARRAY_PARTITION variable=products dim=2 cyclic factor=2

        // UNROLL vòng lặp này: Sẽ yêu cầu 3 bộ Keccak cho mỗi hàng i
        // Tổng cộng 3 hàng x 3 cột = 9 bộ.
        // NHƯNG ta đã set limit=6. HLS sẽ tự động schedule:
        // Cycle T: Chạy 3 bộ cho i=0, và 3 bộ cho i=1. (Tổng 6)
        // Cycle T+n: Chạy nốt 3 bộ cho i=2.
        // -> Rất hiệu quả!
        for(int j=0; j<KYBER_K; j++) {
            #pragma HLS UNROLL 
            
            ap_uint<64> xof_in[5];
            #pragma HLS ARRAY_PARTITION variable=xof_in complete
            for(int w=0; w<4; w++) {
                #pragma HLS UNROLL
                uint64_t val = 0;
                for(int b=0; b<8; b++) val |= ((uint64_t)rho[w*8+b] << (b*8));
                xof_in[w] = val;
            }
            xof_in[4] = (uint64_t)j | ((uint64_t)i << 8); 

            hls::stream<uint8> strm;
            #pragma HLS STREAM variable=strm depth=256
            
            int16 A_poly_temp[256];
            #pragma HLS ARRAY_PARTITION variable=A_poly_temp cyclic factor=2
            
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_poly_temp);
            poly_pointwise(A_poly_temp, s_hat[j], products[j]);
        }
        
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            ap_int<16> sum = e_hat[i][k];
            for(int j=0; j<KYBER_K; j++) sum += products[j][k];
            while(sum >= KYBER_Q) sum -= KYBER_Q;
            if(sum < 0) sum += KYBER_Q;
            acc[k] = (int16)sum;
        }
        poly_tobytes(acc, &pk_local[i*384]);
    }

    int rho_offset = 384 * KYBER_K;
    for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        pk_local[rho_offset + i] = rho[i];
    }

    memcpy(sk_out, sk_local, SK_SIZE_BYTES);
    memcpy(pk_out, pk_local, PK_SIZE_BYTES);
}