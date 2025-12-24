#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"

// Khai báo module ngoài
extern void sha3_512_hash(uint8 input[33], uint8 output[64]);
extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);
extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void ntt(int16 poly[256]);
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);
extern void parse_ntt(hls::stream<uint8>& in_bytes, int16 a_hat[KYBER_N]);
// Module mới
extern void poly_tomsg(int16 coeffs[KYBER_N], uint8 output[384]);

// Định nghĩa kích thước Output chuẩn
// PK = (384 * K) bytes của t_hat + 32 bytes của rho
#define PK_SIZE_BYTES (384 * KYBER_K + 32)
// SK = (384 * K) bytes của s_hat
#define SK_SIZE_BYTES (384 * KYBER_K)

void ml_kem_keygen(
    ap_uint<64> seed_d[4],
    ap_uint<64> seed_z[4],
    uint8 pk_out[PK_SIZE_BYTES],  // Output Bytes chuẩn
    uint8 sk_out[SK_SIZE_BYTES]   // Output Bytes chuẩn
) {
    #pragma HLS INTERFACE m_axi port=seed_d bundle=gmem0
    #pragma HLS INTERFACE m_axi port=seed_z bundle=gmem0
    #pragma HLS INTERFACE m_axi port=pk_out bundle=gmem1
    #pragma HLS INTERFACE m_axi port=sk_out bundle=gmem1
    #pragma HLS INTERFACE s_axilite port=return

    uint8 rho[32], sigma[32];
    int16 s_hat[KYBER_K][KYBER_N];
    int16 e_hat[KYBER_K][KYBER_N];
    int16 A_hat[KYBER_K][KYBER_K][KYBER_N]; 
    
    #pragma HLS ARRAY_PARTITION variable=s_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=e_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=A_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=A_hat dim=2 type=complete

    // 1. Hash G
    uint8 g_in[33];
    #pragma HLS ARRAY_PARTITION variable=g_in type=complete
    for(int i=0; i<4; i++) {
        #pragma HLS UNROLL
        uint64_t w = seed_d[i];
        for(int j=0; j<8; j++) g_in[i*8+j] = (uint8)(w >> (j*8));
    }
    g_in[32] = KYBER_K;

    uint8 g_out[64];
    sha3_512_hash(g_in, g_out);
    for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        rho[i]   = g_out[i];
        sigma[i] = g_out[32+i];
    }

    // 2. Gen Matrix A
    for(int i=0; i<KYBER_K; i++) {
        for(int j=0; j<KYBER_K; j++) {
            ap_uint<64> xof_in[5];
            #pragma HLS ARRAY_PARTITION variable=xof_in type=complete
            for(int w=0; w<4; w++) {
                #pragma HLS UNROLL
                uint64_t val = 0;
                for(int b=0; b<8; b++) val |= ((uint64_t)rho[w*8+b] << (b*8));
                xof_in[w] = val;
            }
            xof_in[4] = (uint64_t)j | ((uint64_t)i << 8);

            hls::stream<uint8> strm;
            #pragma HLS STREAM variable=strm depth=256
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_hat[i][j]);
        }
    }

    // 3. Gen Noise s, e
    uint8 prf_in[33];
    #pragma HLS ARRAY_PARTITION variable=prf_in type=complete
    for(int i=0; i<32; i++) {
        #pragma HLS UNROLL
        prf_in[i] = sigma[i];
    }
    uint8 nonce = 0;

    // Gen s
    for(int i=0; i<KYBER_K; i++) {
        prf_in[32] = nonce++;
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        int16 poly_temp[256];
        cbd_eta2((ap_uint<64>*)cbd_input, poly_temp);
        ntt(poly_temp);
        for(int k=0; k<256; k++) s_hat[i][k] = poly_temp[k];
        
        // ENCODE SK (s_hat -> sk_out)
        // sk_out[i*384 ... (i+1)*384]
        poly_tomsg(s_hat[i], &sk_out[i*384]);
    }

    // Gen e
    for(int i=0; i<KYBER_K; i++) {
        prf_in[32] = nonce++;
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        int16 poly_temp[256];
        cbd_eta2((ap_uint<64>*)cbd_input, poly_temp);
        ntt(poly_temp);
        for(int k=0; k<256; k++) e_hat[i][k] = poly_temp[k];
    }

    // 4. Matrix Mult & Encode PK
    for(int i=0; i<KYBER_K; i++) {
        int16 acc[256];
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            acc[k] = e_hat[i][k];
        }

        for(int j=0; j<KYBER_K; j++) {
            int16 prod[256];
            poly_pointwise(A_hat[i][j], s_hat[j], prod);
            for(int k=0; k<256; k++) {
                #pragma HLS PIPELINE II=1
                int32_t sum = (int32_t)acc[k] + prod[k];
                acc[k] = (int16)(sum % KYBER_Q);
            }
        }
        
        // ENCODE PK (t_hat -> pk_out)
        poly_tomsg(acc, &pk_out[i*384]);
    }

    // 5. Append rho to PK (32 bytes cuối)
    int rho_offset = 384 * KYBER_K;
    for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        pk_out[rho_offset + i] = rho[i];
    }
}