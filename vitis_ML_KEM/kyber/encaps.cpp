#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"

// --- KHAI BÁO MODULE NGOÀI ---
extern void sha3_512_hash(uint8 input[33], uint8 output[64]); // Input của G thay đổi kích thước, ta sẽ xử lý bên trong
extern void sha3_256_hash(uint8* input, int in_len, uint8 output[32]); // Hàm H mới
extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);
extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void ntt(int16 poly[256]);
extern void inv_ntt(int16 poly[256]); // Cần InvNTT
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);
extern void parse_ntt(hls::stream<uint8>& in_bytes, int16 a_hat[KYBER_N]);

// Serializer functions
extern void poly_frombytes(uint8 input[384], int16 coeffs[KYBER_N]);
extern void poly_frommsg(uint8 msg[32], int16 coeffs[KYBER_N]);
extern void poly_compress_u(int16 coeffs[KYBER_N], uint8 output[320]);
extern void poly_compress_v(int16 coeffs[KYBER_N], uint8 output[128]);

// Hàm phụ trợ cho SHA3-512 input 64 bytes (m || H(pk))
// Vì hàm sha3_512 cũ fix input 33 bytes, ta viết nhanh logic absorb 64 bytes ở đây 
// hoặc sửa hàm gốc. Để an toàn, ta viết wrapper nhỏ tại chỗ.
// (Hoặc tốt nhất là dùng keccak_f1600 trực tiếp như dưới đây)
void sha3_512_64bytes(uint8 input[64], uint8 output[64]) {
    #pragma HLS INLINE
    // Tự implement nhanh để tránh sửa file gốc nhiều
    // Rate 72 bytes > 64 bytes -> 1 Block duy nhất
    uint64_t state[25] = {0};
    for(int i=0; i<8; i++) { // 64 bytes = 8 words
        uint64_t w = 0;
        for(int j=0; j<8; j++) w |= ((uint64_t)input[i*8+j] << (j*8));
        state[i] ^= w;
    }
    // Padding 0x06 tại byte 64
    state[8] ^= 0x06; 
    // Padding 0x80 tại byte 71 (Word 8, byte cao nhất)
    state[8] ^= (1ULL << 63);
    
    // Copy logic Keccak Core vào đây hoặc gọi extern
    // Để code gọn, giả sử bạn include file header chứa keccak_f1600
    // Ở đây ta gọi hàm extern void keccak_f1600(uint64_t state[25]);
    extern void keccak_f1600(uint64_t state[25]);
    keccak_f1600(state);

    for(int i=0; i<8; i++) {
        uint64_t w = state[i];
        for(int j=0; j<8; j++) output[i*8+j] = (uint8)(w >> (j*8));
    }
}

// Kích thước chuẩn
#define PK_SIZE 1184
#define CT_SIZE 1088 // 320*3 + 128
#define SS_SIZE 32
#define MSG_SIZE 32

void ml_kem_encaps(
    uint8 pk_in[PK_SIZE],
    uint8 randomness_m[32], // Message ngẫu nhiên (32 bytes) từ bên ngoài
    uint8 ct_out[CT_SIZE],  // Ciphertext
    uint8 ss_out[SS_SIZE]   // Shared Secret
) {
    #pragma HLS INTERFACE m_axi port=pk_in bundle=gmem0
    #pragma HLS INTERFACE m_axi port=randomness_m bundle=gmem0
    #pragma HLS INTERFACE m_axi port=ct_out bundle=gmem1
    #pragma HLS INTERFACE m_axi port=ss_out bundle=gmem1
    #pragma HLS INTERFACE s_axilite port=return

    // Buffer nội bộ
    int16 t_hat[KYBER_K][KYBER_N];
    int16 A_hat[KYBER_K][KYBER_K][KYBER_N];
    int16 r_hat[KYBER_K][KYBER_N]; // Vector r (NTT domain)
    
    // Vector u (Spatial domain)
    int16 u_poly[KYBER_K][KYBER_N];
    int16 v_poly[KYBER_N];

    uint8 rho[32];
    uint8 h_pk[32];
    
    // Partition
    #pragma HLS ARRAY_PARTITION variable=t_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=r_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=A_hat dim=1 type=complete
    #pragma HLS ARRAY_PARTITION variable=A_hat dim=2 type=complete

    // --- BƯỚC 1: UNPACK PUBLIC KEY ---
    // PK = t_hat encoded (1152B) || rho (32B)
    for(int i=0; i<KYBER_K; i++) {
        poly_frombytes(&pk_in[i*384], t_hat[i]);
    }
    for(int i=0; i<32; i++) {
        rho[i] = pk_in[1152 + i];
    }

    // --- BƯỚC 2: HASH H(pk) ---
    sha3_256_hash(pk_in, PK_SIZE, h_pk);

    // --- BƯỚC 3: HASH G(m || H(pk)) ---
    uint8 g_in[64];
    for(int i=0; i<32; i++) g_in[i] = randomness_m[i];
    for(int i=0; i<32; i++) g_in[32+i] = h_pk[i];
    
    uint8 Kr[64]; // K (32B) || r (32B)
    sha3_512_64bytes(g_in, Kr);

    uint8 seed_r[32]; // Seed để sinh r, e1, e2
    for(int i=0; i<32; i++) {
        ss_out[i] = Kr[i]; // Shared Secret K (phần đầu) - Lưu ý: KEM chuẩn sẽ hash lại lần nữa ở cuối
        // Nhưng theo Algorithm 19: K = K_part
        seed_r[i] = Kr[32+i];
    }

    // --- BƯỚC 4: GEN MATRIX A ---
    // (Logic y hệt KeyGen)
    for(int i=0; i<KYBER_K; i++) {
        for(int j=0; j<KYBER_K; j++) {
            ap_uint<64> xof_in[5];
            for(int w=0; w<4; w++) {
                uint64_t val = 0;
                for(int b=0; b<8; b++) val |= ((uint64_t)rho[w*8+b] << (b*8));
                xof_in[w] = val;
            }
            xof_in[4] = (uint64_t)j | ((uint64_t)i << 8); // A[i][j]

            hls::stream<uint8> strm;
            #pragma HLS STREAM variable=strm depth=256
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_hat[i][j]);
        }
    }

    // --- BƯỚC 5: GEN NOISE (r, e1, e2) ---
    uint8 prf_in[33];
    for(int i=0; i<32; i++) prf_in[i] = seed_r[i];
    uint8 nonce = 0;

    // 5.1 Gen r -> r_hat
    for(int i=0; i<KYBER_K; i++) {
        prf_in[32] = nonce++;
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        
        int16 poly_temp[256];
        cbd_eta2((ap_uint<64>*)cbd_input, poly_temp);
        ntt(poly_temp);
        for(int k=0; k<256; k++) r_hat[i][k] = poly_temp[k];
    }

    // 5.2 Gen e1
    int16 e1[KYBER_K][KYBER_N];
    for(int i=0; i<KYBER_K; i++) {
        prf_in[32] = nonce++;
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        cbd_eta2((ap_uint<64>*)cbd_input, e1[i]); // Giữ nguyên miền thời gian
    }

    // 5.3 Gen e2
    int16 e2[KYBER_N];
    {
        prf_in[32] = nonce++;
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        cbd_eta2((ap_uint<64>*)cbd_input, e2);
    }

    // --- BƯỚC 6: MATRIX MULTIPLICATION ---
    
    // 6.1: u = InvNTT(A^T * r) + e1
    // A^T * r nghĩa là: u[i] = sum_j (A[j][i] * r[j])
    for(int i=0; i<KYBER_K; i++) {
        int16 acc[256] = {0};
        
        for(int j=0; j<KYBER_K; j++) {
            int16 prod[256];
            // Lưu ý indices: A_hat[j][i]
            poly_pointwise(A_hat[j][i], r_hat[j], prod);
            
            for(int k=0; k<256; k++) {
                int32_t sum = (int32_t)acc[k] + prod[k];
                acc[k] = (int16)(sum % KYBER_Q);
            }
        }
        
        // Inverse NTT
        inv_ntt(acc);
        
        // Cộng e1 và lưu vào u_poly
        for(int k=0; k<256; k++) {
            int32_t val = (int32_t)acc[k] + e1[i][k];
            u_poly[i][k] = (int16)(val % KYBER_Q);
            if(u_poly[i][k] < 0) u_poly[i][k] += KYBER_Q;
        }
    }

    // 6.2: v = InvNTT(t^T * r) + e2 + m
    // v = sum_i (t_hat[i] * r_hat[i])
    int16 v_acc[256] = {0};
    for(int i=0; i<KYBER_K; i++) {
        int16 prod[256];
        poly_pointwise(t_hat[i], r_hat[i], prod);
        for(int k=0; k<256; k++) {
            int32_t sum = (int32_t)v_acc[k] + prod[k];
            v_acc[k] = (int16)(sum % KYBER_Q);
        }
    }
    inv_ntt(v_acc);

    // Cộng e2 và m
    int16 m_poly[256];
    poly_frommsg(randomness_m, m_poly);
    
    for(int k=0; k<256; k++) {
        int32_t val = (int32_t)v_acc[k] + e2[k] + m_poly[k];
        int16 res = (int16)(val % KYBER_Q);
        if(res < 0) res += KYBER_Q;
        v_poly[k] = res;
    }

    // --- BƯỚC 7: COMPRESS & PACK CIPHERTEXT ---
    // c1 = Compress_u(u)
    for(int i=0; i<KYBER_K; i++) {
        poly_compress_u(u_poly[i], &ct_out[i*320]);
    }
    // c2 = Compress_v(v)
    poly_compress_v(v_poly, &ct_out[KYBER_K*320]); // Offset 3*320 = 960
}