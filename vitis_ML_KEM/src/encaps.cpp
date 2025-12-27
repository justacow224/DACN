#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <cstring>

// --- EXTERN DECLARATIONS ---
extern void keccak_f1600(uint64_t state[25]);
extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);
extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void ntt(int16 poly[256]);
extern void inv_ntt(int16 poly[256]);
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);
extern void parse_ntt(hls::stream<uint8>& in_bytes, int16 a_hat[KYBER_N]);

// Thay đổi quan trọng: Ép Inline các hàm phụ trợ
// Lưu ý: Bạn cần sửa cả trong file serializer.cpp (thêm pragma INLINE) hoặc copy nội dung hàm vào đây nếu muốn chắc chắn.
// Tuy nhiên, với HLS, nếu ta gọi hàm nhỏ trong loop unroll, nó thường tự inline.
// Để đảm bảo, ta khai báo lại prototype (việc inline thực sự diễn ra ở định nghĩa hàm).
extern void poly_frombytes(uint8 input[384], int16 coeffs[KYBER_N]);
extern void poly_frommsg(uint8 msg[32], int16 coeffs[KYBER_N]);
extern void poly_compress_u(int16 coeffs[KYBER_N], uint8 output[320]);
extern void poly_compress_v(int16 coeffs[KYBER_N], uint8 output[128]);

// --- LOCAL STATIC FUNCTIONS ---
// Giữ nguyên static để tránh duplicate logic SHA3
static void sha3_512_64bytes_encaps(uint8 input[64], uint8 output[64]) {
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

static void sha3_256_pk_encaps(uint8 input[1184], uint8 output[32]) {
    #pragma HLS INLINE off
    uint64_t state[25] = {0};
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    
    for(int b=0; b<8; b++) {
        for(int w=0; w<17; w++) {
            #pragma HLS PIPELINE II=1
            uint64_t word = 0;
            int base_idx = b*136 + w*8;
            for(int j=0; j<8; j++) word |= ((uint64_t)input[base_idx+j] << (j*8));
            state[w] ^= word;
        }
        keccak_f1600(state);
    }
    int offset = 1088;
    for(int w=0; w<12; w++) {
        #pragma HLS PIPELINE II=1
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[offset + w*8 + j] << (j*8));
        state[w] ^= word;
    }
    state[12] ^= 0x06;
    state[16] ^= (1ULL << 63); 
    keccak_f1600(state);
    for(int i=0; i<4; i++) {
        #pragma HLS UNROLL
        uint64_t w = state[i];
        for(int j=0; j<8; j++) output[i*8+j] = (uint8)(w >> (j*8));
    }
}

#define PK_SIZE 1184
#define CT_SIZE 1088 

void ml_kem_encaps(
    uint8 pk_in[PK_SIZE],
    uint8 randomness_m[32], 
    uint8 ct_out[CT_SIZE],  
    uint8 ss_out[32]   
) {
    #pragma HLS INTERFACE m_axi port=pk_in bundle=gmem0 depth=1184 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=randomness_m bundle=gmem0 depth=32 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=ct_out bundle=gmem1 depth=1088 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=ss_out bundle=gmem1 depth=32 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return

    // Resource Allocation: Limit=3 is Sweet Spot
    #pragma HLS ALLOCATION function instances=keccak_f1600 limit=3
    #pragma HLS ALLOCATION function instances=ntt limit=3
    #pragma HLS ALLOCATION function instances=inv_ntt limit=3
    #pragma HLS ALLOCATION function instances=poly_pointwise limit=3

    // --- MEMORY OPTIMIZATION ---
    // Loại bỏ A_hat toàn cục để tiết kiệm BRAM
    // int16 A_hat... -> REMOVED

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
    #pragma HLS ARRAY_PARTITION variable=pk_local block factor=3 
    uint8 ct_local[CT_SIZE];
    #pragma HLS ARRAY_PARTITION variable=ct_local block factor=3 

    // --- EXECUTION ---
    memcpy(pk_local, pk_in, PK_SIZE);

    // 1. Hashing
    uint8 h_pk[32];
    #pragma HLS ARRAY_PARTITION variable=h_pk complete
    sha3_256_pk_encaps(pk_local, h_pk);

    uint8 g_in[64];
    #pragma HLS ARRAY_PARTITION variable=g_in complete
    for(int i=0; i<32; i++) {
        #pragma HLS UNROLL
        g_in[i] = randomness_m[i];
        g_in[32+i] = h_pk[i];
    }
    
    uint8 Kr[64]; 
    #pragma HLS ARRAY_PARTITION variable=Kr complete
    sha3_512_64bytes_encaps(g_in, Kr);
    
    for(int i=0; i<32; i++) {
        #pragma HLS UNROLL
        ss_out[i] = Kr[i];
    }

    // Unpack PK
    uint8 rho[32];
    #pragma HLS ARRAY_PARTITION variable=rho complete
    for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        poly_frombytes(&pk_local[i*384], t_hat[i]);
    }
    for(int i=0; i<32; i++) {
        #pragma HLS UNROLL
        rho[i] = pk_local[1152 + i];
    }

    // 2. GEN NOISE (r, e1, e2) FIRST
    // Sinh r trước để dùng cho phép nhân ma trận on-the-fly
    
    // Gen r (Parallel 3)
    Gen_R_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL 
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = Kr[32+k];
        prf_in[32] = (uint8)i; // nonce 0,1,2
        
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        
        ap_uint<64> cbd_ap[16]; // Fix casting safely
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];

        int16 poly_temp[256];
        #pragma HLS ARRAY_PARTITION variable=poly_temp cyclic factor=2
        cbd_eta2(cbd_ap, poly_temp);
        ntt(poly_temp);
        
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            r_hat[i][k] = poly_temp[k];
        }
    }

    // Gen e1 (Parallel 3) -> Store in u_poly
    Gen_E1_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL 
        uint8 prf_in[33];
        #pragma HLS ARRAY_PARTITION variable=prf_in complete
        for(int k=0; k<32; k++) prf_in[k] = Kr[32+k];
        prf_in[32] = (uint8)(i + 3); // nonce 3,4,5
        
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];

        cbd_eta2(cbd_ap, u_poly[i]); 
    }

    // Gen e2
    int16 e2[256];
    #pragma HLS ARRAY_PARTITION variable=e2 cyclic factor=2
    {
        uint8 prf_in[33];
        for(int k=0; k<32; k++) prf_in[k] = Kr[32+k];
        prf_in[32] = 6;
        uint64_t cbd_input[16];
        shake256_prf(prf_in, cbd_input);
        ap_uint<64> cbd_ap[16];
        #pragma HLS ARRAY_PARTITION variable=cbd_ap complete
        for(int k=0; k<16; k++) cbd_ap[k] = cbd_input[k];
        cbd_eta2(cbd_ap, e2);
    }

    // 3. STREAMING MATRIX MULTIPLY (The Optimization)
    // Tính u = A^T * r + e1
    // Loop i (0..2): Tính từng đa thức u[i] song song
    // Loop j (0..2): Duyệt qua các phần tử của A^T (tức là A[j][i])
    
    Calc_U_Loop: for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        
        int16 acc[256] = {0};
        #pragma HLS ARRAY_PARTITION variable=acc cyclic factor=2
        
        // Inner loop: Generate A on-the-fly -> Mult -> Acc
        for(int j=0; j<KYBER_K; j++) {
            // Không UNROLL loop này để tiết kiệm Keccak instance (chỉ cần 3 instance cho 3 hàng i)
            
            // Generate A[j][i] (Transpose)
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
            #pragma HLS STREAM variable=strm depth=256
            
            // Buffer cục bộ cực nhỏ cho 1 đa thức A
            int16 A_poly_temp[256];
            #pragma HLS ARRAY_PARTITION variable=A_poly_temp cyclic factor=2
            
            xof_absorb_squeeze(xof_in, strm);
            parse_ntt(strm, A_poly_temp);
            
            int16 prod[256];
            poly_pointwise(A_poly_temp, r_hat[j], prod);
            
            for(int k=0; k<256; k++) {
                #pragma HLS PIPELINE II=2
                ap_int<16> sum = (ap_int<16>)acc[k] + prod[k];
                while(sum >= KYBER_Q) sum -= KYBER_Q;
                acc[k] = (int16)sum;
            }
        }
        
        inv_ntt(acc);
        
        // Cộng e1 (đang ở u_poly)
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val = (ap_int<16>)acc[k] + u_poly[i][k];
            while(val >= KYBER_Q) val -= KYBER_Q;
            if(val < 0) val += KYBER_Q;
            u_poly[i][k] = (int16)val;
        }
    }

    // 4. Calc v
    {
        int16 v_acc[256] = {0};
        #pragma HLS ARRAY_PARTITION variable=v_acc cyclic factor=2
        for(int i=0; i<KYBER_K; i++) {
            #pragma HLS UNROLL 
            int16 prod[256];
            #pragma HLS ARRAY_PARTITION variable=prod cyclic factor=2
            poly_pointwise(t_hat[i], r_hat[i], prod);
            for(int k=0; k<256; k++) {
                #pragma HLS PIPELINE II=2
                ap_int<16> sum = (ap_int<16>)v_acc[k] + prod[k];
                while(sum >= KYBER_Q) sum -= KYBER_Q;
                v_acc[k] = (int16)sum;
            }
        }
        inv_ntt(v_acc);

        int16 m_poly[256];
        #pragma HLS ARRAY_PARTITION variable=m_poly cyclic factor=2
        poly_frommsg(randomness_m, m_poly);
        
        for(int k=0; k<256; k++) {
            #pragma HLS PIPELINE II=1
            ap_int<16> val = (ap_int<16>)v_acc[k] + e2[k] + m_poly[k];
            while(val >= KYBER_Q) val -= KYBER_Q;
            if(val < 0) val += KYBER_Q;
            v_poly[k] = (int16)val;
        }
    }

    // 5. Pack Output
    // Unroll packing để tận dụng các hàm đã được inline
    for(int i=0; i<KYBER_K; i++) {
        #pragma HLS UNROLL
        poly_compress_u(u_poly[i], &ct_local[i*320]);
    }
    poly_compress_v(v_poly, &ct_local[KYBER_K*320]);

    memcpy(ct_out, ct_local, CT_SIZE);
}