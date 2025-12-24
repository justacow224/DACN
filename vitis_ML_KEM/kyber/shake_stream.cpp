#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"

// =========================================================
// PHẦN 1: CÁC HẰNG SỐ VÀ HÀM HỖ TRỢ CẤP THẤP
// =========================================================

// Round Constants (24 vòng)
const uint64_t KECCAK_RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// Hàm xoay bit trái (Rotate Left) - Chuẩn 64-bit
static uint64_t rotl64(uint64_t x, int n) {
    #pragma HLS INLINE
    return (x << n) | (x >> (64 - n));
}

// =========================================================
// PHẦN 2: LÕI KECCAK-F1600 (Permutation Core)
// =========================================================
void keccak_f1600(uint64_t state[25]) {
    #pragma HLS INLINE off
    // Biến state thành thanh ghi (Flip-Flops) hoàn toàn
    #pragma HLS ARRAY_PARTITION variable=state type=complete

    uint64_t C[5], D[5], B[25];
    #pragma HLS ARRAY_PARTITION variable=C type=complete
    #pragma HLS ARRAY_PARTITION variable=D type=complete
    #pragma HLS ARRAY_PARTITION variable=B type=complete

    // Vòng lặp 24 Rounds
    Round_Loop: for (int i = 0; i < 24; i++) {
        #pragma HLS PIPELINE II=1

        // --- Step Theta ---
        for (int x = 0; x < 5; x++) {
            #pragma HLS UNROLL
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        }
        for (int x = 0; x < 5; x++) {
            #pragma HLS UNROLL
            D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        }
        for (int j = 0; j < 25; j++) {
            #pragma HLS UNROLL
            state[j] ^= D[j % 5];
        }

        // --- Step Rho & Pi (Hard-coded để tối ưu dây nối) ---
        B[ 0] = state[ 0];
        B[10] = rotl64(state[ 1],  1);
        B[20] = rotl64(state[ 2], 62);
        B[ 5] = rotl64(state[ 3], 28);
        B[15] = rotl64(state[ 4], 27);
        B[16] = rotl64(state[ 5], 36);
        B[ 1] = rotl64(state[ 6], 44);
        B[11] = rotl64(state[ 7],  6);
        B[21] = rotl64(state[ 8], 55);
        B[ 6] = rotl64(state[ 9], 20);
        B[ 7] = rotl64(state[10],  3);
        B[17] = rotl64(state[11], 10);
        B[ 2] = rotl64(state[12], 43);
        B[12] = rotl64(state[13], 25);
        B[22] = rotl64(state[14], 39);
        B[23] = rotl64(state[15], 41);
        B[ 8] = rotl64(state[16], 45);
        B[18] = rotl64(state[17], 15);
        B[ 3] = rotl64(state[18], 21);
        B[13] = rotl64(state[19],  8);
        B[14] = rotl64(state[20], 18);
        B[24] = rotl64(state[21],  2);
        B[ 9] = rotl64(state[22], 61);
        B[19] = rotl64(state[23], 56);
        B[ 4] = rotl64(state[24], 14);

        // --- Step Chi ---
        for (int j = 0; j < 25; j += 5) {
            #pragma HLS UNROLL
            state[j+0] = B[j+0] ^ ((~B[j+1]) & B[j+2]);
            state[j+1] = B[j+1] ^ ((~B[j+2]) & B[j+3]);
            state[j+2] = B[j+2] ^ ((~B[j+3]) & B[j+4]);
            state[j+3] = B[j+3] ^ ((~B[j+4]) & B[j+0]);
            state[j+4] = B[j+4] ^ ((~B[j+0]) & B[j+1]);
        }

        // --- Step Iota ---
        state[0] ^= KECCAK_RC[i];
    }
}

// =========================================================
// PHẦN 3: CÁC HÀM CRYPTO WRAPPERS (High Level)
// =========================================================

// ---------------------------------------------------------
// 3.1 SHA3-512 (Dùng cho hàm G)
// Rate: 576 bits = 72 bytes.
// Input: 33 bytes (Seed 32B + k 1B).
// Output: 64 bytes (rho + sigma).
// ---------------------------------------------------------
void sha3_512_hash(uint8 input[33], uint8 output[64]) {
    #pragma HLS INLINE
    uint64_t state[25];
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    
    // Init state
    for(int i=0; i<25; i++) state[i] = 0;

    // 1. Absorb 33 bytes
    // Word 0-3: 32 bytes đầu
    for(int i=0; i<4; i++) {
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[i*8+j] << (j*8));
        state[i] ^= word;
    }
    // Word 4: Byte thứ 33 (input[32])
    state[4] ^= (uint64_t)input[32];

    // 2. Padding SHA3 (Domain 0x06)
    // Byte 33 là nơi bắt đầu padding 0x06.
    // Trong Word 4, byte 33 là byte thứ 2 (index 1).
    // -> Shift 8 bits (1 * 8).
    state[4] ^= (0x06ULL << 8);
    
    // Byte cuối block (71) là 0x80.
    // Byte 71 nằm ở Word 8 (64-71), là byte cao nhất (MSB).
    state[8] ^= (1ULL << 63);

    // 3. Permutation
    keccak_f1600(state);

    // 4. Squeeze 64 bytes (8 words)
    for(int i=0; i<8; i++) {
        uint64_t word = state[i];
        for(int j=0; j<8; j++) {
            #pragma HLS UNROLL
            output[i*8+j] = (uint8)(word >> (j*8));
        }
    }
}

// ---------------------------------------------------------
// 3.2 SHAKE256 (Dùng cho PRF sinh s, e)
// Rate: 1088 bits = 136 bytes.
// Input: 33 bytes (Seed 32B + Nonce 1B).
// Output: 128 bytes (eta=2 CBD input).
// ---------------------------------------------------------
void shake256_prf(uint8 input[33], uint64_t output_64[16]) {
    #pragma HLS INLINE
    uint64_t state[25];
    #pragma HLS ARRAY_PARTITION variable=state type=complete

    for(int i=0; i<25; i++) state[i] = 0;

    // 1. Absorb 33 bytes
    for(int i=0; i<4; i++) {
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[i*8+j] << (j*8));
        state[i] ^= word;
    }
    state[4] ^= (uint64_t)input[32];

    // 2. Padding SHAKE (Domain 0x1F)
    // Byte 33 là nơi padding 0x1F. (Word 4, byte index 1)
    state[4] ^= (0x1FULL << 8);
    
    // Byte cuối block (135) là 0x80.
    // Byte 135 nằm ở Word 16 (128-135), là byte cao nhất (MSB).
    state[16] ^= (1ULL << 63);

    // 3. Permutation
    keccak_f1600(state);

    // 4. Squeeze 128 bytes (16 words)
    // Rate 136 bytes > 128 bytes -> Chỉ cần 1 lần squeeze
    for(int i=0; i<16; i++) {
        #pragma HLS UNROLL
        output_64[i] = state[i];
    }
}

// ---------------------------------------------------------
// 3.3 SHAKE128 (XOF - Dùng cho Matrix A)
// Rate: 1344 bits = 168 bytes = 21 words.
// Input: 34 bytes (Seed 32B + Index 2B).
// Output: Stream bytes vô tận.
// ---------------------------------------------------------
#define SHAKE128_RATE_WORDS 21

void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream) {
    #pragma HLS INLINE
    uint64_t state[25];
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    
    for(int i=0; i<25; i++) state[i] = 0;

    // 1. Absorb 34 Bytes
    for(int i=0; i<4; i++) {
        state[i] ^= input_B[i];
    }
    // Word 5 (index 4) chứa 2 byte cuối (index j, i)
    state[4] ^= input_B[4]; 

    // 2. Padding SHAKE (0x1F)
    // Byte 34 là nơi padding 0x1F.
    // Word 4 chứa byte 32-39. Byte 34 là byte thứ 3 (index 2).
    // -> Shift 16 bits.
    state[4] ^= (0x1FULL << 16); 
    
    // Byte cuối block (167) là 0x80.
    // Word 20 (byte 160-167). Byte 167 là MSB.
    state[SHAKE128_RATE_WORDS - 1] ^= (1ULL << 63);

    // 3. Permutation
    keccak_f1600(state);

    // 4. Squeeze Loop (Squeeze 3 blocks ~ 504 bytes)
    for(int b=0; b<5; b++) {
        for(int i=0; i < SHAKE128_RATE_WORDS; i++) {
            uint64_t word = state[i];
            for(int k=0; k<8; k++) {
                #pragma HLS PIPELINE II=1
                out_stream.write((uint8)word);
                word >>= 8;
            }
        }
        keccak_f1600(state);
    }
}

// --- BỔ SUNG: SHA3-256 (Hàm H) ---
// Rate: 1088 bits = 136 bytes.
// Input: Mảng byte tùy ý (thường là pk = 1184 bytes)
// Output: 32 bytes digest
void sha3_256_hash(uint8* input, int in_len, uint8 output[32]) {
    #pragma HLS INLINE
    uint64_t state[25];
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    for(int i=0; i<25; i++) state[i] = 0;

    // Rate của SHA3-256 là 136 bytes (17 words 64-bit)
    const int RATE_WORDS = 17; 

    // 1. Absorb nhanh (Word-based)
    int i = 0;
    while (in_len >= 8) {
        // Gom 8 bytes thành 1 word 64-bit
        uint64_t word = 0;
        for (int j = 0; j < 8; j++) {
            #pragma HLS UNROLL
            word |= ((uint64_t)input[i + j] << (j * 8));
        }
        
        // XOR vào state
        // Tính vị trí word trong block (0..16)
        int word_idx = (i / 8) % RATE_WORDS;
        state[word_idx] ^= word;

        // Nếu đầy block (sau khi xử lý word thứ 16) -> Permute
        if (word_idx == RATE_WORDS - 1) {
            keccak_f1600(state);
        }

        i += 8;
        in_len -= 8;
    }

    // 2. Absorb phần dư (Bytes lẻ còn lại)
    // (Logic cũ của bạn cho phần này là ổn, hoặc xử lý nốt các byte cuối)
    for (int j = 0; j < in_len; j++) {
         int byte_pos = i % 136;
         state[byte_pos/8] ^= ((uint64_t)input[i] << ((byte_pos%8)*8));
         i++;
    }

    // 3. Padding (Logic cũ ok)
    int byte_pos = i % 136;
    state[byte_pos/8] ^= (0x06ULL << ((byte_pos%8)*8));
    state[16] ^= (1ULL << 63); 
    keccak_f1600(state);

    // 4. Squeeze (Logic cũ ok)
    for(int j=0; j<4; j++) {
        #pragma HLS UNROLL
        uint64_t w = state[j];
        for(int k=0; k<8; k++) output[j*8+k] = (uint8)(w >> (k*8));
    }
}