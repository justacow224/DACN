#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"
#include <stdint.h>

// =========================================================
// PHẦN 1: CÁC HẰNG SỐ VÀ HÀM HỖ TRỢ
// =========================================================

const uint64_t KECCAK_RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

template <int N>
static ap_uint<64> ROTL(ap_uint<64> x, int n) {
    #pragma HLS INLINE
    if (n == 0) return x;
    return (x << n) | (x >> (N - n));
}

// =========================================================
// PHẦN 2: LÕI KECCAK-F1600 (VITIS OPTIMIZED KERNEL)
// Lõi này BẮT BUỘC phải INLINE off để làm Resource Sharing
// =========================================================
void keccak_f1600(uint64_t state[25]) {
    #pragma HLS INLINE off
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    #pragma HLS BIND_STORAGE variable=KECCAK_RC type=rom_1p impl=bram

    ap_uint<64> stateArray[25];
    #pragma HLS ARRAY_PARTITION variable=stateArray type=complete
    
    for(int i=0; i<25; i++) {
        #pragma HLS UNROLL
        stateArray[i] = state[i];
    }

    LOOP_ROUND:
    for (int rnd = 0; rnd < 24; rnd++) {
        #pragma HLS PIPELINE II=2

        ap_uint<64> rowReg[5];
        #pragma HLS ARRAY_PARTITION variable=rowReg type=complete
        
        for (int i = 0; i < 5; i++) {
            #pragma HLS UNROLL
            ap_uint<64> t1 = stateArray[i] ^ stateArray[i + 5];
            ap_uint<64> t2 = stateArray[i + 10] ^ stateArray[i + 15];
            rowReg[i] = t1 ^ t2 ^ stateArray[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            #pragma HLS UNROLL
            ap_uint<64> tmp = rowReg[(i + 4) % 5] ^ ROTL<64>(rowReg[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                #pragma HLS UNROLL
                stateArray[i + j] ^= tmp;
            }
        }

        ap_uint<64> tmpStateArray[24];
        #pragma HLS ARRAY_PARTITION variable=tmpStateArray type=complete

        tmpStateArray[0] = ROTL<64>(stateArray[1], 1);
        tmpStateArray[1] = ROTL<64>(stateArray[10], 3);
        tmpStateArray[2] = ROTL<64>(stateArray[7], 6);
        tmpStateArray[3] = ROTL<64>(stateArray[11], 10);
        tmpStateArray[4] = ROTL<64>(stateArray[17], 15);
        tmpStateArray[5] = ROTL<64>(stateArray[18], 21);
        tmpStateArray[6] = ROTL<64>(stateArray[3], 28);
        tmpStateArray[7] = ROTL<64>(stateArray[5], 36);
        tmpStateArray[8] = ROTL<64>(stateArray[16], 45);
        tmpStateArray[9] = ROTL<64>(stateArray[8], 55);
        tmpStateArray[10] = ROTL<64>(stateArray[21], 2);
        tmpStateArray[11] = ROTL<64>(stateArray[24], 14);
        tmpStateArray[12] = ROTL<64>(stateArray[4], 27);
        tmpStateArray[13] = ROTL<64>(stateArray[15], 41);
        tmpStateArray[14] = ROTL<64>(stateArray[23], 56);
        tmpStateArray[15] = ROTL<64>(stateArray[19], 8);
        tmpStateArray[16] = ROTL<64>(stateArray[13], 25);
        tmpStateArray[17] = ROTL<64>(stateArray[12], 43);
        tmpStateArray[18] = ROTL<64>(stateArray[2], 62);
        tmpStateArray[19] = ROTL<64>(stateArray[20], 18);
        tmpStateArray[20] = ROTL<64>(stateArray[14], 39);
        tmpStateArray[21] = ROTL<64>(stateArray[22], 61);
        tmpStateArray[22] = ROTL<64>(stateArray[9], 20);
        tmpStateArray[23] = ROTL<64>(stateArray[6], 44);

        stateArray[10] = tmpStateArray[0];  stateArray[7] = tmpStateArray[1];
        stateArray[11] = tmpStateArray[2];  stateArray[17] = tmpStateArray[3];
        stateArray[18] = tmpStateArray[4];  stateArray[3] = tmpStateArray[5];
        stateArray[5] = tmpStateArray[6];   stateArray[16] = tmpStateArray[7];
        stateArray[8] = tmpStateArray[8];   stateArray[21] = tmpStateArray[9];
        stateArray[24] = tmpStateArray[10]; stateArray[4] = tmpStateArray[11];
        stateArray[15] = tmpStateArray[12]; stateArray[23] = tmpStateArray[13];
        stateArray[19] = tmpStateArray[14]; stateArray[13] = tmpStateArray[15];
        stateArray[12] = tmpStateArray[16]; stateArray[2] = tmpStateArray[17];
        stateArray[20] = tmpStateArray[18]; stateArray[14] = tmpStateArray[19];
        stateArray[22] = tmpStateArray[20]; stateArray[9] = tmpStateArray[21];
        stateArray[6] = tmpStateArray[22];  stateArray[1] = tmpStateArray[23];

        for (int j = 0; j < 25; j += 5) {
            #pragma HLS UNROLL
            ap_uint<64> s0 = stateArray[j];
            ap_uint<64> s1 = stateArray[j+1];
            ap_uint<64> s2 = stateArray[j+2];
            ap_uint<64> s3 = stateArray[j+3];
            ap_uint<64> s4 = stateArray[j+4];

            stateArray[j]   ^= (~s1) & s2;
            stateArray[j+1] ^= (~s2) & s3;
            stateArray[j+2] ^= (~s3) & s4;
            stateArray[j+3] ^= (~s4) & s0;
            stateArray[j+4] ^= (~s0) & s1;
        }
        stateArray[0] ^= KECCAK_RC[rnd];
    }

    for(int i=0; i<25; i++) {
        #pragma HLS UNROLL
        state[i] = stateArray[i];
    }
}

// =========================================================
// PHẦN 3: UNIFIED CRYPTO WRAPPERS
// Tất cả đều được ép INLINE để hòa logic vào module gọi
// =========================================================

void sha3_256_1184bytes(uint8 input[1184], uint8 output[32]) {
    #pragma HLS INLINE
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

void sha3_512_33bytes(uint8 input[33], uint8 output[64]) {
    #pragma HLS INLINE
    uint64_t state[25] = {0};
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    
    for(int i=0; i<4; i++) {
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[i*8+j] << (j*8));
        state[i] ^= word;
    }
    state[4] ^= (uint64_t)input[32];

    state[4] ^= (0x06ULL << 8);
    state[8] ^= (1ULL << 63);

    keccak_f1600(state);

    for(int i=0; i<8; i++) {
        uint64_t word = state[i];
        for(int j=0; j<8; j++) {
            #pragma HLS UNROLL
            output[i*8+j] = (uint8)(word >> (j*8));
        }
    }
}

void sha3_512_64bytes(uint8 input[64], uint8 output[64]) {
    #pragma HLS INLINE
    uint64_t state[25] = {0};
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    
    for(int w=0; w<8; w++) {
        #pragma HLS PIPELINE II=1
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[w*8+j] << (j*8));
        state[w] ^= word;
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

void sha3_512_1120bytes(uint8 input[1120], uint8 output[64]) {
    #pragma HLS INLINE
    uint64_t state[25] = {0};
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    
    for(int b=0; b<15; b++) {
        for(int w=0; w<9; w++) {
            #pragma HLS PIPELINE II=1
            uint64_t word = 0;
            int base_idx = b*72 + w*8;
            for(int j=0; j<8; j++) word |= ((uint64_t)input[base_idx+j] << (j*8));
            state[w] ^= word;
        }
        keccak_f1600(state);
    }
    
    int offset = 1080;
    for(int w=0; w<5; w++) {
        #pragma HLS PIPELINE II=1
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[offset + w*8 + j] << (j*8));
        state[w] ^= word;
    }
    
    state[5] ^= 0x06;
    state[8] ^= (1ULL << 63);
    keccak_f1600(state);

    for(int i=0; i<8; i++) {
        #pragma HLS UNROLL
        uint64_t w = state[i];
        for(int j=0; j<8; j++) output[i*8+j] = (uint8)(w >> (j*8));
    }
}

void shake256_33bytes(uint8 input[33], uint64_t output_64[16]) {
    #pragma HLS INLINE
    uint64_t state[25] = {0};
    #pragma HLS ARRAY_PARTITION variable=state type=complete

    for(int i=0; i<4; i++) {
        uint64_t word = 0;
        for(int j=0; j<8; j++) word |= ((uint64_t)input[i*8+j] << (j*8));
        state[i] ^= word;
    }
    state[4] ^= (uint64_t)input[32];

    state[4] ^= (0x1FULL << 8);
    state[16] ^= (1ULL << 63);

    keccak_f1600(state);

    for(int i=0; i<16; i++) {
        #pragma HLS UNROLL
        output_64[i] = state[i];
    }
}

#define SHAKE128_RATE_WORDS 21
void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream) {
    #pragma HLS INLINE
    uint64_t state[25];
    #pragma HLS ARRAY_PARTITION variable=state type=complete
    for(int i=0; i<25; i++) state[i] = 0;

    for(int i=0; i<4; i++) state[i] ^= input_B[i];
    state[4] ^= input_B[4]; 

    state[4] ^= (0x1FULL << 16); 
    state[SHAKE128_RATE_WORDS - 1] ^= (1ULL << 63);

    keccak_f1600(state);

    for(int b=0; b<5; b++) {
        for(int i=0; i < SHAKE128_RATE_WORDS; i++) {
            uint64_t word = state[i];
            for(int k=0; k<8; k++) {
                #pragma HLS PIPELINE II=1
                out_stream.write((uint8)(word >> (k*8)));
            }
        }
        keccak_f1600(state);
    }
}