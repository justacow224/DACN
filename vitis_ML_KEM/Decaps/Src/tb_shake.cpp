#include <iostream>
#include <cstring>
#include "keccak_data.h"
#include "params.h"
#include "ap_int.h"

// --- KHAI BÁO CÁC HÀM CẦN TEST ---
// (Copy prototype chính xác từ mã nguồn của bạn)

// 1. SHA3-256 (Input length variable)
extern void sha3_256_hash(uint8* input, int in_len, uint8 output[32]);

// 2. SHA3-512 (Input 33 bytes)
extern void sha3_512_hash(uint8 input[33], uint8 output[64]);

// 3. SHAKE-256 (PRF - Input 33 bytes, Output 16 words uint64)
extern void shake256_prf(uint8 input[33], uint64_t output_64[16]);

// Hàm phụ trợ để in lỗi
void print_diff(uint8* hw, const uint8* exp, int len, const char* name) {
    for(int i=0; i<len; i++) {
        if(hw[i] != exp[i]) {
            std::cout << "[FAIL " << name << "] idx=" << i 
                      << " HW=" << (int)hw[i] << " Exp=" << (int)exp[i] << std::endl;
            return; // Chỉ in lỗi đầu tiên
        }
    }
}

int main() {
    std::cout << "--- STARTING KECCAK SUITE TEST ---" << std::endl;
    int fails = 0;

    for (int t = 0; t < NUM_TESTS; t++) {
        std::cout << "Test Case " << t << "..." << std::endl;

        // --- TEST 1: SHA3-256 ---
        uint8 out_256[32];
        // Ép kiểu const uint8* sang uint8* cho hàm (nếu hàm không const)
        uint8 in_256[1184];
        memcpy(in_256, SHA3_256_IN[t], 1184);
        
        sha3_256_hash(in_256, 1184, out_256);
        
        if (memcmp(out_256, SHA3_256_EXP[t], 32) != 0) {
            print_diff(out_256, SHA3_256_EXP[t], 32, "SHA3-256");
            fails++;
        }

        // --- TEST 2: SHA3-512 ---
        uint8 in_33[33];
        memcpy(in_33, INPUT_33[t], 33);
        uint8 out_512[64];
        
        sha3_512_hash(in_33, out_512);
        
        if (memcmp(out_512, SHA3_512_EXP[t], 64) != 0) {
            print_diff(out_512, SHA3_512_EXP[t], 64, "SHA3-512");
            fails++;
        }

        // --- TEST 3: SHAKE-256 PRF ---
        uint64_t out_shake_words[16];
        shake256_prf(in_33, out_shake_words);
        
        // Convert words to bytes to compare
        uint8 out_shake_bytes[128];
        for(int i=0; i<16; i++) {
            uint64_t w = out_shake_words[i];
            for(int j=0; j<8; j++) {
                out_shake_bytes[i*8 + j] = (uint8)(w >> (8*j));
            }
        }
        
        if (memcmp(out_shake_bytes, SHAKE256_EXP[t], 128) != 0) {
            print_diff(out_shake_bytes, SHAKE256_EXP[t], 128, "SHAKE-256");
            fails++;
        }
    }

    if (fails == 0) std::cout << "ALL KECCAK TESTS PASSED!" << std::endl;
    else std::cout << "KECCAK TESTS FAILED: " << fails << " errors." << std::endl;
    
    return fails;
}