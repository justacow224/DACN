#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include "params.h"

// Kích thước chuẩn cho Kyber-768
#define PK_SIZE 1184 // 384*3 + 32
#define SK_HW_SIZE 1152 // 384*3 (Chỉ phần s_hat encoded)

// Khai báo DUT
void ml_kem_keygen(
    ap_uint<64> seed_d[4],
    ap_uint<64> seed_z[4],
    uint8 pk_out[PK_SIZE],
    uint8 sk_out[SK_HW_SIZE]
);

// --- HELPER FUNCTIONS ---

// 1. Hex String -> Vector Bytes
std::vector<uint8_t> hex2bin(const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// 2. Vector Bytes -> ap_uint<64> Array (Input HW)
void bytes_to_words(const std::vector<uint8_t>& bytes, ap_uint<64> words[4]) {
    for(int i=0; i<4; i++) {
        uint64_t w = 0;
        for(int j=0; j<8; j++) {
            if (i*8 + j < bytes.size())
                w |= ((uint64_t)bytes[i*8 + j] << (j*8));
        }
        words[i] = w;
    }
}

// --- MAIN ---
int main() {
    std::cout << "--- STARTING KAT KEYGEN TEST (BYTE-LEVEL) ---" << std::endl;

    std::ifstream file("KAT_768.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Could not open KAT_768.txt" << std::endl;
        return 1;
    }

    std::string line, token, eq, hex_str;
    std::vector<uint8_t> d_bytes, z_bytes, pk_ref, sk_ref;
    int count = 0, pass_count = 0;

    while (file >> token) {
        if (token == "count") {
            file >> eq >> count;
            std::cout << "Testing Case #" << count << "... ";
        } 
        else if (token == "d") {
            file >> eq >> hex_str;
            d_bytes = hex2bin(hex_str);
        }
        else if (token == "z") {
            file >> eq >> hex_str;
            z_bytes = hex2bin(hex_str);
        }
        else if (token == "pk") {
            file >> eq >> hex_str;
            pk_ref = hex2bin(hex_str);
        }
        else if (token == "sk") {
            file >> eq >> hex_str;
            sk_ref = hex2bin(hex_str);

            // --- CHẠY TEST KHI ĐỦ DỮ LIỆU ---

            // 1. Prepare Input
            ap_uint<64> seed_d[4], seed_z[4];
            bytes_to_words(d_bytes, seed_d);
            bytes_to_words(z_bytes, seed_z);

            // 2. Prepare Output
            uint8 pk_hw[PK_SIZE];
            uint8 sk_hw[SK_HW_SIZE];

            // 3. Call Hardware
            ml_kem_keygen(seed_d, seed_z, pk_hw, sk_hw);

            // 4. Verify Public Key (PK) - So khớp 100% (1184 bytes)
            bool pk_pass = true;
            for(int i=0; i<PK_SIZE; i++) {
                if((uint8_t)pk_hw[i] != pk_ref[i]) {
                    // std::cout << "\nPK Mismatch at " << i 
                    //           << " HW=" << std::hex << (int)pk_hw[i] 
                    //           << " Ref=" << (int)pk_ref[i];
                    pk_pass = false;
                    break;
                }
            }

            // 5. Verify Secret Key (SK) - So khớp phần đầu (1152 bytes)
            bool sk_pass = true;
            for(int i=0; i<SK_HW_SIZE; i++) {
                if((uint8_t)sk_hw[i] != sk_ref[i]) {
                    // std::cout << "\nSK Mismatch at " << i 
                    //           << " HW=" << std::hex << (int)sk_hw[i] 
                    //           << " Ref=" << (int)sk_ref[i];
                    sk_pass = false;
                    break;
                }
            }

            if (pk_pass && sk_pass) {
                std::cout << "PASS" << std::endl;
                pass_count++;
            } else {
                std::cout << "FAIL" << std::endl;
                if(!pk_pass) std::cout << "  -> PK Failed" << std::endl;
                if(!sk_pass) std::cout << "  -> SK Failed (First " << SK_HW_SIZE << " bytes)" << std::endl;
                // return 1; // Uncomment để dừng ngay khi lỗi
            }
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << "Summary: Passed " << pass_count << " / " << count+1 << " cases." << std::endl;
    file.close();
    return 0;
}