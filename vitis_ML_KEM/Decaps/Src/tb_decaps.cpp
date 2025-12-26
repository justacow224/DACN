#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include "params.h"

// Kích thước chuẩn cho Kyber-768
#define SK_SIZE 2400 // s_hat + pk + H(pk) + z
#define CT_SIZE 1088 // u + v
#define SS_SIZE 32

// Khai báo DUT (Device Under Test)
void ml_kem_decaps(
    uint8 sk_in[SK_SIZE],
    uint8 ct_in[CT_SIZE],
    uint8 ss_out[SS_SIZE]
);

// --- HÀM HỖ TRỢ ---

// Chuyển Hex String -> Vector Byte
std::vector<uint8_t> hex2bin(const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// So sánh mảng byte
bool verify_bytes(uint8* hw, std::vector<uint8_t>& ref, int len, std::string name) {
    for(int i=0; i<len; i++) {
        if(hw[i] != ref[i]) {
            // Uncomment để debug lỗi chi tiết
            // std::cout << "\n   " << name << " Mismatch at " << i 
            //           << " HW=" << std::hex << (int)hw[i] 
            //           << " Ref=" << (int)ref[i] << std::dec;
            return false;
        }
    }
    return true;
}

// --- MAIN ---
int main() {
    std::cout << "--- STARTING KAT DECAPSULATION TEST ---" << std::endl;

    // Mở file KAT
    std::ifstream file("KAT_768.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Could not open KAT_768.txt" << std::endl;
        return 1;
    }

    std::string token, eq, hex_str;
    
    // Vector lưu dữ liệu đọc từ file
    std::vector<uint8_t> sk_vec, ct_vec, ss_vec;
    
    int count = 0;
    int pass_count = 0;
    
    // Cờ đánh dấu
    bool has_sk = false, has_ct = false, has_ss = false;

    while (file >> token) {
        if (token == "count") {
            file >> eq >> count;
            has_sk = has_ct = has_ss = false;
            std::cout << "Testing Case #" << count << "... ";
        } 
        else if (token == "sk") {
            file >> eq >> hex_str;
            sk_vec = hex2bin(hex_str);
            has_sk = true;
        }
        else if (token == "ct") {
            file >> eq >> hex_str;
            ct_vec = hex2bin(hex_str);
            has_ct = true;
        }
        else if (token == "ss") {
            file >> eq >> hex_str;
            ss_vec = hex2bin(hex_str);
            has_ss = true;
        }

        // KHI ĐỦ DỮ LIỆU INPUT VÀ OUTPUT
        if (has_sk && has_ct && has_ss) {
            
            // 1. Prepare Hardware Buffers
            uint8 sk_in[SK_SIZE];
            uint8 ct_in[CT_SIZE];
            uint8 ss_hw[SS_SIZE];

            // Check size để tránh segfault
            if (sk_vec.size() == SK_SIZE && ct_vec.size() == CT_SIZE) {
                // Copy data
                memcpy(sk_in, sk_vec.data(), SK_SIZE);
                memcpy(ct_in, ct_vec.data(), CT_SIZE);

                // 2. Call Hardware (DUT)
                ml_kem_decaps(sk_in, ct_in, ss_hw);

                // 3. Verify
                if (verify_bytes(ss_hw, ss_vec, SS_SIZE, "SharedSecret")) {
                    std::cout << "PASS" << std::endl;
                    pass_count++;
                } else {
                    std::cout << "FAIL" << std::endl;
                    std::cout << "   -> Shared Secret Mismatch" << std::endl;
                }
            } else {
                std::cout << "SKIP (Data size mismatch)" << std::endl;
                std::cout << "   Expected SK: " << SK_SIZE << ", Got: " << sk_vec.size() << std::endl;
                std::cout << "   Expected CT: " << CT_SIZE << ", Got: " << ct_vec.size() << std::endl;
            }

            // Reset flags
            has_sk = has_ct = has_ss = false;
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << "Summary: Passed " << pass_count << " test cases." << std::endl;
    
    file.close();
    return 0;
}