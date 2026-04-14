#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include "ap_int.h" // Thêm thư viện ap_int
#include "params.h"

// Kích thước chuẩn cho Kyber-768
#define SK_SIZE 2400
#define CT_SIZE 1088
#define SS_SIZE 32

// Kích thước mảng 128-bit
#define SK_SIZE_128 (SK_SIZE / 16) // 150
#define CT_SIZE_128 (CT_SIZE / 16) // 68
#define SS_SIZE_128 (SS_SIZE / 16) // 2

// Khai báo DUT (Device Under Test) cập nhật theo interface mới
void ml_kem_decaps(
    ap_uint<128> sk_in[SK_SIZE_128],
    ap_uint<128> ct_in[CT_SIZE_128],
    ap_uint<128> ss_out[SS_SIZE_128]
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
            
            // Check size để tránh segfault
            if (sk_vec.size() == SK_SIZE && ct_vec.size() == CT_SIZE) {
                
                // 1. Prepare Hardware Buffers (128-bit)
                ap_uint<128> sk_hw_128[SK_SIZE_128];
                ap_uint<128> ct_hw_128[CT_SIZE_128];
                ap_uint<128> ss_hw_128[SS_SIZE_128];

                // Đóng gói Secret Key (2400 bytes -> 150 x 128-bit)
                for(int i = 0; i < SK_SIZE_128; i++) {
                    ap_uint<128> chunk = 0;
                    for(int j = 0; j < 16; j++) {
                        chunk((j * 8) + 7, j * 8) = sk_vec[i * 16 + j];
                    }
                    sk_hw_128[i] = chunk;
                }

                // Đóng gói Ciphertext (1088 bytes -> 68 x 128-bit)
                for(int i = 0; i < CT_SIZE_128; i++) {
                    ap_uint<128> chunk = 0;
                    for(int j = 0; j < 16; j++) {
                        chunk((j * 8) + 7, j * 8) = ct_vec[i * 16 + j];
                    }
                    ct_hw_128[i] = chunk;
                }

                // 2. Call Hardware (DUT)
                ml_kem_decaps(sk_hw_128, ct_hw_128, ss_hw_128);

                // 3. Unpack Output (Shared Secret: 2 x 128-bit -> 32 bytes)
                uint8 ss_hw_bytes[SS_SIZE];
                for(int i = 0; i < SS_SIZE_128; i++) {
                    ap_uint<128> chunk = ss_hw_128[i];
                    for(int j = 0; j < 16; j++) {
                        ss_hw_bytes[i * 16 + j] = (uint8)chunk((j * 8) + 7, j * 8);
                    }
                }

                // 4. Verify
                if (verify_bytes(ss_hw_bytes, ss_vec, SS_SIZE, "SharedSecret")) {
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