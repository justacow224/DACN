#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include "params.h"

// Kích thước chuẩn cho Kyber-768
#define PK_SIZE 1184
#define CT_SIZE 1088
#define SS_SIZE 32
#define MSG_SIZE 32

// Khai báo DUT (Device Under Test)
void ml_kem_encaps(
    uint8 pk_in[PK_SIZE],
    uint8 randomness_m[32],
    uint8 ct_out[CT_SIZE],
    uint8 ss_out[SS_SIZE]
);

// --- CÁC HÀM HỖ TRỢ ---

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

// So sánh mảng byte và in lỗi chi tiết
bool verify_bytes(uint8* hw, std::vector<uint8_t>& ref, int len, std::string name) {
    for(int i=0; i<len; i++) {
        if(hw[i] != ref[i]) {
            // Uncomment dòng dưới nếu muốn debug chi tiết từng byte lỗi
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
    std::cout << "--- STARTING KAT ENCAPSULATION TEST ---" << std::endl;

    // Mở file KAT_768.txt
    std::ifstream file("KAT_768.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Could not open KAT_768.txt" << std::endl;
        return 1;
    }

    std::string token, eq, hex_str;
    
    // Các biến lưu dữ liệu tạm thời cho mỗi test case
    std::vector<uint8_t> pk_vec, msg_vec, ct_vec, ss_vec;
    
    int count = 0;
    int pass_count = 0;
    
    // Cờ đánh dấu đã đọc đủ dữ liệu cho 1 case chưa
    bool has_pk = false, has_msg = false, has_ct = false, has_ss = false;

    while (file >> token) {
        // Đọc dấu "=" và giá trị hex
        if (token == "count") {
            file >> eq >> count;
            // Reset cờ cho case mới
            has_pk = has_msg = has_ct = has_ss = false;
            std::cout << "Testing Case #" << count << "... ";
        } 
        else if (token == "pk") {
            file >> eq >> hex_str;
            pk_vec = hex2bin(hex_str);
            has_pk = true;
        }
        else if (token == "msg" || token == "m") { // Hỗ trợ cả key 'msg' và 'm'
            file >> eq >> hex_str;
            msg_vec = hex2bin(hex_str);
            has_msg = true;
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

        // KHI ĐÃ ĐỦ DỮ LIỆU -> CHẠY TEST NGAY
        if (has_pk && has_msg && has_ct && has_ss) {
            
            // 1. Prepare Buffers
            uint8 pk_in[PK_SIZE];
            uint8 m_in[MSG_SIZE];
            uint8 ct_hw[CT_SIZE];
            uint8 ss_hw[SS_SIZE];

            // Copy vector sang array (Check size để an toàn)
            if (pk_vec.size() == PK_SIZE && msg_vec.size() == MSG_SIZE) {
                memcpy(pk_in, pk_vec.data(), PK_SIZE);
                memcpy(m_in, msg_vec.data(), MSG_SIZE);

                // 2. Call Hardware
                ml_kem_encaps(pk_in, m_in, ct_hw, ss_hw);

                // 3. Verify
                bool p1 = verify_bytes(ct_hw, ct_vec, CT_SIZE, "Ciphertext");
                bool p2 = verify_bytes(ss_hw, ss_vec, SS_SIZE, "SharedSecret");

                if (p1 && p2) {
                    std::cout << "PASS" << std::endl;
                    pass_count++;
                } else {
                    std::cout << "FAIL" << std::endl;
                    if(!p1) std::cout << "   -> Ciphertext Mismatch" << std::endl;
                    if(!p2) std::cout << "   -> Shared Secret Mismatch" << std::endl;
                }
            } else {
                std::cout << "SKIP (Data size mismatch)" << std::endl;
            }

            // Reset cờ để tránh chạy lại case cũ
            has_pk = has_msg = has_ct = has_ss = false;
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << "Summary: Passed " << pass_count << " test cases." << std::endl;
    
    file.close();
    return 0;
}