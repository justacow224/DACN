#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include "ap_int.h"
#include "params.h"

// --- KHAI BÁO CÁC HÀM PHẦN CỨNG TOP-LEVEL ---
extern void ml_kem_keygen(ap_uint<64> seed_d[4], ap_uint<64> seed_z[4], ap_uint<128> pk_out[1184/16], ap_uint<128> sk_out[2400/16]);
extern void ml_kem_encaps(ap_uint<128> pk_in[1184/16], ap_uint<128> randomness_m_in[32/16], ap_uint<128> ct_out[1088/16], ap_uint<128> ss_out[32/16]);
extern void ml_kem_decaps(ap_uint<128> sk_in[2400/16], ap_uint<128> ct_in[1088/16], ap_uint<128> ss_out[32/16]);

// --- UTILITY: Chuyển đổi chuỗi Hex sang mảng Byte ---
void hex2bytes(const std::string& hex, uint8_t* bytes) {
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    }
}

// --- UTILITIES: Đóng gói (Pack) từ Byte (Software) sang ap_uint (Hardware AXI Bus) ---
void pack_64(const uint8_t* bytes, ap_uint<64>* chunks, int num_chunks) {
    for (int i = 0; i < num_chunks; i++) {
        ap_uint<64> chunk = 0;
        for (int j = 0; j < 8; j++) {
            chunk((j * 8) + 7, j * 8) = bytes[i * 8 + j];
        }
        chunks[i] = chunk;
    }
}

void pack_128(const uint8_t* bytes, ap_uint<128>* chunks, int num_chunks) {
    for (int i = 0; i < num_chunks; i++) {
        ap_uint<128> chunk = 0;
        for (int j = 0; j < 16; j++) {
            chunk((j * 8) + 7, j * 8) = bytes[i * 16 + j];
        }
        chunks[i] = chunk;
    }
}

// --- UTILITIES: Giải nén (Unpack) từ ap_uint (Hardware) về Byte (Software) ---
void unpack_128(const ap_uint<128>* chunks, uint8_t* bytes, int num_chunks) {
    for (int i = 0; i < num_chunks; i++) {
        ap_uint<128> chunk = chunks[i];
        for (int j = 0; j < 16; j++) {
            bytes[i * 16 + j] = (uint8_t)chunk((j * 8) + 7, j * 8);
        }
    }
}

// --- MAIN TESTBENCH ---
int main() {
    std::cout << "==========================================\n";
    std::cout << "  ML-KEM (KYBER-768) HARDWARE TESTBENCH   \n";
    std::cout << "==========================================\n";

    std::ifstream kat_file("KAT_768.txt");
    if (!kat_file.is_open()) {
        std::cerr << "LỖI: Không thể mở file KAT_768.txt. Hãy đảm bảo file nằm cùng thư mục chạy Csim.\n";
        return -1;
    }

    std::string line;
    int test_case = 0;
    int pass_count = 0;

    // Các bộ nhớ đệm (Software buffers)
    uint8_t d_kat[32], z_kat[32], m_kat[32];
    uint8_t pk_kat[1184], sk_kat[2400], ct_kat[1088], ss_kat[32];
    
    // Đánh dấu để biết khi nào đọc xong 1 testcase (đọc đến ss là xong 1 cụm)
    bool has_d=false, has_z=false, has_pk=false, has_sk=false, has_m=false, has_ct=false;

    while (std::getline(kat_file, line)) {
        if (line.empty()) continue;

        // Tiền xử lý chuỗi: xóa tag "" nếu có
        size_t bracket_pos = line.find(']');
        if (bracket_pos != std::string::npos) {
            line = line.substr(bracket_pos + 1);
        }

        // Tách key và value
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string val = line.substr(eq_pos + 1);

        // Xóa khoảng trắng
        key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
        val.erase(std::remove_if(val.begin(), val.end(), ::isspace), val.end());

        // Parse Hex
        if (key == "d")  { hex2bytes(val, d_kat);  has_d = true; }
        if (key == "z")  { hex2bytes(val, z_kat);  has_z = true; }
        if (key == "pk") { hex2bytes(val, pk_kat); has_pk = true; }
        if (key == "sk") { hex2bytes(val, sk_kat); has_sk = true; }
        if (key == "m")  { hex2bytes(val, m_kat);  has_m = true; }
        if (key == "ct") { hex2bytes(val, ct_kat); has_ct = true; }
        if (key == "ss") { 
            hex2bytes(val, ss_kat); 
            
            // KHI ĐÃ ĐỌC XONG 1 TESTCASE, TIẾN HÀNH CHẠY HARDWARE
            test_case++;
            std::cout << "Running Testcase #" << test_case << "...\n";
            bool tc_pass = true;

            // ==========================================
            // 1. TEST KEYGEN
            // ==========================================
            ap_uint<64> seed_d_hw[4], seed_z_hw[4];
            ap_uint<128> pk_hw[1184/16], sk_hw[2400/16];
            uint8_t pk_out_bytes[1184], sk_out_bytes[2400];

            pack_64(d_kat, seed_d_hw, 4);
            pack_64(z_kat, seed_z_hw, 4);

            ml_kem_keygen(seed_d_hw, seed_z_hw, pk_hw, sk_hw);

            unpack_128(pk_hw, pk_out_bytes, 1184/16);
            unpack_128(sk_hw, sk_out_bytes, 2400/16);

            if (memcmp(pk_kat, pk_out_bytes, 1184) != 0 || memcmp(sk_kat, sk_out_bytes, 2400) != 0) {
                std::cout << "  [FAIL] Keygen mismatch!\n";
                tc_pass = false;
            } else {
                std::cout << "  [PASS] Keygen\n";
            }

            // ==========================================
            // 2. TEST ENCAPS
            // ==========================================
            ap_uint<128> pk_in_hw[1184/16], m_in_hw[32/16];
            ap_uint<128> ct_hw[1088/16], ss_enc_hw[32/16];
            uint8_t ct_out_bytes[1088], ss_enc_bytes[32];

            // Dùng pk từ KAT để đảm bảo Encaps không bị ảnh hưởng nếu Keygen lỗi
            pack_128(pk_kat, pk_in_hw, 1184/16);
            pack_128(m_kat, m_in_hw, 32/16);

            ml_kem_encaps(pk_in_hw, m_in_hw, ct_hw, ss_enc_hw);

            unpack_128(ct_hw, ct_out_bytes, 1088/16);
            unpack_128(ss_enc_hw, ss_enc_bytes, 32/16);

            if (memcmp(ct_kat, ct_out_bytes, 1088) != 0 || memcmp(ss_kat, ss_enc_bytes, 32) != 0) {
                std::cout << "  [FAIL] Encaps mismatch!\n";
                tc_pass = false;
            } else {
                std::cout << "  [PASS] Encaps\n";
            }

            // ==========================================
            // 3. TEST DECAPS
            // ==========================================
            ap_uint<128> sk_in_hw[2400/16], ct_in_hw[1088/16];
            ap_uint<128> ss_dec_hw[32/16];
            uint8_t ss_dec_bytes[32];

            // Dùng sk và ct từ KAT
            pack_128(sk_kat, sk_in_hw, 2400/16);
            pack_128(ct_kat, ct_in_hw, 1088/16);

            ml_kem_decaps(sk_in_hw, ct_in_hw, ss_dec_hw);

            unpack_128(ss_dec_hw, ss_dec_bytes, 32/16);

            if (memcmp(ss_kat, ss_dec_bytes, 32) != 0) {
                std::cout << "  [FAIL] Decaps mismatch!\n";
                tc_pass = false;
            } else {
                std::cout << "  [PASS] Decaps\n";
            }

            // --- Reset cờ cho testcase tiếp theo ---
            if(tc_pass) pass_count++;
            has_d = has_z = has_pk = has_sk = has_m = has_ct = false;
        }
    }

    kat_file.close();

    std::cout << "\n==========================================\n";
    std::cout << " KẾT QUẢ TỔNG QUAN: " << pass_count << " / " << test_case << " TESTCASES PASSED.\n";
    if (pass_count == test_case) {
        std::cout << " CHÚC MỪNG! HỆ THỐNG PHẦN CỨNG CHUẨN XÁC 100%!\n";
    } else {
        std::cout << " CÓ LỖI XẢY RA! HÃY KIỂM TRA LẠI LOG.\n";
    }
    std::cout << "==========================================\n";

    return (pass_count == test_case) ? 0 : 1;
}