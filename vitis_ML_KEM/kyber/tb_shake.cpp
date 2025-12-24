#include <iostream>
#include <iomanip>
#include <string>
#include "params.h"

// Khai báo hàm Top-level từ thiết kế HLS
void test_keccak_top(ap_uint<64> seed_in[4], ap_uint<64> data_out[100]);

// Hàm so sánh kết quả tự động
bool verify(uint64_t* hw_result, uint64_t* expected, int count, std::string case_name) {
    bool pass = true;
    std::cout << "Checking " << case_name << " (" << count * 8 << " bytes)... ";
    
    for(int i=0; i<count; i++) {
        // So sánh từng từ 64-bit
        if(hw_result[i] != expected[i]) {
            std::cout << "\n  [FAIL] Index " << i << ":" << std::endl;
            std::cout << "    Got (HW): 0x" << std::hex << std::setw(16) << std::setfill('0') << hw_result[i] << std::endl;
            std::cout << "    Exp (SW): 0x" << std::hex << std::setw(16) << std::setfill('0') << expected[i] << std::endl;
            pass = false;
        }
    }
    
    if(pass) std::cout << "[PASS]" << std::endl;
    else std::cout << "[FAILED]" << std::endl;
    
    return pass;
}

int main() {
    std::cout << "=============================================" << std::endl;
    std::cout << "   STARTING SHAKE-128 HLS VERIFICATION" << std::endl;
    std::cout << "=============================================" << std::endl;

    ap_uint<64> hw_output[100]; // Buffer chứa kết quả FPGA
    bool all_tests_passed = true;

    // ====================================================================
    // TEST CASE 1: SEED TOÀN SỐ 0
    // Python: b'\x00' * 32
    // ====================================================================
    ap_uint<64> seed1[4] = {0, 0, 0, 0};
    
    // --- KHU VỰC COPY-PASTE TỪ PYTHON (CASE 1) ---
    // Bạn hãy dán mảng "expected_case1" từ terminal vào đây:
    uint64_t expected_case1[4] = {
        0x8d89e3754bcaa724, 0x65bb8cea4de7124f,
        0x1e285b5234bd3307, 0xdb0f1c29d488644b
    };
    // ---------------------------------------------

    test_keccak_top(seed1, hw_output);
    if(!verify((uint64_t*)hw_output, expected_case1, 4, "Case 1: All Zero Seed")) 
        all_tests_passed = false;


    // ====================================================================
    // TEST CASE 2: SEED TĂNG DẦN (INCREMENTAL)
    // Python: 0x00, 0x01, ..., 0x1F
    // C++ (Little Endian): 0x0706050403020100...
    // ====================================================================
    ap_uint<64> seed2[4] = {
        0x0706050403020100, 0x0f0e0d0c0b0a0908, 
        0x1716151413121110, 0x1f1e1d1c1b1a1918
    };

    // --- KHU VỰC COPY-PASTE TỪ PYTHON (CASE 2) ---
    // Bạn hãy dán mảng "expected_case2" từ terminal vào đây:
    uint64_t expected_case2[4] = {
        0x56f875c61d366a06, 0x108a21252bc0cdce,
        0xc09e8579cfcec0ce, 0x927a84e509d4c3fe
    };
    // ---------------------------------------------

    test_keccak_top(seed2, hw_output);
    if(!verify((uint64_t*)hw_output, expected_case2, 4, "Case 2: Incremental Seed"))
        all_tests_passed = false;


    // ====================================================================
    // TEST CASE 3: SEED TOÀN 0xFF
    // Python: b'\xFF' * 32
    // ====================================================================
    ap_uint<64> seed3[4] = {
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
    };

    // --- KHU VỰC COPY-PASTE TỪ PYTHON (CASE 3) ---
    // Bạn hãy dán mảng "expected_case3" từ terminal vào đây:
    uint64_t expected_case3[4] = {
        0x2216af2f2286de44, 0xcd7235d9b3bafd8c,
        0x5802ea835974a03e, 0x354f74851e12bec8
    };
    // ---------------------------------------------

    test_keccak_top(seed3, hw_output);
    if(!verify((uint64_t*)hw_output, expected_case3, 4, "Case 3: All 0xFF Seed"))
        all_tests_passed = false;
        
        
    // ====================================================================
    // TEST CASE 4: SQUEEZE NHIỀU DỮ LIỆU (800 Bytes)
    // Kiểm tra khả năng XOF chạy liên tục
    // ====================================================================
    ap_uint<64> seed4[4] = {
        0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA,
        0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA
    };
    
    // --- KHU VỰC COPY-PASTE TỪ PYTHON (CASE 4) ---
    // Chỉ cần dán 4 từ đầu tiên để kiểm tra logic thôi
    uint64_t expected_case4_head[4] = {
        0x73711f1661a8ff3f, 0xae2864b97d9e62cd,
        0x6be8848e2a317b95, 0x4110c39b043d1ec2
    };
    // ---------------------------------------------

    test_keccak_top(seed4, hw_output);
    if(!verify((uint64_t*)hw_output, expected_case4_head, 4, "Case 4: Long Output (Head Check)"))
        all_tests_passed = false;


    std::cout << "=============================================" << std::endl;
    if(all_tests_passed) {
        std::cout << "   ALL TESTS PASSED! CONGRATULATIONS!" << std::endl;
        return 0;
    } else {
        std::cout << "   SOME TESTS FAILED." << std::endl;
        return 1;
    }
}