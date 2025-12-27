#include <iostream>
#include "ntt_data.h" // File sinh ra từ Python
#include "params.h"

// Khai báo hàm cần test
extern void ntt(int16 poly[256]);
extern void inv_ntt(int16 poly[256]);

// Hàm kiểm tra sai số
int check_array(int16 result[256], const int16 expected[256], const char* name) {
    int err = 0;
    for(int i=0; i<256; i++) {
        // Xử lý modulo để so sánh (vì HLS có thể ra kết quả âm hoặc > Q nhưng đồng dư)
        int16 r = result[i];
        int16 e = expected[i];
        
        // Đưa về [0, Q-1]
        while(r < 0) r += KYBER_Q;
        while(r >= KYBER_Q) r -= KYBER_Q;
        
        while(e < 0) e += KYBER_Q;
        while(e >= KYBER_Q) e -= KYBER_Q;

        if (r != e) {
            std::cout << "ERROR [" << name << "]: index " << i 
                      << " got " << r << " expected " << e << std::endl;
            err++;
            if (err > 5) break; // Chỉ in 5 lỗi đầu tiên
        }
    }
    return err;
}

int main() {
    std::cout << "--- STARTING NTT UNIT TEST ---" << std::endl;
    int total_errors = 0;

    for (int t = 0; t < NUM_TESTS; t++) {
        std::cout << "Running Test Case " << t << "..." << std::endl;
        
        int16 poly[256];
        
        // --- TEST 1: Forward NTT ---
        // Copy input
        for(int i=0; i<256; i++) poly[i] = TEST_INPUTS[t][i];
        
        // Run HLS function
        ntt(poly);
        
        // Check result
        if (check_array(poly, EXPECTED_NTT[t], "NTT") != 0) {
            std::cout << ">> FAIL: Forward NTT failed at test " << t << std::endl;
            return 1;
        }

        // --- TEST 2: Inverse NTT ---
        // Input của InvNTT chính là output của NTT (poly hiện tại)
        // Output mong đợi chính là Input ban đầu (TEST_INPUTS[t])
        // Lưu ý: InvNTT(NTT(x)) = x
        
        inv_ntt(poly);
        
        // Check result (So sánh với input gốc)
        if (check_array(poly, TEST_INPUTS[t], "InvNTT") != 0) {
            std::cout << ">> FAIL: Inverse NTT (Roundtrip) failed at test " << t << std::endl;
            return 1;
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << "ALL TESTS PASSED!" << std::endl;
    return 0;
}