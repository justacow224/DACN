#include <iostream>
#include "pointwise_data.h" // File sinh ra
#include "params.h"

// Khai báo hàm
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);

// Hàm kiểm tra sai số Modulo
int check_array(int16 result[256], const int16 expected[256], const char* name) {
    int err = 0;
    for(int i=0; i<256; i++) {
        int16 r = result[i];
        int16 e = expected[i];
        
        // Chuẩn hóa về [0, Q-1] để so sánh
        while(r < 0) r += KYBER_Q;
        while(r >= KYBER_Q) r -= KYBER_Q;
        
        while(e < 0) e += KYBER_Q;
        while(e >= KYBER_Q) e -= KYBER_Q;

        if (r != e) {
            std::cout << "ERROR [" << name << "]: index " << i 
                      << " got " << r << " expected " << e << std::endl;
            err++;
            if (err > 5) break; 
        }
    }
    return err;
}

int main() {
    std::cout << "--- STARTING POLY_POINTWISE TEST ---" << std::endl;
    
    for (int t = 0; t < NUM_TESTS; t++) {
        std::cout << "Running Test Case " << t << "..." << std::endl;
        
        int16 a[256], b[256], r[256];
        
        // Copy Inputs
        for(int i=0; i<256; i++) {
            a[i] = PW_INPUT_A[t][i];
            b[i] = PW_INPUT_B[t][i];
        }
        
        // Gọi hàm HLS
        poly_pointwise(a, b, r);
        
        // Kiểm tra
        if (check_array(r, EXPECTED_PW[t], "Pointwise") != 0) {
            std::cout << ">> FAIL: Pointwise Multiplication failed at test " << t << std::endl;
            return 1;
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << "ALL POINTWISE TESTS PASSED!" << std::endl;
    return 0;
}