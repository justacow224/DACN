#include <iostream>
#include "cbd_data.h"
#include "params.h"
#include "ap_int.h"

// Khai báo hàm CBD (trong cbd.cpp)
// Input là mảng ap_uint<64>
void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);

// // Wrapper CBD Top (nếu bạn dùng wrapper)
// void cbd_top(ap_uint<64> input_buf[16], int16 coeffs[256]) {
//     cbd_eta2(input_buf, coeffs);
// }
void cbd_top(
    ap_uint<64> input_buf[16], 
    int16 coeffs[256]
);
int check_result(int16 hw[256], const int16 exp[256], const char* mode) {
    int err = 0;
    for(int i=0; i<256; i++) {
        // Chuẩn hóa về [0, Q) để so sánh (vì output python có thể âm)
        int16 h = hw[i];
        if (h < 0) h += KYBER_Q;
        
        int16 e = exp[i];
        if (e < 0) e += KYBER_Q;
        
        if (h != e) {
            std::cout << "[FAIL " << mode << "] idx=" << i 
                      << " HW=" << h << " Exp=" << e << std::endl;
            err++;
            if(err > 2) break; 
        }
    }
    return err;
}

int main() {
    std::cout << "--- STARTING CBD TEST ---" << std::endl;
    int total_fail = 0;

    for(int t=0; t<NUM_TESTS; t++) {
        // 1. Dữ liệu đầu vào gốc (uint64_t)
        uint64_t raw_input[16];
        for(int i=0; i<16; i++) raw_input[i] = CBD_INPUTS[t][i];
        
        int16 hw_out[256];

        // --- TEST MODE A: SAFE COPY (Khuyên dùng) ---
        // Copy sang ap_uint buffer
        ap_uint<64> safe_input[16];
        for(int i=0; i<16; i++) safe_input[i] = raw_input[i];
        
        // Reset output
        for(int i=0; i<256; i++) hw_out[i] = 0;
        
        cbd_top(safe_input, hw_out);
        
        if (check_result(hw_out, EXPECTED_CBD[t], "SAFE_COPY") != 0) {
            std::cout << ">> Test " << t << " FAILED with Safe Copy!" << std::endl;
            total_fail++;
        }

        // --- TEST MODE B: POINTER CAST (Mô phỏng lỗi Decaps cũ) ---
        /* Lưu ý: Trong C Simulation thuần túy (g++), việc ép kiểu con trỏ 
           (ap_uint<64>*)raw_input KHI input là uint64_t* thường SẼ HOẠT ĐỘNG
           nếu ap_uint chỉ chứa đúng 64 bit data.
           
           TUY NHIÊN, trên HLS/RTL, cấu trúc bộ nhớ có thể khác.
           Nếu Test này PASS trên C-Sim nhưng FAIL trên RTL/Cosim, 
           thì Pointer Cast chính là thủ phạm.
        */
        
        // Uncomment để thử vận may (Có thể gây Segfault nếu ap_uint phức tạp)
        /*
        for(int i=0; i<256; i++) hw_out[i] = 0;
        cbd_top((ap_uint<64>*)raw_input, hw_out);
        if (check_result(hw_out, EXPECTED_CBD[t], "UNSAFE_CAST") != 0) {
             std::cout << ">> Test " << t << " FAILED with Unsafe Cast!" << std::endl;
        }
        */
    }

    if(total_fail == 0) 
        std::cout << "ALL CBD TESTS PASSED!" << std::endl;
    else 
        std::cout << "SOME TESTS FAILED!" << std::endl;

    return total_fail;
}