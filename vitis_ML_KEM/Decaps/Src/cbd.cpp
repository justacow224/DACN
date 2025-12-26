#include "params.h"
#include "ap_int.h"

// =========================================================
// CBD Core (Eta = 2) - Tối ưu cho cấu hình Factor=2
// =========================================================
void cbd_eta2(
    ap_uint<64> input_buf[16], 
    int16 coeffs[256]
) {
    // Tắt Inline để module hóa, tiết kiệm tài nguyên khi dùng nhiều Lane
    #pragma HLS INLINE off
    
    // Sử dụng int chuẩn cho biến vòng lặp để tối ưu địa chỉ mảng
    Loop_Words: for(int i=0; i<16; i++) {
        
        ap_uint<64> word = input_buf[i];
        
        // Loop Bytes: Xử lý 8 byte trong 1 word 64-bit
        // Mỗi byte sinh ra 2 hệ số -> Tổng 16 hệ số/word
        Loop_Bytes_In_Word: for(int k=0; k<8; k++) {
            // Pipeline II=1: Mỗi clock cycle xử lý 1 byte và ghi 2 hệ số
            #pragma HLS PIPELINE II=1
            
            // 1. Trích xuất byte (8 bit) từ word 64-bit
            ap_uint<8> byte = word.range(8*k + 7, 8*k);
            
            // 2. Tính toán CBD (d = bit_a + bit_b)
            // Các biến này cực nhỏ (0-2), dùng ap_uint<2> tiết kiệm LUT tối đa
            ap_uint<2> d0 = (ap_uint<1>)byte[0] + (ap_uint<1>)byte[1];
            ap_uint<2> d1 = (ap_uint<1>)byte[2] + (ap_uint<1>)byte[3];
            ap_uint<2> d2 = (ap_uint<1>)byte[4] + (ap_uint<1>)byte[5];
            ap_uint<2> d3 = (ap_uint<1>)byte[6] + (ap_uint<1>)byte[7];
            
            // t = d_a - d_b (Kết quả trong khoảng [-2, 2])
            ap_int<4> t1 = (ap_int<4>)d0 - (ap_int<4>)d1;
            ap_int<4> t2 = (ap_int<4>)d2 - (ap_int<4>)d3;
            
            // 3. Hiệu chỉnh Modulo Kyber_Q (Chỉ áp dụng khi t < 0)
            // HLS sẽ tối ưu logic này thành một bộ Multiplexer nhỏ
            int16 res1 = t1;
            if (t1 < 0) res1 += KYBER_Q;
            
            int16 res2 = t2;
            if (t2 < 0) res2 += KYBER_Q;
            
            // 4. Ghi kết quả vào RAM
            // i*16 + 2*k là chỉ số chẵn, +1 là chỉ số lẻ.
            // Vì mảng partitioned cyclic factor=2, hai lệnh ghi này 
            // sẽ trỏ vào 2 ngân hàng RAM khác nhau (Bank 0 và Bank 1).
            coeffs[i*16 + 2*k]     = res1;
            coeffs[i*16 + 2*k + 1] = res2;
        }
    }
}

// Wrapper Top-level
void cbd_top(
    ap_uint<64> input_buf[16], 
    int16 coeffs[256]
) {
    #pragma HLS INTERFACE m_axi port=input_buf bundle=gmem0 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=coeffs bundle=gmem1 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return
    
    // Cấu hình mảng quan trọng nhất để đồng bộ với phần còn lại của hệ thống
    #pragma HLS ARRAY_PARTITION variable=coeffs cyclic factor=2

    cbd_eta2(input_buf, coeffs);
}