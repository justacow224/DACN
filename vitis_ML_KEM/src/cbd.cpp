#include "params.h"
#include "ap_int.h"

// =========================================================
// CBD Core (Eta = 2) - Optimized for Factor=2
// =========================================================
void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]) {
    #pragma HLS INLINE off
    
    // Loop qua 16 words 64-bit
    for(int i=0; i<16; i++) {
        
        ap_uint<64> word = input_buf[i];

        // Loop qua 8 bytes trong word
        // XÓA UNROLL, thay bằng PIPELINE ở đây
        for(int k=0; k<8; k++) {
            #pragma HLS PIPELINE II=1
            
            // 1. Lấy byte ra bằng dịch bit
            uint8_t byte = (uint8_t)(word >> (8 * k));
            
            // 2. Tính toán CBD
            ap_uint<2> d0 = ((byte >> 0) & 1) + ((byte >> 1) & 1);
            ap_uint<2> d1 = ((byte >> 2) & 1) + ((byte >> 3) & 1);
            ap_uint<2> d2 = ((byte >> 4) & 1) + ((byte >> 5) & 1);
            ap_uint<2> d3 = ((byte >> 6) & 1) + ((byte >> 7) & 1);
            
            // 3. Tính a - b
            int16 a0 = (int16)d0 - (int16)d1;
            int16 a1 = (int16)d2 - (int16)d3;
            
            // Ghi 2 hệ số vào mảng (Khớp với factor=2 -> II=1)
            int base_idx = 16 * i + 2 * k;
            coeffs[base_idx]     = a0;
            coeffs[base_idx + 1] = a1;
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