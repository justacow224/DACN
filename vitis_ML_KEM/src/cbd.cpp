#include "params.h"
#include "ap_int.h"
#include <stdint.h>

// =========================================================
// CBD Core (Eta = 2) - Optimized for Factor=2
// =========================================================
void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]) {
    #pragma HLS INLINE off
    
    for(int i=0; i<16; i++) {
        
        ap_uint<64> word = input_buf[i];

        for(int k=0; k<8; k++) {
            #pragma HLS PIPELINE II=1
            
            // TỐI ƯU LUT: Lấy 8 bit cuối và dịch thanh ghi tuần tự
            // Triệt tiêu hoàn toàn bộ Dynamic Barrel Shifter 64-bit
            uint8_t byte = (uint8_t)(word & 0xFF);
            word >>= 8; 
            
            // Tối ưu các phép toán bit (loại bỏ phép >> 0 thừa thãi)
            ap_uint<2> d0 = (byte & 1)       + ((byte >> 1) & 1);
            ap_uint<2> d1 = ((byte >> 2) & 1) + ((byte >> 3) & 1);
            ap_uint<2> d2 = ((byte >> 4) & 1) + ((byte >> 5) & 1);
            ap_uint<2> d3 = ((byte >> 6) & 1) + ((byte >> 7) & 1);
            
            int16 a0 = (int16)d0 - (int16)d1;
            int16 a1 = (int16)d2 - (int16)d3;
            
            int base_idx = 16 * i + 2 * k;
            coeffs[base_idx]     = a0;
            coeffs[base_idx + 1] = a1;
        }
    }
}