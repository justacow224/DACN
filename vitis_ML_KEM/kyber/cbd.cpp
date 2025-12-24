#include "params.h"
#include "ap_int.h"

// =========================================================
// CBD Core (Eta = 2)
// Input: 128 bytes (16 x 64-bit words)
// Output: 256 poly coefficients
// =========================================================
void cbd_eta2(
    ap_uint<64> input_buf[16], 
    int16 coeffs[256]
) {
    // Giữ INLINE off để tiết kiệm LUT (chia sẻ module nếu cần)
    // Hoặc INLINE nếu bạn muốn tối ưu luồng dữ liệu cục bộ trong Decaps.
    // Với chiến thuật 2-Lane, INLINE off là an toàn.
    #pragma HLS INLINE off
    
    // Loop Words: Duyệt qua 16 từ 64-bit
    Loop_Words: for(int i=0; i<16; i++) {
        // II=2 là kỳ vọng vì mảng output bên ngoài có factor=8
        #pragma HLS PIPELINE II=1
        
        ap_uint<64> word = input_buf[i];
        
        // Loop Bytes: Xử lý 8 byte song song
        Loop_Bytes_In_Word: for(int k=0; k<8; k++) {
            #pragma HLS UNROLL 
            
            // Trích xuất byte (Dùng range bit của ap_uint gọn hơn shift)
            // byte tại k: bit [8*k+7 : 8*k]
            uint8 byte = word.range(8*k + 7, 8*k);
            
            // --- HỆ SỐ 1 (Bits 0-3) ---
            // d0 = bit0 + bit1
            int16 d0 = (byte & 0x1) + ((byte >> 1) & 0x1);
            int16 d1 = ((byte >> 2) & 0x1) + ((byte >> 3) & 0x1);
            int16 t1 = d0 - d1;
            
            // Branchless Modulo: Tiết kiệm Mux
            // Nếu t1 < 0, cộng thêm Q. Ngược lại cộng 0.
            int16 res1 = t1 + ((t1 >> 15) & KYBER_Q);
            
            // --- HỆ SỐ 2 (Bits 4-7) ---
            int16 d2 = ((byte >> 4) & 0x1) + ((byte >> 5) & 0x1);
            int16 d3 = ((byte >> 6) & 0x1) + ((byte >> 7) & 0x1);
            int16 t2 = d2 - d3;
            
            int16 res2 = t2 + ((t2 >> 15) & KYBER_Q);
            
            // Ghi ra mảng (Sẽ tốn 2 cycle để ghi hết 16 số vào RAM 8 cổng)
            coeffs[i*16 + 2*k]     = res1;
            coeffs[i*16 + 2*k + 1] = res2;
        }
    }
}

// Wrapper Top-level (Cho Testbench)
void cbd_top(
    ap_uint<64> input_buf[16], 
    int16 coeffs[256]
) {
    // Cấu hình AXI tối ưu
    #pragma HLS INTERFACE m_axi port=input_buf bundle=gmem0 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=coeffs bundle=gmem1 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return
    
    // Partition local buffer nếu cần mô phỏng factor=16 (tùy ý)
    #pragma HLS ARRAY_PARTITION variable=coeffs cyclic factor=8

    cbd_eta2(input_buf, coeffs);
}