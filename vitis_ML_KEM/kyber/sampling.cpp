#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"

// Link tới hàm XOF bên shake_stream.cpp
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);

// =========================================================
// Parse Function (Algorithm 7: SampleNTT)
// =========================================================
void parse_ntt(
    hls::stream<uint8>& in_bytes,
    int16 a_hat[KYBER_N]
) {
    // 1. CẤM INLINE: Để module này gọn gàng, có thể tái sử dụng
    #pragma HLS INLINE off 

    int j = 0;
    
    // Parse Loop
    // Lưu ý: Stream 8-bit giới hạn tốc độ ở mức II=3 (3 cycles/iter)
    Parse_Loop: while(j < KYBER_N) {
        #pragma HLS PIPELINE II=3 
        
        // Đọc 3 bytes (Block reading)
        // Cần đảm bảo stream không rỗng, nhưng XOF logic đã đảm bảo đủ data
        uint8 b0 = in_bytes.read();
        uint8 b1 = in_bytes.read();
        uint8 b2 = in_bytes.read();

        // Ghép bit (Little Endian)
        // d1: 12 bits từ b0 và 4 bit thấp của b1
        uint16 d1 = (uint16)b0 | (((uint16)b1 & 0x0F) << 8);
        
        // d2: 12 bits từ 4 bit cao của b1 và b2
        uint16 d2 = ((uint16)b1 >> 4) | ((uint16)b2 << 4);

        // Rejection Sampling (Logic chuẩn)
        if(d1 < KYBER_Q) {
            a_hat[j] = (int16)d1;
            j++;
        }
        
        // Kiểm tra j < N để tránh ghi tràn mảng
        if(j < KYBER_N && d2 < KYBER_Q) {
            a_hat[j] = (int16)d2;
            j++;
        }
    }
    
    // Flush Loop (Xả hàng thừa)
    // Rất quan trọng để tránh tắc nghẽn stream cho lần gọi sau
    Flush_Loop: while(!in_bytes.empty()) {
        #pragma HLS PIPELINE II=1
        in_bytes.read();
    }
}

// =========================================================
// Top Function Wrapper (Simulation / Testbench)
// =========================================================
void sampling_top(
    ap_uint<64> input_B[5],  
    int16 coeffs_out[256]    
) {
    // Tối ưu giao tiếp AXI: Ép dùng 128-bit để nạp/xuất nhanh hơn
    #pragma HLS INTERFACE m_axi port=input_B bundle=gmem0 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=coeffs_out bundle=gmem1 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return
    
    // DATAFLOW: Cho phép XOF vừa đẻ trứng, Parse vừa ấp trứng cùng lúc
    #pragma HLS DATAFLOW

    hls::stream<uint8> byte_stream;
    #pragma HLS STREAM variable=byte_stream depth=256 

    // 1. Producer: SHAKE128
    xof_absorb_squeeze(input_B, byte_stream);
    
    // 2. Consumer: SampleNTT
    parse_ntt(byte_stream, coeffs_out);
}