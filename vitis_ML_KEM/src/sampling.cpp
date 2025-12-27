#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"

// Liên kết với hàm XOF từ shake_stream.cpp
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);

// =========================================================
// Parse Function (Algorithm 7: SampleNTT)
// =========================================================
void parse_ntt(
    hls::stream<uint8>& in_bytes,
    int16 a_hat[KYBER_N]
) {
    // Tắt Inline để tiết kiệm tài nguyên khi module này được gọi nhiều nơi
    #pragma HLS INLINE off 

    // j là biến đếm hệ số đã được chấp nhận (0 đến 255)
    // Dùng unsigned int để tối ưu hóa việc tính toán index cho RAM
    unsigned int j = 0;
    
    // Parse Loop: Duyệt cho đến khi đủ 256 hệ số
    // II=3 là giới hạn thấp nhất vì mỗi vòng lặp cần đọc 3 byte từ stream 8-bit
    Parse_Loop: while(j < KYBER_N) {
        #pragma HLS PIPELINE II=3 
        
        // Đọc 3 byte từ XOF stream để tạo ra 2 ứng viên d1, d2
        uint8 b0 = in_bytes.read();
        uint8 b1 = in_bytes.read();
        uint8 b2 = in_bytes.read();

        // Ghép bit tạo 2 số 12-bit (d1, d2)
        // d1: 8 bit b0 + 4 bit thấp b1
        ap_uint<12> d1 = (ap_uint<12>)b0 | ((ap_uint<12>)(b1 & 0x0F) << 8);
        // d2: 4 bit cao b1 + 8 bit b2
        ap_uint<12> d2 = (ap_uint<12>)(b1 >> 4) | ((ap_uint<12>)b2 << 4);

        // Rejection Sampling: Chỉ chấp nhận nếu giá trị nhỏ hơn Q (3329)
        // Việc ghi vào a_hat[j] với factor=2 sẽ tự động khớp với 2 cổng RAM
        if(d1 < (ap_uint<12>)KYBER_Q) {
            a_hat[j] = (int16)d1; 
            j++;
        }
        
        // Kiểm tra điều kiện dừng j < 256 trước khi ghi ứng viên thứ 2
        if(j < KYBER_N && d2 < (ap_uint<12>)KYBER_Q) {
            a_hat[j] = (int16)d2; 
            j++;
        }
    }
    
    // Flush Loop: Xả hết dữ liệu còn lại trong stream để tránh treo hệ thống
    Flush_Loop: while(!in_bytes.empty()) {
        #pragma HLS PIPELINE II=1
        in_bytes.read();
    }
}

// Wrapper Top-level
void sampling_top(
    ap_uint<64> input_B[5],  
    int16 coeffs_out[256]    
) {
    // Interface cấu hình chuẩn Vitis cho board Kria K26
    #pragma HLS INTERFACE m_axi port=input_B bundle=gmem0 max_widen_bitwidth=128
    #pragma HLS INTERFACE m_axi port=coeffs_out bundle=gmem1 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return
    
    // Dataflow cho phép SHAKE và PARSE chạy song song (Stream)
    #pragma HLS DATAFLOW

    // Mảng coeffs_out trong hệ thống được partition factor=2
    #pragma HLS ARRAY_PARTITION variable=coeffs_out cyclic factor=2

    hls::stream<uint8> byte_stream;
    // Buffer stream 256 byte là đủ cho luồng xử lý
    #pragma HLS STREAM variable=byte_stream depth=256 

    xof_absorb_squeeze(input_B, byte_stream);
    parse_ntt(byte_stream, coeffs_out);
}