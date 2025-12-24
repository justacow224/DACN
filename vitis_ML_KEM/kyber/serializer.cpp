#include "params.h"
#include "ap_int.h"

// =========================================================
// ByteEncode (d=12)
// Input: 256 hệ số int16 (đã nằm trong khoảng 0..Q-1)
// Output: 384 bytes (vì 256 * 12 / 8 = 384)
// =========================================================
void poly_tomsg(
    int16 coeffs[KYBER_N],
    uint8 output[384]
) {
    #pragma HLS INLINE off
    // Loop xử lý 2 hệ số -> 3 bytes
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        
        uint16 t0 = (uint16)coeffs[2*i];
        uint16 t1 = (uint16)coeffs[2*i+1];

        // Byte 0: 8 bit thấp t0
        output[3*i+0] = (uint8)(t0 & 0xFF);
        // Byte 1: 4 bit cao t0 | 4 bit thấp t1
        output[3*i+1] = (uint8)((t0 >> 8) | ((t1 & 0x0F) << 4));
        // Byte 2: 8 bit cao t1
        output[3*i+2] = (uint8)(t1 >> 4);
    }
}

// Wrapper Top-level
void encode_top(int16 coeffs[256], uint8 out_bytes[384]) {
    #pragma HLS INTERFACE m_axi port=coeffs bundle=gmem0
    #pragma HLS INTERFACE m_axi port=out_bytes bundle=gmem1
    #pragma HLS INTERFACE s_axilite port=return
    poly_tomsg(coeffs, out_bytes);
}

// =========================================================
// 1. Poly From Bytes (Decode 12-bit)
// =========================================================
void poly_frombytes(
    uint8 input[384],
    int16 coeffs[KYBER_N]
) {
    #pragma HLS INLINE off
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        
        uint8 a = input[3*i+0];
        uint8 b = input[3*i+1];
        uint8 c = input[3*i+2];
        
        coeffs[2*i]   = (int16)a | ((int16)(b & 0x0F) << 8);
        coeffs[2*i+1] = ((int16)b >> 4) | ((int16)c << 4);
    }
}

// =========================================================
// 2. Poly From Message (Decode 1-bit)
// =========================================================
void poly_frommsg(
    uint8 msg[32],
    int16 coeffs[KYBER_N]
) {
    #pragma HLS INLINE off
    for(int i=0; i<32; i++) {
        #pragma HLS PIPELINE II=1
        uint8 byte = msg[i];
        for(int j=0; j<8; j++) {
            #pragma HLS UNROLL
            // Branchless logic: mask = (bit) ? -1 : 0
            int16 mask = -((int16)((byte >> j) & 1));
            coeffs[i*8+j] = mask & ((KYBER_Q+1)/2);
        }
    }
}

// =========================================================
// 3. Compress U (d=10)
// =========================================================
void poly_compress_u(
    int16 coeffs[KYBER_N],
    uint8 output[320]
) {
    #pragma HLS INLINE off
    for(int i=0; i<KYBER_N/4; i++) {
        #pragma HLS PIPELINE II=1
        
        uint8 t[5];
        #pragma HLS ARRAY_PARTITION variable=t type=complete

        uint16 u[4];
        #pragma HLS ARRAY_PARTITION variable=u type=complete

        for(int k=0; k<4; k++) {
            #pragma HLS UNROLL // Tính 4 số cùng lúc
            
            int32_t val = (int32_t)coeffs[4*i+k];
            int32_t val_mul;
            // Ép nhân DSP: val * 1024
            // Thực ra nhân 1024 là dịch bit (<<10), HLS tự tối ưu thành dây.
            // Nhưng phép chia cho 3329 mới cần DSP (biến thành nhân nghịch đảo).
            // Ta cứ để DSP cho chắc.
            #pragma HLS BIND_OP variable=val_mul op=mul impl=dsp
            val_mul = val * 1024;

            // Công thức nén: (val * 1024 + 1664) / 3329
            uint32_t compressed = (uint32_t)((val_mul + 1664) / KYBER_Q);
            u[k] = (uint16)(compressed & 0x3FF); 
        }

        // Bit packing (5 bytes)
        t[0] = (uint8)(u[0] & 0xFF);
        t[1] = (uint8)((u[0] >> 8) | ((u[1] & 0x3F) << 2));
        t[2] = (uint8)((u[1] >> 6) | ((u[2] & 0x0F) << 4));
        t[3] = (uint8)((u[2] >> 4) | ((u[3] & 0x03) << 6));
        t[4] = (uint8)(u[3] >> 2);

        for(int k=0; k<5; k++) output[5*i+k] = t[k];
    }
}

// =========================================================
// 4. Compress V (d=4)
// =========================================================
void poly_compress_v(
    int16 coeffs[KYBER_N],
    uint8 output[128]
) {
    #pragma HLS INLINE off
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        
        uint16 u[2];
        for(int k=0; k<2; k++) {
            #pragma HLS UNROLL 
            int32_t val = (int32_t)coeffs[2*i+k];
            
            // Ép DSP cho phép chia (nhân nghịch đảo)
            #pragma HLS BIND_OP variable=val op=mul impl=dsp
            
            // (x * 16 + 1664) / 3329
            uint32_t compressed = (uint32_t)((val * 16 + 1664) / KYBER_Q);
            u[k] = (uint16)(compressed & 0x0F);
        }

        output[i] = (uint8)(u[0] | (u[1] << 4));
    }
}

// =========================================================
// 5. Decompress U (d=10)
// =========================================================
void poly_decompress_u(
    uint8 input[320],
    int16 coeffs[KYBER_N]
) {
    #pragma HLS INLINE off
    for(int i=0; i<KYBER_N/4; i++) {
        #pragma HLS PIPELINE II=1
        
        uint8 t[5];
        #pragma HLS ARRAY_PARTITION variable=t type=complete
        for(int k=0; k<5; k++) t[k] = input[5*i+k];

        uint16 u[4];
        #pragma HLS ARRAY_PARTITION variable=u type=complete
        
        // Bit unpacking
        u[0] = (uint16)t[0] | (((uint16)t[1] & 0x03) << 8);
        u[1] = ((uint16)t[1] >> 2) | (((uint16)t[2] & 0x0F) << 6);
        u[2] = ((uint16)t[2] >> 4) | (((uint16)t[3] & 0x3F) << 4);
        u[3] = ((uint16)t[3] >> 6) | ((uint16)t[4] << 2);

        for(int k=0; k<4; k++) {
            #pragma HLS UNROLL 
            
            // Decompress: (x * Q + 512) >> 10
            // ÉP DÙNG DSP CHO PHÉP NHÂN NÀY (Để giảm tải LUT)
            uint32_t val_mul;
            #pragma HLS BIND_OP variable=val_mul op=mul impl=dsp
            val_mul = (uint32_t)u[k] * KYBER_Q;
            
            uint32_t val = val_mul + 512;
            coeffs[4*i+k] = (int16)(val >> 10);
        }
    }
}

// =========================================================
// 6. Decompress V (d=4)
// =========================================================
void poly_decompress_v(
    uint8 input[128],
    int16 coeffs[KYBER_N]
) {
    #pragma HLS INLINE off
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        #pragma HLS UNROLL factor=4 // Unroll nhẹ cho nhanh
        
        uint8 byte = input[i];
        
        // Tách 2 số
        uint8 v0 = byte & 0x0F;
        uint8 v1 = byte >> 4;

        // Decompress: (x * Q + 8) >> 4
        // Ép dùng DSP
        uint32_t val0_mul, val1_mul;
        #pragma HLS BIND_OP variable=val0_mul op=mul impl=dsp
        #pragma HLS BIND_OP variable=val1_mul op=mul impl=dsp
        
        val0_mul = (uint32_t)v0 * KYBER_Q;
        val1_mul = (uint32_t)v1 * KYBER_Q;

        coeffs[2*i]   = (int16)((val0_mul + 8) >> 4);
        coeffs[2*i+1] = (int16)((val1_mul + 8) >> 4);
    }
}