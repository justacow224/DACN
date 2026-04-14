#include "params.h"
#include "ap_int.h"

// Định nghĩa kiểu dữ liệu
typedef ap_uint<12> u12_t;
typedef ap_uint<10> u10_t;
typedef ap_uint<4>  u4_t;
typedef ap_uint<1>  u1_t;

// =========================================================
// 1. Poly To Bytes (Encode d=12) - Output 384 bytes
// =========================================================
void poly_frombytes(uint8 input[384], int16 coeffs[KYBER_N]) {
    #pragma HLS INLINE
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        
        int base_idx = i * 3;
        uint8 a = input[base_idx + 0];
        uint8 b = input[base_idx + 1];
        uint8 c = input[base_idx + 2];
        
        u12_t c0 = (u12_t)a | ((u12_t)(b & 0x0F) << 8);
        u12_t c1 = (u12_t)(b >> 4) | ((u12_t)c << 4);
        
        coeffs[2*i]   = (int16)c0;
        coeffs[2*i+1] = (int16)c1;
    }
}

// =========================================================
// 2. Poly From Message (Decode d=1) - Output 256 coeffs
// =========================================================
void poly_frommsg(uint8 msg[32], int16 coeffs[KYBER_N]) {
    #pragma HLS INLINE
    for(int i=0; i<32; i++) {
        uint8 byte = msg[i];
        
        // SỬA LỖI WARNING: Xử lý rõ ràng 2 bit/chu kỳ (II=1)
        for(int j=0; j<8; j+=2) {
            #pragma HLS PIPELINE II=1
            u1_t bit0 = (byte >> j) & 1;
            u1_t bit1 = (byte >> (j+1)) & 1;
            
            coeffs[i*8 + j]   = (bit0 == 1) ? (int16)((KYBER_Q+1)/2) : (int16)0;
            coeffs[i*8 + j+1] = (bit1 == 1) ? (int16)((KYBER_Q+1)/2) : (int16)0;
        }
    }
}

// =========================================================
// 3. Poly To Message (Encode d=1) - Output 32 bytes 
// =========================================================
void poly_tomsg(int16 coeffs[KYBER_N], uint8 output[32]) {
    #pragma HLS INLINE
    for(int i=0; i<32; i++) {
        uint8 byte = 0;
        
        // SỬA LỖI WARNING: Xử lý rõ ràng 2 hệ số/chu kỳ (II=1)
        for(int j=0; j<8; j+=2) {
            #pragma HLS PIPELINE II=1
            int idx = i * 8 + j;
            
            int16 val0 = coeffs[idx];
            int16 val1 = coeffs[idx+1];
            
            if(val0 < 0) val0 += KYBER_Q;
            if(val0 < 0) val0 += KYBER_Q; 
            if(val0 >= KYBER_Q) val0 -= KYBER_Q;
            if(val0 >= KYBER_Q) val0 -= KYBER_Q;

            if(val1 < 0) val1 += KYBER_Q;
            if(val1 < 0) val1 += KYBER_Q; 
            if(val1 >= KYBER_Q) val1 -= KYBER_Q;
            if(val1 >= KYBER_Q) val1 -= KYBER_Q;

            ap_uint<32> t0 = (ap_uint<32>)val0 * 2 + 1664; 
            u1_t bit0 = (u1_t)(t0 / KYBER_Q);
            
            ap_uint<32> t1 = (ap_uint<32>)val1 * 2 + 1664; 
            u1_t bit1 = (u1_t)(t1 / KYBER_Q);
            
            byte |= ((uint8)bit0 << j);
            byte |= ((uint8)bit1 << (j+1));
        }
        output[i] = byte;
    }
}

// =========================================================
// 4. Compress U (d=10) - Output 320 bytes 
// =========================================================
void poly_compress_u(int16 coeffs[KYBER_N], uint8 output[320]) {
    #pragma HLS INLINE
    for(int i=0; i<KYBER_N/4; i++) {
        #pragma HLS PIPELINE II=2 
        u10_t u[4];
        #pragma HLS ARRAY_PARTITION variable=u complete

        for(int k=0; k<4; k++) {
            #pragma HLS UNROLL 
            int16 val = coeffs[4*i+k];
            
            if(val < 0) val += KYBER_Q;
            if(val < 0) val += KYBER_Q;
            if(val >= KYBER_Q) val -= KYBER_Q;
            if(val >= KYBER_Q) val -= KYBER_Q;

            ap_uint<32> t = (ap_uint<32>)val * 1024 + 1664;
            u[k] = (u10_t)((t / KYBER_Q) & 0x3FF);
        }

        int base_idx = 5 * i;
        output[base_idx + 0] = (uint8)(u[0] & 0xFF);
        output[base_idx + 1] = (uint8)((u[0] >> 8) | ((u[1] & 0x3F) << 2));
        output[base_idx + 2] = (uint8)((u[1] >> 6) | ((u[2] & 0x0F) << 4));
        output[base_idx + 3] = (uint8)((u[2] >> 4) | ((u[3] & 0x03) << 6));
        output[base_idx + 4] = (uint8)(u[3] >> 2);
    }
}

// =========================================================
// 5. Decompress U (d=10)
// =========================================================
void poly_decompress_u(uint8 input[320], int16 coeffs[KYBER_N]) {
    #pragma HLS INLINE
    for(int i=0; i<KYBER_N/4; i++) {
        #pragma HLS PIPELINE II=2
        uint8 t[5];
        #pragma HLS ARRAY_PARTITION variable=t complete
        int base_idx = 5 * i;
        for(int k=0; k<5; k++) t[k] = input[base_idx + k];

        u10_t u[4];
        #pragma HLS ARRAY_PARTITION variable=u complete
        
        u[0] = (u10_t)t[0] | ((u10_t)(t[1] & 0x03) << 8);
        u[1] = (u10_t)(t[1] >> 2) | ((u10_t)(t[2] & 0x0F) << 6);
        u[2] = (u10_t)(t[2] >> 4) | ((u10_t)(t[3] & 0x3F) << 4);
        u[3] = (u10_t)(t[3] >> 6) | ((u10_t)t[4] << 2);

        for(int k=0; k<4; k++) {
            #pragma HLS UNROLL
            ap_uint<32> val = (ap_uint<32>)u[k] * KYBER_Q;
            val = (val + 512) >> 10; 
            coeffs[4*i+k] = (int16)val;
        }
    }
}

// =========================================================
// 6. Compress V (d=4) - Output 128 bytes 
// =========================================================
void poly_compress_v(int16 coeffs[KYBER_N], uint8 output[128]) {
    #pragma HLS INLINE
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        
        u4_t u[2];
        for(int k=0; k<2; k++) {
            #pragma HLS UNROLL 
            int16 val = coeffs[2*i+k];
            
            if(val < 0) val += KYBER_Q;
            if(val < 0) val += KYBER_Q;
            if(val >= KYBER_Q) val -= KYBER_Q;
            if(val >= KYBER_Q) val -= KYBER_Q;

            ap_uint<32> t = (ap_uint<32>)val * 16 + 1664;
            u[k] = (u4_t)((t / KYBER_Q) & 0x0F);
        }
        output[i] = (uint8)u[0] | ((uint8)u[1] << 4);
    }
}

// =========================================================
// 7. Decompress V (d=4)
// =========================================================
void poly_decompress_v(uint8 input[128], int16 coeffs[KYBER_N]) {
    #pragma HLS INLINE
    for(int i=0; i<KYBER_N/2; i++) {
        #pragma HLS PIPELINE II=1
        
        uint8 byte = input[i];
        u4_t v0 = (u4_t)(byte & 0x0F);
        u4_t v1 = (u4_t)(byte >> 4);

        ap_uint<32> val0 = (ap_uint<32>)v0 * KYBER_Q;
        coeffs[2*i] = (int16)((val0 + 8) >> 4); 

        ap_uint<32> val1 = (ap_uint<32>)v1 * KYBER_Q;
        coeffs[2*i+1] = (int16)((val1 + 8) >> 4);
    }
}