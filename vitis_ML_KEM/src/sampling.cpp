#include "params.h"
#include "hls_stream.h"
#include "ap_int.h"

extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8>& out_stream);

// =========================================================
// Parse Function (Algorithm 7: SampleNTT)
// =========================================================
void parse_ntt(
    hls::stream<uint8>& in_bytes,
    int16 a_hat[KYBER_N]
) {
    #pragma HLS INLINE off 

    unsigned int j = 0;
    
    // Ép kiểu hằng số Q sang u12 trước vòng lặp để tránh mạch so sánh bị quá khổ
    const ap_uint<12> Q_U12 = KYBER_Q;

    Parse_Loop: while(j < KYBER_N) {
        #pragma HLS PIPELINE II=3 
        
        uint8 b0 = in_bytes.read();
        uint8 b1 = in_bytes.read();
        uint8 b2 = in_bytes.read();

        ap_uint<12> d1 = ((ap_uint<12>)b0) | (((ap_uint<12>)(b1 & 0x0F)) << 8);
        ap_uint<12> d2 = ((ap_uint<12>)(b1 >> 4)) | (((ap_uint<12>)b2) << 4);

        if(d1 < Q_U12) {
            a_hat[j] = (int16)d1; 
            j++;
        }
        
        if(j < KYBER_N && d2 < Q_U12) {
            a_hat[j] = (int16)d2; 
            j++;
        }
    }
    
    Flush_Loop: while(!in_bytes.empty()) {
        #pragma HLS PIPELINE II=1
        in_bytes.read();
    }
}