#include "params.h"
#include "ap_int.h" // Cần thư viện này cho ap_int/ap_uint

// =========================================================
// PHẦN 1: BẢNG TRA CỨU (BRAM STRATEGY)
// =========================================================

const int16 ZETAS[128] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
};

const int16 GAMMAS[128] = {
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154
};

// =========================================================
// PHẦN 2: MUL_MOD (BARRETT w/ FULL DSP - OPTIMIZED)
// =========================================================
// Sử dụng ap_int để tối ưu hóa độ rộng bit cho bộ nhân
typedef ap_int<13> coeff_t;      // Hệ số Kyber (13-bit)
typedef ap_int<25> prod_t;       // Tích trung gian (25-bit)

int16 mul_mod(int16 a, int16 b) {
    #pragma HLS INLINE
    
    coeff_t a_opt = (coeff_t)a;
    coeff_t b_opt = (coeff_t)b;
    
    // 1. Nhân chính (25-bit) -> Dùng DSP
    // latency=3 để HLS chèn thanh ghi pipeline vào DSP, cắt ngắn delay
    prod_t product;
    #pragma HLS BIND_OP variable=product op=mul impl=dsp latency=3
    product = a_opt * b_opt;

    // 2. Barrett Reduction: product * 20159
    // Kết quả nhân 25bit * 16bit ~ 41 bit -> Dùng ap_int<42>
    ap_int<42> t_full; 
    #pragma HLS BIND_OP variable=t_full op=mul impl=dsp latency=3
    t_full = product * 20159;
    
    coeff_t t = (coeff_t)(t_full >> 26);
    
    // 3. Nhân trừ: t * 3329 -> Dùng DSP
    prod_t sub_term;
    #pragma HLS BIND_OP variable=sub_term op=mul impl=dsp latency=3
    sub_term = t * 3329;
    
    prod_t res = product - sub_term;
    
    // Xử lý modulo cuối
    int16 res_final = (int16)res;
    if (res_final >= 3329) res_final -= 3329;
    
    return res_final;
}

// =========================================================
// PHẦN 3: NTT CORE (FACTOR 2 COMPATIBLE)
// =========================================================
void ntt(int16 poly[256]) {
    #pragma HLS INLINE off
    // Giữ factor=2 theo yêu cầu hệ thống
    #pragma HLS ARRAY_PARTITION variable=poly cyclic factor=2 
    // Ép bảng hằng số vào BRAM để tiết kiệm LUT
    // #pragma HLS BIND_STORAGE variable=ZETAS type=rom_1p impl=bram

    // Dùng int cho các biến vòng lặp truy cập mảng để tránh warning
    int k = 1; 
    
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            
            int16 zeta = ZETAS[k++];
            
            for (int j = start; j < start + len; j++) {
                #pragma HLS PIPELINE II=2
                
                // Pipeline II=1 với factor=2 là khả thi vì mỗi chu kỳ đọc 2 số (poly[j], poly[j+len])
                int16 t = mul_mod(zeta, poly[j + len]);
                int16 r2 = poly[j] - t;
                if (r2 < 0) r2 += KYBER_Q;
                int16 r1 = poly[j] + t;
                if (r1 >= KYBER_Q) r1 -= KYBER_Q;
                
                poly[j + len] = r2;
                poly[j]       = r1;
            }
        }
    }
}

// =========================================================
// PHẦN 4: POINTWISE & INV_NTT
// =========================================================
const int16 F_INV_128 = 3303; 

void basemul(int16 a0, int16 a1, int16 b0, int16 b1, int16 gamma, int16* c0_out, int16* c1_out) {
    #pragma HLS INLINE
    int16 term1 = mul_mod(a0, b0);
    int16 term2 = mul_mod(a1, b1);
    int16 term3 = mul_mod(term2, gamma); 
    
    int16 sum0 = term1 + term3;
    if (sum0 >= KYBER_Q) sum0 -= KYBER_Q;
    *c0_out = sum0;

    int16 term4 = mul_mod(a0, b1);
    int16 term5 = mul_mod(a1, b0);
    int16 sum1 = term4 + term5;
    if (sum1 >= KYBER_Q) sum1 -= KYBER_Q;
    *c1_out = sum1;
}

void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]) {
    #pragma HLS INLINE off
    // #pragma HLS BIND_STORAGE variable=GAMMAS type=rom_1p impl=bram

    // Dùng int cho loop
    Pointwise_Loop: for(int i=0; i<128; i++) {
        #pragma HLS PIPELINE II=1
        
        int16 c0, c1;
        basemul(a[2*i], a[2*i+1], b[2*i], b[2*i+1], GAMMAS[i], &c0, &c1);
        r[2*i]   = c0;
        r[2*i+1] = c1;
    }
}

void inv_ntt(int16 poly[256]) {
    #pragma HLS INLINE off
    #pragma HLS ARRAY_PARTITION variable=poly cyclic factor=2
    // #pragma HLS BIND_STORAGE variable=ZETAS type=rom_1p impl=bram
    
    // Dùng int cho biến vòng lặp
    int k = 127; 
    
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16 zeta = ZETAS[k--]; 
            int16 zeta_inv = KYBER_Q - zeta; 

            for (int j = start; j < start + len; j++) {
                #pragma HLS PIPELINE II=2
                
                int16 t = poly[j];
                int16 r1 = t + poly[j + len];
                if (r1 >= KYBER_Q) r1 -= KYBER_Q;
                int16 t2 = t - poly[j + len];
                if (t2 < 0) t2 += KYBER_Q;
                int16 r2 = mul_mod(t2, zeta_inv); 
                
                poly[j]       = r1;
                poly[j + len] = r2;
            }
        }
    }
    // Vòng lặp cuối cùng
    for (int i = 0; i < 256; i++) {
        #pragma HLS PIPELINE II=1
        poly[i] = mul_mod(poly[i], F_INV_128);
    }
}

// Wrappers (Interface chuẩn)
void ntt_top(int16 poly[256]) {
    #pragma HLS INTERFACE m_axi port=poly bundle=gmem0 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return
    ntt(poly);
}
void invntt_top(int16 poly[256]) {
    #pragma HLS INTERFACE m_axi port=poly bundle=gmem0 max_widen_bitwidth=128
    #pragma HLS INTERFACE s_axilite port=return
    inv_ntt(poly);
}