#include "params.h"

// =========================================================
// PHẦN 1: BẢNG TRA CỨU (LOOKUP TABLES)
// Copy chính xác từ ML_KEM/NTT.py
// =========================================================

// ZETAS (Used for NTT)
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

// GAMMAS (Used for BaseCaseMultiply/Pointwise)
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
// PHẦN 2: CÁC HÀM TOÁN HỌC MODULO
// =========================================================

// Nhân modulo an toàn (Safe Modular Multiplication)
// Đảm bảo khớp với logic Python: (a * b) % Q
// Xử lý cả trường hợp số âm
int16 mul_mod(int16 a, int16 b) {
    #pragma HLS INLINE
    
    // Ép nhân DSP
    int32_t product = (int32_t)a * b;
    #pragma HLS BIND_OP variable=product op=mul impl=dsp
    
    // Barrett Reduction thủ công (Nhanh hơn %)
    // t = (product * 20159) >> 26
    int32_t t = (int32_t)((int64_t)product * 20159 >> 26);
    int32_t res = product - t * 3329;
    
    // Hiệu chỉnh cuối (rất nhẹ)
    if (res >= 3329) res -= 3329;
    
    return (int16)res;
}

// =========================================================
// PHẦN 3: NTT CORE (Algorithm 9)
// =========================================================

void ntt(int16 poly[256]) {
    // 1. TẮT INLINE (Để chia sẻ tài nguyên)
    #pragma HLS INLINE off

    // 1. Chia mảng thành 2 ngân hàng bộ nhớ để truy cập song song 
    // (Cho phép đọc 2 số chẵn/lẻ cùng lúc)
    #pragma HLS ARRAY_PARTITION variable=poly cyclic factor=2 dim=1

    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            
            // Lấy zeta ra khỏi vòng lặp trong để giảm tải
            int16 zeta = ZETAS[k++];

            for (int j = start; j < start + len; j++) {
                // ÉP HLS CHẠY 1 CYCLE/ITERATION
                #pragma HLS PIPELINE II=1 
                // #pragma HLS UNROLL factor=4
                
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
// PHẦN 4: POINTWISE MULTIPLICATION (Algorithm 11 & 12)
// =========================================================

// BaseCaseMultiply (Algorithm 12)
// Nhân 2 đa thức bậc 1: (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma)
void basemul(
    int16 a0, int16 a1,
    int16 b0, int16 b1,
    int16 gamma,
    int16* c0_out, int16* c1_out
) {
    #pragma HLS INLINE
    
    // c0 = (a0*b0 + a1*b1*gamma) % q
    int16 term1 = mul_mod(a0, b0);
    int16 term2 = mul_mod(a1, b1);
    int16 term3 = mul_mod(term2, gamma);
    
    int32_t sum0 = (int32_t)term1 + term3;
    if (sum0 >= KYBER_Q) sum0 -= KYBER_Q; // Logic cộng modulo đơn giản
    // Lưu ý: term3 có thể âm nếu gamma âm và chưa được chuẩn hóa, 
    // nhưng mul_mod của ta đã trả về số dương.
    // Logic an toàn nhất cho phép cộng:
    int16 c0 = (int16)(sum0 % KYBER_Q); 
    // Nếu sum0 vẫn vượt quá giới hạn hoặc âm (do overflow int16 - hiếm), 
    // ta dùng int32_t ở trên là an toàn.

    // c1 = (a0*b1 + a1*b0) % q
    int16 term4 = mul_mod(a0, b1);
    int16 term5 = mul_mod(a1, b0);
    
    int32_t sum1 = (int32_t)term4 + term5;
    int16 c1 = (int16)(sum1 % KYBER_Q);

    *c0_out = c0;
    *c1_out = c1;
}

// MultiplyNTTs (Algorithm 11)
// Input: a, b (NTT domain)
// Output: r (NTT domain)
void poly_pointwise(
    int16 a[256], 
    int16 b[256], 
    int16 r[256]
) {
    #pragma HLS INLINE off
    // Vòng lặp 128 khối (mỗi khối 2 hệ số)
    Pointwise_Loop: for(int i=0; i<128; i++) {
        #pragma HLS PIPELINE II=1
        
        // Load inputs
        int16 a0 = a[2*i];
        int16 a1 = a[2*i+1];
        int16 b0 = b[2*i];
        int16 b1 = b[2*i+1];
        
        // Load gamma
        int16 gam = GAMMAS[i];
        
        // Compute
        int16 c0, c1;
        basemul(a0, a1, b0, b1, gam, &c0, &c1);
        
        // Store
        r[2*i]   = c0;
        r[2*i+1] = c1;
    }
}

// Hằng số f = 128^-1 mod 3329 = 3303
const int16 F_INV_128 = 3303; 

// Inverse NTT (Algorithm 10)
void inv_ntt(int16 poly[256]) {
    // 1. TẮT INLINE (Để chia sẻ tài nguyên)
    #pragma HLS INLINE off
    
    #pragma HLS ARRAY_PARTITION variable=poly cyclic factor=2 dim=1
    
    int k = 127; // Bắt đầu từ cuối bảng Zeta

    // Duyệt ngược Layers: len = 2 -> 4 -> ... -> 128
    for (int len = 2; len <= 128; len <<= 1) {
        
        for (int start = 0; start < 256; start += 2 * len) {
            
            // Trong InvNTT chuẩn Kyber: zeta = zetas[127-k] nhưng đổi dấu
            // Tuy nhiên, logic Gentleman-Sande (GS) thường dùng:
            // a = poly[j], b = poly[j+len]
            // poly[j] = a + b
            // poly[j+len] = (a - b) * zeta
            
            // Ta dùng logic: zeta = ZETAS[k] nhưng đổi dấu (thành 0 - zeta)
            // Hoặc đơn giản là dùng phép trừ ngược.
            
            int16 zeta = ZETAS[k--]; 
            // Lưu ý: Logic này phải khớp với Python. 
            // Nếu Python dùng zetas[127-..] thì k-- từ 127 là đúng.
            // Nhưng zeta trong InvNTT là zeta^-1. 
            // Trong Kyber, ZETAS bao gồm cả nghịch đảo hoặc có tính chất đối xứng.
            // *QUAN TRỌNG*: Hãy thử đổi dấu zeta: zeta = -zeta (hoặc Q - zeta)
            int16 zeta_inv = KYBER_Q - zeta; 

            for (int j = start; j < start + len; j++) {
                #pragma HLS PIPELINE II=1
                // #pragma HLS UNROLL factor=4
                
                int16 t = poly[j];
                
                // GS Butterfly:
                // r1 = a + b
                int16 r1 = t + poly[j + len];
                if (r1 >= KYBER_Q) r1 -= KYBER_Q;
                
                // r2 = (a - b)
                int16 t2 = t - poly[j + len];
                if (t2 < 0) t2 += KYBER_Q;
                
                // r2 = (a - b) * zeta
                int16 r2 = mul_mod(t2, zeta_inv); 
                
                poly[j]       = r1;
                poly[j + len] = r2;
            }
        }
    }

    // Bước cuối: Nhân với 1/128 mod Q
    for (int i = 0; i < 256; i++) {
        #pragma HLS PIPELINE II=1
        poly[i] = mul_mod(poly[i], F_INV_128);
    }
}

// Wrapper Top-level
void invntt_top(int16 poly[256]) {
    #pragma HLS INTERFACE m_axi port=poly bundle=gmem0
    #pragma HLS INTERFACE s_axilite port=return
    inv_ntt(poly);
}