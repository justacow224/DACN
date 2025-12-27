#include <iostream>
#include <fstream>
#include "params.h"

// Khai báo hàm HW
void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
void inv_ntt(int16 poly[256]);

// Hàm Wrapper giả lập luồng Decaps
// Input: a, b
// Output: InvNTT(Pointwise(a, b))
void hw_combo_wrapper(int16 a[256], int16 b[256], int16 out[256]) {
    int16 tmp_prod[256];
    
    // 1. Chạy Pointwise (Output sẽ bị chia R - Dữ liệu C)
    poly_pointwise(a, b, tmp_prod);
    
    // 2. Chạy InvNTT (Input là C, Output là D - Đã nhân bù F=1423)
    inv_ntt(tmp_prod);
    
    // Copy ra output
    for(int i=0; i<256; i++) out[i] = tmp_prod[i];
}

bool load_dat(const char* filename, int16* buffer) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "Error opening " << filename << std::endl;
        return false;
    }
    int val;
    for (int i = 0; i < 256; i++) {
        file >> val;
        buffer[i] = (int16)val;
    }
    return true;
}

int main() {
    int16 poly_a[256], poly_b[256], golden_res[256];
    int16 hw_res[256];

    if (!load_dat("pw_in_a.dat", poly_a)) return 1;
    if (!load_dat("pw_in_b.dat", poly_b)) return 1;
    if (!load_dat("pw_inv_out.dat", golden_res)) return 1;

    std::cout << "Running HW Combo (Pointwise + InvNTT)..." << std::endl;
    
    // CHẠY HARDWARE
    hw_combo_wrapper(poly_a, poly_b, hw_res);

    // KIỂM TRA
    int err = 0;
    for(int i=0; i<256; i++) {
        int16 hw = hw_res[i];
        if (hw < 0) hw += KYBER_Q; // Chuẩn hóa số âm
        if (hw >= KYBER_Q) hw -= KYBER_Q;
        
        int16 gold = golden_res[i]; // Python luôn dương
        
        if (hw != gold) {
            std::cout << "Mismatch at " << i << ": HW=" << hw << " Ref=" << gold << std::endl;
            err++;
            if(err > 5) break;
        }
    }

    if (err == 0) {
        std::cout << ">>> COMBO TEST PASSED! System is synchronized." << std::endl;
    } else {
        std::cout << ">>> COMBO TEST FAILED! Data mismatch." << std::endl;
    }

    return err;
}