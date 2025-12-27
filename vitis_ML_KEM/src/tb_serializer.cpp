#include <iostream>
#include <cstring>
#include "poly_data.h"
#include "params.h"
#include "ap_int.h"

// --- DECLARATIONS ---
extern void poly_compress_u(int16 coeffs[256], uint8 output[320]);
extern void poly_decompress_u(uint8 input[320], int16 coeffs[256]);
extern void poly_compress_v(int16 coeffs[256], uint8 output[128]);
extern void poly_decompress_v(uint8 input[128], int16 coeffs[256]);
extern void poly_tomsg(int16 coeffs[256], uint8 output[32]);
extern void poly_frommsg(uint8 msg[32], int16 coeffs[256]);

int check_bytes(uint8* hw, const uint8* exp, int len, const char* name) {
    for(int i=0; i<len; i++) {
        if(hw[i] != exp[i]) {
            std::cout << "[FAIL " << name << "] idx=" << i 
                      << " HW=" << (int)hw[i] << " Exp=" << (int)exp[i] << std::endl;
            return 1;
        }
    }
    return 0;
}

int check_coeffs(int16* hw, const int16* exp, const char* name) {
    for(int i=0; i<256; i++) {
        // Tolerant comparison? No, decompress is deterministic.
        if(hw[i] != exp[i]) {
            std::cout << "[FAIL " << name << "] idx=" << i 
                      << " HW=" << hw[i] << " Exp=" << exp[i] << std::endl;
            return 1;
        }
    }
    return 0;
}

int main() {
    std::cout << "--- STARTING POLY COMPRESS/DECOMPRESS TEST ---" << std::endl;
    int fails = 0;

    for(int t=0; t<NUM_TESTS; t++) {
        int16 poly_in[256];
        for(int i=0; i<256; i++) poly_in[i] = INPUT_POLY[t][i];
        
        // 1. Test Compress U
        uint8 comp_u_out[320];
        poly_compress_u(poly_in, comp_u_out);
        if(check_bytes(comp_u_out, EXP_COMP_U[t], 320, "Compress U")) fails++;
        
        // 2. Test Decompress U
        int16 decomp_u_out[256];
        poly_decompress_u(comp_u_out, decomp_u_out);
        if(check_coeffs(decomp_u_out, EXP_DECOMP_U[t], "Decompress U")) fails++;
        
        // 3. Test Compress V
        uint8 comp_v_out[128];
        poly_compress_v(poly_in, comp_v_out);
        if(check_bytes(comp_v_out, EXP_COMP_V[t], 128, "Compress V")) fails++;
        
        // 4. Test Decompress V
        int16 decomp_v_out[256];
        poly_decompress_v(comp_v_out, decomp_v_out);
        if(check_coeffs(decomp_v_out, EXP_DECOMP_V[t], "Decompress V")) fails++;
        
        // 5. Test ToMsg
        uint8 msg_out[32];
        poly_tomsg(poly_in, msg_out);
        if(check_bytes(msg_out, EXP_MSG[t], 32, "ToMsg")) fails++;
        
        // 6. Test FromMsg
        uint8 msg_in[32];
        for(int i=0; i<32; i++) msg_in[i] = INPUT_MSG[t][i];
        int16 frommsg_out[256];
        poly_frommsg(msg_in, frommsg_out);
        if(check_coeffs(frommsg_out, EXP_FROM_MSG_OUT[t], "FromMsg")) fails++;
    }

    if(fails == 0) std::cout << "ALL POLY TESTS PASSED!" << std::endl;
    else std::cout << "POLY TESTS FAILED with " << fails << " errors." << std::endl;
    
    return fails;
}