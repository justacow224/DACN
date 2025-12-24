#ifndef PARAMS_H
#define PARAMS_H

#include "ap_int.h"

#define KYBER_K 3
#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32
#define KYBER_ETA1 2
#define KYBER_ETA2 2

// Typedefs mới (Fix lỗi redefinition)
typedef ap_int<16> int16;
typedef ap_uint<16> uint16;
typedef ap_uint<8> uint8;

#endif