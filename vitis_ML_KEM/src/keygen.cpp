#include "ap_int.h"
#include "hls_stream.h"
#include "params.h"
#include <cstring>
#include <stdint.h>

// --- EXTERN DECLARATIONS ---
extern void keccak_f1600(uint64_t state[25]);
extern void sha3_256_1184bytes(uint8 input[1184], uint8 output[32]);
extern void sha3_512_33bytes(uint8 input[33], uint8 output[64]);
extern void shake256_33bytes(uint8 input[33], uint64_t output_64[16]);

extern void cbd_eta2(ap_uint<64> input_buf[16], int16 coeffs[256]);
extern void ntt(int16 poly[256]);
extern void poly_pointwise(int16 a[256], int16 b[256], int16 r[256]);
extern void xof_absorb_squeeze(ap_uint<64> input_B[5], hls::stream<uint8> &out_stream);
extern void parse_ntt(hls::stream<uint8> &in_bytes, int16 a_hat[KYBER_N]);

static void poly_tobytes(int16 coeffs[KYBER_N], uint8 output[384]) {
#pragma HLS INLINE
  for (int i = 0; i < KYBER_N / 2; i++) {
#pragma HLS PIPELINE II = 1
    uint16_t t0 = coeffs[2 * i];
    uint16_t t1 = coeffs[2 * i + 1];
    output[3 * i + 0] = (uint8)(t0 & 0xFF);
    output[3 * i + 1] = (uint8)((t0 >> 8) | ((t1 & 0x0F) << 4));
    output[3 * i + 2] = (uint8)(t1 >> 4);
  }
}

#define PK_SIZE_BYTES 1184
#define SK_SIZE_BYTES 2400
#define PK_SIZE_128 (PK_SIZE_BYTES / 16) 
#define SK_SIZE_128 (SK_SIZE_BYTES / 16) 

void ml_kem_keygen(ap_uint<64> seed_d[4], ap_uint<64> seed_z[4],
                   ap_uint<128> pk_out[PK_SIZE_128],
                   ap_uint<128> sk_out[SK_SIZE_128]) {
#pragma HLS INTERFACE m_axi port = seed_d bundle = gmem0 depth = 4
#pragma HLS INTERFACE m_axi port = seed_z bundle = gmem0 depth = 4
#pragma HLS INTERFACE m_axi port = pk_out bundle = gmem1 depth = 74
#pragma HLS INTERFACE m_axi port = sk_out bundle = gmem1 depth = 150
#pragma HLS INTERFACE s_axilite port = return

#pragma HLS ALLOCATION function instances = keccak_f1600 limit = 1
#pragma HLS ALLOCATION function instances = ntt limit = 1
#pragma HLS ALLOCATION function instances = poly_pointwise limit = 1

  // --- BUFFERS ---
  int16 s_hat[KYBER_K][KYBER_N];
#pragma HLS ARRAY_PARTITION variable = s_hat dim = 1 type = complete
#pragma HLS ARRAY_PARTITION variable = s_hat dim = 2 cyclic factor = 2

  int16 e_hat[KYBER_K][KYBER_N];
#pragma HLS ARRAY_PARTITION variable = e_hat dim = 1 type = complete
#pragma HLS ARRAY_PARTITION variable = e_hat dim = 2 cyclic factor = 2

  uint8 pk_local[PK_SIZE_BYTES];
#pragma HLS ARRAY_PARTITION variable = pk_local cyclic factor = 16
  uint8 sk_local[SK_SIZE_BYTES];
#pragma HLS ARRAY_PARTITION variable = sk_local cyclic factor = 16

  uint8 rho[32], sigma[32];
#pragma HLS ARRAY_PARTITION variable = rho complete
#pragma HLS ARRAY_PARTITION variable = sigma complete

  // Step 1: Hash G
  uint8 g_in[33];
#pragma HLS ARRAY_PARTITION variable = g_in complete
  for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
    uint64_t w = seed_d[i];
    for (int j = 0; j < 8; j++)
      g_in[i * 8 + j] = (uint8)(w >> (j * 8));
  }
  g_in[32] = KYBER_K;

  uint8 g_out[64];
  // FIXED: Chia g_out thành các thanh ghi (wires) để đọc ghi song song 100% không bị xung đột
#pragma HLS ARRAY_PARTITION variable = g_out complete

  sha3_512_33bytes(g_in, g_out);
  for (int i = 0; i < 32; i++) {
#pragma HLS UNROLL
    rho[i] = g_out[i];
    sigma[i] = g_out[32 + i];
  }

  uint8 sigma_local[32];
#pragma HLS ARRAY_PARTITION variable = sigma_local complete
  for (int i = 0; i < 32; i++)
    sigma_local[i] = sigma[i];

  // Step 2: Gen s & e 
Gen_S_Loop:
  for (int i = 0; i < KYBER_K; i++) {
    uint8 prf_in[33];
#pragma HLS ARRAY_PARTITION variable = prf_in complete
    for (int k = 0; k < 32; k++)
      prf_in[k] = sigma_local[k];
    prf_in[32] = (uint8)i;

    uint64_t cbd_input[16];
    // FIXED: Partition mảng nhận hash để tránh warning cổng bộ nhớ
#pragma HLS ARRAY_PARTITION variable = cbd_input complete
    
    shake256_33bytes(prf_in, cbd_input);

    ap_uint<64> cbd_ap[16];
#pragma HLS ARRAY_PARTITION variable = cbd_ap complete
    for (int k = 0; k < 16; k++)
      cbd_ap[k] = cbd_input[k];

    int16 poly_temp[256];
#pragma HLS ARRAY_PARTITION variable = poly_temp cyclic factor = 2
    cbd_eta2(cbd_ap, poly_temp);
    ntt(poly_temp);
    
    for (int k = 0; k < 256; k+=2) {
#pragma HLS PIPELINE II=1
      s_hat[i][k] = poly_temp[k];
      s_hat[i][k+1] = poly_temp[k+1];
    }
    poly_tobytes(s_hat[i], &sk_local[i * 384]);
  }

Gen_E_Loop:
  for (int i = 0; i < KYBER_K; i++) {
    uint8 prf_in[33];
#pragma HLS ARRAY_PARTITION variable = prf_in complete
    for (int k = 0; k < 32; k++)
      prf_in[k] = sigma_local[k];
    prf_in[32] = (uint8)(3 + i);
    
    uint64_t cbd_input[16];
#pragma HLS ARRAY_PARTITION variable = cbd_input complete
    shake256_33bytes(prf_in, cbd_input);
    
    ap_uint<64> cbd_ap[16];
#pragma HLS ARRAY_PARTITION variable = cbd_ap complete
    for (int k = 0; k < 16; k++)
      cbd_ap[k] = cbd_input[k];
      
    int16 poly_temp[256];
#pragma HLS ARRAY_PARTITION variable = poly_temp cyclic factor = 2
    cbd_eta2(cbd_ap, poly_temp);
    ntt(poly_temp);
    
    for (int k = 0; k < 256; k+=2) {
#pragma HLS PIPELINE II=1
      e_hat[i][k] = poly_temp[k];
      e_hat[i][k+1] = poly_temp[k+1];
    }
  }

  // Step 3: Matrix Mult
Gen_PK_Loop:
  for (int i = 0; i < KYBER_K; i++) {

    int16 acc[256];
#pragma HLS ARRAY_PARTITION variable = acc cyclic factor = 2

    for(int k=0; k<256; k+=2) {
#pragma HLS PIPELINE II=1
        acc[k] = e_hat[i][k];
        acc[k+1] = e_hat[i][k+1];
    }

    for (int j = 0; j < KYBER_K; j++) {
      ap_uint<64> xof_in[5];
#pragma HLS ARRAY_PARTITION variable = xof_in complete
      for (int w = 0; w < 4; w++) {
#pragma HLS UNROLL
        uint64_t val = 0;
        for (int b = 0; b < 8; b++)
          val |= ((uint64_t)rho[w * 8 + b] << (b * 8));
        xof_in[w] = val;
      }
      xof_in[4] = (uint64_t)j | ((uint64_t)i << 8);

      hls::stream<uint8> strm;
#pragma HLS STREAM variable = strm depth = 16

      int16 A_poly_temp[256];
#pragma HLS ARRAY_PARTITION variable = A_poly_temp cyclic factor = 2

      xof_absorb_squeeze(xof_in, strm);
      parse_ntt(strm, A_poly_temp);
      
      int16 prod[256];
#pragma HLS ARRAY_PARTITION variable = prod cyclic factor = 2
      poly_pointwise(A_poly_temp, s_hat[j], prod);

      for (int k = 0; k < 256; k+=2) {
#pragma HLS PIPELINE II = 1
        ap_int<16> sum0 = (ap_int<16>)acc[k] + prod[k];
        if (sum0 >= KYBER_Q) sum0 -= KYBER_Q;
        acc[k] = (int16)sum0;

        ap_int<16> sum1 = (ap_int<16>)acc[k+1] + prod[k+1];
        if (sum1 >= KYBER_Q) sum1 -= KYBER_Q;
        acc[k+1] = (int16)sum1;
      }
    }
    poly_tobytes(acc, &pk_local[i * 384]);
  }

  int rho_offset = 384 * KYBER_K; // 1152
Pack_Rho_into_PK:
  for (int i = 0; i < 2; i++) {
#pragma HLS PIPELINE II = 1
    for(int j = 0; j < 16; j++) {
        pk_local[rho_offset + i*16 + j] = rho[i*16 + j];
    }
  }

Pack_PK_into_SK:
  for (int i = 0; i < PK_SIZE_BYTES / 16; i++) {
#pragma HLS PIPELINE II = 1
    for(int j = 0; j < 16; j++) {
        sk_local[1152 + i*16 + j] = pk_local[i*16 + j];
    }
  }

  uint8 hpk[32];
#pragma HLS ARRAY_PARTITION variable = hpk complete
  sha3_256_1184bytes(pk_local, hpk);

Pack_Hash_into_SK:
  for (int i = 0; i < 2; i++) {
#pragma HLS PIPELINE II = 1
    for(int j = 0; j < 16; j++) {
        sk_local[2336 + i*16 + j] = hpk[i*16 + j];
    }
  }

  uint8 z_bytes[32];
#pragma HLS ARRAY_PARTITION variable = z_bytes complete
  for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
    uint64_t w = seed_z[i];
    for (int j = 0; j < 8; j++)
      z_bytes[i * 8 + j] = (uint8)(w >> (j * 8));
  }
  
Pack_Z_into_SK:
  for (int i = 0; i < 2; i++) {
#pragma HLS PIPELINE II = 1
    for(int j = 0; j < 16; j++) {
        sk_local[2368 + i*16 + j] = z_bytes[i*16 + j];
    }
  }

Pack_PK_Out:
  for (int i = 0; i < PK_SIZE_128; i++) {
#pragma HLS PIPELINE II = 1
    ap_uint<128> chunk = 0;
    for (int j = 0; j < 16; j++) {
      chunk((j * 8) + 7, j * 8) = pk_local[i * 16 + j];
    }
    pk_out[i] = chunk;
  }

Pack_SK_Out:
  for (int i = 0; i < SK_SIZE_128; i++) {
#pragma HLS PIPELINE II = 1
    ap_uint<128> chunk = 0;
    for (int j = 0; j < 16; j++) {
      chunk((j * 8) + 7, j * 8) = sk_local[i * 16 + j];
    }
    sk_out[i] = chunk;
  }
}