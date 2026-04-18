# Roadmap: Batch 3 → 6 (ML-KEM-768 Pure RTL)

> **Platform:** Kria KR260 (ZU5EV) | **Clock:** 100 MHz | **Architecture:** Sequential Host-Port Pump

---

## Dependency Graph

```
Batch 1 (Serialization) ✅
    ├──→ Batch 2 (ML-KEM KeyGen) ✅ VERIFIED
    ├──→ Batch 3 (K-PKE Decrypt) DONE - VERIFIED (KAT 100/100 pass, TB_REV 2026-04-18 full-kat-default)
    │        └──→ Batch 4 (K-PKE Encrypt + ML-KEM Encaps)
    │                 └──→ Batch 5 (ML-KEM Decaps)
    │                          └──→ Batch 6 (AXI Integration)
    └──→ Batch 3 ← (Decrypt cũng cần Batch 1)
```

---
---

# Batch 3 — K-PKE Decrypt
Status: DONE - VERIFIED
Evidence: decaps_metrics/sim_decrypt_20260418_114128 and sim_decrypt_20260418_112811 (ALL TESTS PASSED: 100 KAT vectors).

**FIPS 203 Ref:** Algorithm 15 (K-PKE.Decrypt)
**HLS Golden:** `decaps.cpp` lines 86–146 (phần DECODE + DECRYPT)

## Algorithm (pseudo-code cho RTL)

```
Input:  dk_PKE  (1152 bytes = 3 × 384)    — ByteEncode_12(ŝ)
        ct      (1088 bytes = 3×320 + 128) — c1 || c2
Output: m       (32 bytes)

// Step 1: Decode secret key
for i = 0..2:
    ŝ[i] = ByteDecode_12(dk_PKE[i*384 .. (i+1)*384-1])     // poly_frombytes

// Step 2: Decompress ciphertext
for i = 0..2:
    u[i] = Decompress_10(c1[i*320 .. (i+1)*320-1])          // poly_decompress d=10

v = Decompress_4(c2[0..127])                                // poly_decompress d=4

// Step 3: NTT(u)
for i = 0..2:
    û[i] = NTT(u[i])                                        // ntt_top

// Step 4: Inner product ŝ^T · û
acc = Pointwise(ŝ[0], û[0])
for i = 1..2:
    tmp = Pointwise(ŝ[i], û[i])
    acc = Add(acc, tmp)

// Step 5: INTT
w = INTT(acc)                                               // inv_ntt_top

// Step 6: v - w
diff = Sub(v, w)                                            // poly_add_sub_top (is_sub=1)

// Step 7: Compress to message
m = Compress_1(diff)                                        // poly_compress d=1
```

## Files cần tạo

| File | Mô tả |
|------|--------|
| `sources_1/new/kpke_decrypt.v` | FSM orchestrator |
| `sim_1/new/tb_kpke_decrypt.sv` | KAT-driven testbench |

## IP Cores instantiate bên trong

- 1× `ntt_top`
- 1× `inv_ntt_top`
- 1× `poly_pointwise_top`
- 1× `poly_add_sub_top`
- 1× `poly_frombytes`
- 1× `poly_decompress`
- 1× `poly_compress` (d=1 only)

> **Không cần** `keccak_sponge_top` — Decrypt không hashing.

## BRAM nội bộ

| Tên | Số lượng | Kích thước | Mục đích |
|-----|---------|-----------|----------|
| `s_hat[0..2]` | 3× BRAM18K | 256×16 mỗi cái | Khóa bí mật (decode từ dk) |
| `u_hat[0..2]` | 3× BRAM18K | 256×16 mỗi cái | NTT(u) |
| `acc` | 1× BRAM18K | 256×16 | Accumulator cho inner product |
| **Tổng** | **7× BRAM18K** | | |

Thêm byte buffer cho `ct_in` (1088 bytes) và `v_poly` (256×16) — tùy kiến trúc I/O.

## FSM States

```
S_IDLE
  │ start
  ▼
S_DECODE_SK ──── poly_frombytes × 3 → ŝ[0..2] vào BRAM
  │
  ▼
S_DECOMPRESS_U ── poly_decompress(d=10) × 3 → u[0..2] (ghi tạm)
  │
  ▼
S_DECOMPRESS_V ── poly_decompress(d=4) → v
  │
  ▼
S_NTT_U_LOOP (i=0..2) ──── Pump u[i] → NTT → û[i] vào BRAM
  │
  ▼
S_POINTWISE_ACC_LOOP (i=0..2):
  │  i=0: acc = Pointwise(ŝ[0], û[0])
  │  i>0: tmp = Pointwise(ŝ[i], û[i])
  │       acc = Add(acc, tmp)
  │
  ▼
S_INTT_W ──── INTT(acc) → w
  │
  ▼
S_SUB_V_W ──── Sub(v, w) → diff    (is_sub = 1)
  │
  ▼
S_COMPRESS_MSG ── Compress_1(diff) → m (32 bytes output)
  │
  ▼
S_DONE
```

## Cycle Estimate

| Bước | Cycles |
|------|--------|
| 3× frombytes | 3 × 200 ≈ 600 |
| 3× decompress_10 + 1× decompress_4 | 4 × 200 ≈ 800 |
| 3× NTT | 3 × 900 ≈ 2,700 |
| 3× Pointwise | 3 × 140 ≈ 420 |
| 2× Add | 2 × 130 ≈ 260 |
| 1× INTT | 900 |
| 1× Sub | 130 |
| 1× compress_1 | 150 |
| Pump overhead | ~5,000 |
| **Tổng** | **~11,000 cycles → ~110 µs** |

## Verification

- **KAT source:** Trích `dk_PKE` + `ct` từ NIST KAT → verify `m` output
- **Self-checking:** byte-to-byte compare `m_out[31:0]` vs expected
- **Edge case:** Tất cả hệ số u ở biên `q-1` hoặc `0` — kiểm tra rounding

## Lưu ý Kỹ thuật

1. `poly_decompress` cần MUX chọn `d_sel` (10 cho u, 4 cho v) — FSM set trước mỗi lần gọi
2. `poly_frombytes` đọc byte stream → output coefficient pairs — cần byte BRAM cho dk input
3. `v` chỉ có 1 poly → có thể lưu trong BRAM acc hoặc add_sub.RAM_A
4. Inner product là **gộp** (accumulate), không tách từng bước — cần giữ acc trong add_sub.RAM_A xuyên suốt loop

---
---

# Batch 4 — K-PKE Encrypt + ML-KEM Encaps

**FIPS 203 Ref:** Algorithm 14 (K-PKE.Encrypt) + Algorithm 17 (ML-KEM.Encaps)
**HLS Golden:** `encaps.cpp` (full file)

## Algorithm K-PKE.Encrypt

```
Input:  ek  (1184 bytes = 3×384 + 32)  — ByteEncode_12(t̂) || ρ
        m   (32 bytes)                  — message
        r   (32 bytes)                  — randomness
Output: c   (1088 bytes = 3×320 + 128) — c1 || c2

// Step 1: Decode ek
for i = 0..2:
    t̂[i] = ByteDecode_12(ek[i*384..(i+1)*384-1])
ρ = ek[1152..1183]

// Step 2: Generate noise
for i = 0..2:
    r̂[i] = NTT(CBD_η2(PRF(r, i)))        // nonce = 0,1,2
for i = 0..2:
    e1[i] = CBD_η2(PRF(r, 3+i))           // nonce = 3,4,5
e2 = CBD_η2(PRF(r, 6))                    // nonce = 6

// Step 3: Compute u = INTT(Â^T · r̂) + e1
for i = 0..2:
    acc = 0
    for j = 0..2:
        Â^T[i][j] = SampleNTT(XOF(ρ || i || j))     ⚠️ ρ||i||j (TRANSPOSE!)
        acc = acc + Pointwise(Â^T[i][j], r̂[j])
    u[i] = INTT(acc) + e1[i]

// Step 4: Compute v = INTT(t̂^T · r̂) + e2 + encode(m)
v_acc = 0
for i = 0..2:
    v_acc = v_acc + Pointwise(t̂[i], r̂[i])
v = INTT(v_acc) + e2 + Decompress_1(m)    // Decompress_1(m) = poly_frommsg

// Step 5: Compress output
for i = 0..2:
    c1[i] = Compress_10(u[i])
c2 = Compress_4(v)
c = c1 || c2
```

> [!CAUTION]
> **XOF Index cho Encrypt: `ρ || i || j` — ĐẢO so với KeyGen (`ρ || j || i`)!**
> Encrypt tính Â^T (transpose), nên index đảo.
> Xác minh: `encaps.cpp` line 274: `xof_in[4] = (uint64_t)i | ((uint64_t)j << 8)`

## Algorithm ML-KEM.Encaps (thin wrapper)

```
Input:  ek  (1184 bytes)
        m   (32 bytes, random)
Output: K   (32 bytes — shared secret)
        c   (1088 bytes — ciphertext)

1. h = SHA3-256(ek)                       // H(ek)
2. (K, r) = SHA3-512(m || h)              // G(m || H(ek))
3. c = K-PKE.Encrypt(ek, m, r)
4. return (K, c)
```

> **Không có KDF** — FIPS 203 final đã loại bỏ `SHAKE-256(K || H(c))`.

## Files cần tạo

| File | Mô tả |
|------|--------|
| `sources_1/new/kpke_encrypt.v` | FSM orchestrator cho K-PKE.Encrypt |
| `sources_1/new/ml_kem_encaps.v` | Thin wrapper gọi kpke_encrypt |
| `sim_1/new/tb_kpke_encrypt.sv` | Roundtrip test: Dec(Enc(m)) == m |
| `sim_1/new/tb_ml_kem_encaps.sv` | Full KAT test |

## Module phụ mới cần tạo

### [NEW] `poly_frommsg.v`
Chuyển 32-byte message → 256 coefficients (Decompress_1):
```
for i = 0..31:
    for j = 0..7:
        coeff[8*i+j] = ((msg[i] >> j) & 1) * ⌈q/2⌉     // = 0 hoặc 1665
```
Module rất đơn giản, ~50 lines. FSM: read byte → extract 8 bits → write 8 coefficients.

### [NEW] `poly_tomsg.v` (nếu chưa có — tương đương Compress_1)
Có thể reuse `poly_compress` với `d_sel = 1`.

## IP Cores cho `kpke_encrypt.v`

- 1× `keccak_sponge_top` (SHAKE128 cho XOF, SHAKE256 cho PRF)
- 1× `poly_cbd_eta2_top`
- 1× `ntt_top`
- 1× `inv_ntt_top`
- 1× `poly_parse_inline_top`
- 1× `poly_pointwise_top`
- 1× `poly_add_sub_top`
- 1× `poly_frombytes`
- 1× `poly_compress` (d=10 và d=4)
- 1× `poly_frommsg` (encode message)

## BRAM nội bộ cho `kpke_encrypt.v`

| Tên | Số lượng | Mục đích |
|-----|---------|----------|
| `t_hat[0..2]` | 3× BRAM18K | Decode từ ek |
| `r_hat[0..2]` | 3× BRAM18K | NTT(CBD(PRF(r))) |
| `e1[0..2]` | 3× BRAM18K | Noise e1 (time-domain, không NTT) |
| `e2` | 1× BRAM18K | Noise e2 |
| `acc / A_hat_buf` | 1× BRAM18K | Tạm cho XOF parse + accumulator |
| `v_poly` | 1× BRAM18K | Kết quả v |
| **Tổng** | **12× BRAM18K** | |

## FSM States cho `kpke_encrypt.v`

```
S_IDLE
  │ start
  ▼
S_DECODE_EK ──── frombytes × 3 → t̂[0..2], extract ρ (32 bytes)
  │
  ▼
S_GEN_R_LOOP (i=0..2) ──── SHAKE256(r||i) → CBD → NTT → r̂[i]
  │
  ▼
S_GEN_E1_LOOP (i=0..2) ─── SHAKE256(r||3+i) → CBD → e1[i]  (NO NTT!)
  │
  ▼
S_GEN_E2 ──── SHAKE256(r||6) → CBD → e2
  │
  ▼
┌─S_CALC_U_LOOP (i=0..2, j=0..2)──────────────────────────┐
│  ├─ S_XOF_AT ──── SHAKE128(ρ || i || j) → Parse → Â^T   │  ⚠️ i||j!
│  ├─ S_LOAD_PW ─── Pump Â^T → PW.A, r̂[j] → PW.B         │
│  ├─ S_RUN_PW ──── Pointwise, wait done                   │
│  ├─ S_LOAD_ADD ── Pump result → ADD.B                     │
│  ├─ S_RUN_ADD ─── acc += PW_result                        │
│  └─ (j==2) → S_INTT_U → S_ADD_E1 → store u[i]           │
└───────────────────────────────────────────────────────────┘
  │  u[i] = INTT(acc) + e1[i]
  ▼
S_CALC_V ──── t̂^T · r̂ (PW+Add × 3) → INTT → + e2 → + encode(m) → v
  │
  ▼
S_COMPRESS_U ── compress_10(u[i]) × 3 → c1
  │
  ▼
S_COMPRESS_V ── compress_4(v) → c2
  │
  ▼
S_DONE ──── c = c1 || c2
```

## Cycle Estimate

| Bước | Cycles |
|------|--------|
| 3× frombytes (t̂) | 600 |
| 7× SHAKE256+CBD (r,e1,e2) | 7 × 2,500 ≈ 17,500 |
| 3× NTT (r) | 2,700 |
| 9× SHAKE128+Parse (Â^T) | 9 × 3,500 ≈ 31,500 |
| 9× Pointwise + 9× Add (u-loop) | 9 × 270 ≈ 2,430 |
| 3× Pointwise + 2× Add (v-loop) | 680 |
| 3× INTT (u) + 1× INTT (v) | 3,600 |
| 3× Add e1 + Add e2 + Add msg | 650 |
| 3× compress_10 + 1× compress_4 | 800 |
| Pump overhead | ~20,000 |
| **Tổng** | **~80,000 cycles → ~800 µs** |

## Verification

### `tb_kpke_encrypt.sv` — Roundtrip Test (MILESTONE!)
```
1. Load seed_d → ml_kem_keygen → (ek, dk)
2. Chọn random m, r
3. kpke_encrypt(ek, m, r) → ct
4. kpke_decrypt(dk[0:1151], ct) → m'
5. ASSERT: m == m'
```
Đây là bài test quan trọng nhất — chứng minh Encrypt/Decrypt đúng đối xứng.

### `tb_ml_kem_encaps.sv` — KAT Test
```
1. Load (pk, randomness_m) từ KAT
2. ml_kem_encaps(pk, m) → (K, ct)
3. Compare K, ct vs KAT golden
```

---
---

# Batch 5 — ML-KEM Decaps

**FIPS 203 Ref:** Algorithm 18 (ML-KEM.Decaps)
**HLS Golden:** `decaps.cpp` (full file)

## Algorithm

```
Input:  dk  (2400 bytes = dk_PKE || ek || h || z)
        ct  (1088 bytes)
Output: K   (32 bytes — shared secret)

// Unpack dk
dk_PKE = dk[0..1151]           // 1152 bytes
ek     = dk[1152..2335]        // 1184 bytes
h      = dk[2336..2367]        // 32 bytes = H(ek), pre-computed
z      = dk[2368..2399]        // 32 bytes = implicit rejection seed

// Step 1: Decrypt
m' = K-PKE.Decrypt(dk_PKE, ct)

// Step 2: Re-derive keys
(K', r') = SHA3-512(m' || h)              // G(m' || h)

// Step 3: Re-encrypt
ct' = K-PKE.Encrypt(ek, m', r')

// Step 4: Constant-time compare
match = ConstantTimeCompare(ct, ct')       // XOR-accumulate ALL 1088 bytes

// Step 5: Conditional output
if match:
    K = K'                                 // 32 bytes from SHA3-512 output
else:
    K = SHAKE-256(z || ct, 32)             // Implicit rejection — deterministic

// SECURITY: Both branches MUST execute. Final K = MUX(match, K', K_reject)
```

> [!WARNING]
> **Security-Critical:**
> 1. **Constant-time compare:** XOR-accumulate, NO early exit
> 2. **Implicit rejection:** Output `SHAKE-256(z || ct)` khi fail, KHÔNG return error
> 3. **Both K' and K_reject phải được tính xong** trước khi MUX chọn output
> 4. **Zeroization:** Clear m', r', K' khỏi BRAM/register sau khi done

## Quyết định Kiến trúc: Shared-Core FSM

Decaps chạy tuần tự: Decrypt → Hash → Re-Encrypt → Compare.
**KHÔNG** instantiate cả `kpke_decrypt` + `kpke_encrypt` (→ 2× tất cả cores, lãng phí).
Thay vào đó: **1 bộ shared cores** với FSM 2-pha.

> Điều này khác với Batch 2 (mỗi module có cores riêng) vì Decaps chạy
> Decrypt và Encrypt **tuần tự**, không bao giờ song song.

## Files cần tạo

| File | Mô tả |
|------|--------|
| `sources_1/new/ml_kem_decaps.v` | FSM orchestrator (shared cores, 2-pha) |
| `sim_1/new/tb_ml_kem_decaps.sv` | Full KAT + implicit rejection test |

## IP Cores instantiate bên trong

- 1× `keccak_sponge_top` (SHA3-512, SHAKE128, SHAKE256)
- 1× `ntt_top`
- 1× `inv_ntt_top`
- 1× `poly_pointwise_top`
- 1× `poly_add_sub_top`
- 1× `poly_cbd_eta2_top`
- 1× `poly_parse_inline_top`
- 1× `poly_frombytes`
- 1× `poly_compress` (d=1, d=4, d=10)
- 1× `poly_decompress` (d=4, d=10)
- 1× `poly_frommsg`

## BRAM nội bộ

| Tên | Số lượng | Dùng cho |
|-----|---------|----------|
| `s_hat[0..2]` | 3 | Decrypt: ŝ từ dk_PKE |
| `t_hat[0..2]` | 3 | Re-Encrypt: t̂ từ ek |
| `r_hat[0..2]` | 3 | Re-Encrypt: NTT(CBD(PRF(r'))) — **reuse** u_hat slots sau Decrypt xong |
| `acc` | 1 | Shared accumulator |
| `v_poly` | 1 | v (Decrypt) hoặc v' (Re-Encrypt) |
| `e2` | 1 | Noise e2 cho Re-Encrypt |
| **Tổng** | **~12× BRAM18K** | *reuse giữa 2 pha giảm xuống ~9* |

Thêm byte-BRAM cho:
- `ct_in` (1088 bytes) — input ciphertext
- `ct_prime` (1088 bytes) — re-encrypted ciphertext cho compare
- `ek_buf` (1184 bytes), `dk_buf` (1152 bytes) — hoặc stream từ external

## FSM States (high-level)

```
S_IDLE
  │ start
  ▼
S_UNPACK_DK ──── Slice dk → dk_PKE, ek, h[32], z[32]
  │
  ▼
════════════ PHASE 1: DECRYPT ════════════
  │
S_DEC_DECODE_SK ─── frombytes × 3 → ŝ[0..2]
S_DEC_DECOMPRESS_U ─ decompress_10 × 3 → u[0..2]
S_DEC_DECOMPRESS_V ─ decompress_4 → v
S_DEC_NTT_U ─────── NTT × 3 → û[0..2]
S_DEC_PW_ACC ─────── ŝ·û accumulate × 3
S_DEC_INTT ────────── INTT → w
S_DEC_SUB ──────────── v - w → diff
S_DEC_COMPRESS_MSG ── compress_1 → m' (32 bytes, save to register)
  │
  ▼
════════════ HASH DERIVATION ════════════
  │
S_HASH_G ──── SHA3-512(m' || h) → (K'[32], r'[32])
  │
  ▼
S_HASH_J ──── SHAKE-256(z || ct_in) → K_reject[32]   ← ALWAYS compute!
  │
  ▼
════════════ PHASE 2: RE-ENCRYPT ════════════
  │
S_ENC_DECODE_EK ─── frombytes(ek) × 3 → t̂, extract ρ
S_ENC_GEN_R ─────── PRF+CBD+NTT × 3 → r̂'[0..2]
S_ENC_GEN_E1 ────── PRF+CBD × 3 → e1'[0..2]
S_ENC_GEN_E2 ────── PRF+CBD → e2'
S_ENC_CALC_U ────── Â^T·r̂' + e1' (same logic as Encrypt Batch 4)
                     ⚠️ XOF index: ρ || i || j (transpose!)
S_ENC_CALC_V ────── t̂·r̂' + e2' + encode(m')
S_ENC_COMPRESS_U ── compress_10 × 3 → c1'
S_ENC_COMPRESS_V ── compress_4 → c2'
  │                  ct' = c1' || c2' (save to ct_prime BRAM)
  ▼
════════════ COMPARE & OUTPUT ════════════
  │
S_COMPARE ──── XOR-accumulate(ct_in[i] ^ ct_prime[i]) for i=0..1087
  │             reg xor_acc |= (byte_a ^ byte_b)  — NO EARLY EXIT
  │             wire match = (xor_acc == 8'd0)
  ▼
S_OUTPUT_K ──── K = match ? K' : K_reject    ← constant-time MUX
  │
  ▼
S_ZEROIZE ──── Clear m', r', K', s_hat from BRAM/registers
  │
  ▼
S_DONE
```

## Constant-Time RTL Patterns

### Compare (KHÔNG early exit)
```verilog
reg [7:0] xor_acc;
// In S_COMPARE: iterate ALL 1088 bytes
always @(posedge clk) begin
    if (state == S_COMPARE_INIT)
        xor_acc <= 8'd0;
    else if (state == S_COMPARE)
        xor_acc <= xor_acc | (ct_in_byte ^ ct_prime_byte);
end
wire match = (xor_acc == 8'd0); // Only valid AFTER all 1088 iterations
```

### Conditional Output (constant-time MUX)
```verilog
// BOTH K' and K_reject already computed
// Select using bitwise mask, not if/else
wire [7:0] mask = {8{match}};  // 0xFF or 0x00
wire [7:0] k_out = (K_prime & mask) | (K_reject & ~mask);
```

## Cycle Estimate

| Bước | Cycles |
|------|--------|
| Unpack dk | ~3,000 |
| Phase 1: Decrypt | ~11,000 |
| Hash G + Hash J | ~3,500 |
| Phase 2: Re-Encrypt | ~80,000 |
| Compare (1088 bytes) | ~1,100 |
| Output + Zeroize | ~500 |
| **Tổng** | **~99,000 cycles → ~990 µs** |

## Verification

### `tb_ml_kem_decaps.sv`

**Test 1 — Normal flow (match):**
```
1. ml_kem_keygen(seed_d, seed_z) → (pk, sk)
2. ml_kem_encaps(pk, m) → (K_enc, ct)
3. ml_kem_decaps(sk, ct) → K_dec
4. ASSERT: K_enc == K_dec
```

**Test 2 — Implicit rejection (fail):**
```
1. Tạo (pk, sk, ct) như trên
2. Tamper ct: ct[0] ^= 0xFF
3. ml_kem_decaps(sk, ct_tampered) → K_dec
4. ASSERT: K_dec != K_enc   (K_dec = SHAKE-256(z || ct_tampered))
5. ASSERT: K_dec == expected_rejection_value (from golden model)
```

**Test 3 — Timing:**
```
Đo cycle_count cho cả 2 test cases trên.
ASSERT: |cycles_match - cycles_fail| < 10   // Constant-time verification
```

---
---

# Batch 6 — AXI Integration

**Mục tiêu:** Kết nối PS (ARM) ↔ PL (FPGA) qua bus AXI

## Files cần tạo

| File | Mô tả |
|------|--------|
| `sources_1/new/ml_kem_top.v` | Top-level AXI wrapper |
| `sources_1/new/ml_kem_axi_lite_slave.v` | AXI4-Lite register interface |
| `constraints/ml_kem_kr260.xdc` | Timing + pin constraints |
| `sim_1/new/tb_ml_kem_top.sv` | AXI BFM simulation |

## Kiến trúc Top-Level

```
┌─────────────────────────────────────────────────────┐
│  PS (ARM A53, Linux/PYNQ)                           │
│                                                     │
│  crypto_kem_keypair() / encaps() / decaps()         │
│    │  AXI4-Lite (control)        AXI4-MM (data)     │
└────┼─────────────────────────────┼──────────────────┘
     │                             │
┌────┼─────────────────────────────┼──────────────────┐
│  PL│(FPGA Fabric)               │                   │
│    ▼                             ▼                   │
│  ┌────────────────┐  ┌──────────────────────┐       │
│  │ AXI4-Lite      │  │ AXI4-MM Master       │       │
│  │ Slave (regs)   │  │ (burst DDR access)   │       │
│  └───────┬────────┘  └──────────┬───────────┘       │
│          │                      │                    │
│          ▼                      ▼                    │
│  ┌───────────────────────────────────────────┐      │
│  │          ml_kem_controller FSM            │      │
│  │                                           │      │
│  │  ┌─────────────┐ ┌──────────────┐         │      │
│  │  │ml_kem_keygen│ │ml_kem_encaps │         │      │
│  │  └─────────────┘ └──────────────┘         │      │
│  │  ┌──────────────┐                         │      │
│  │  │ml_kem_decaps │                         │      │
│  │  └──────────────┘                         │      │
│  └───────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────┘
```

## AXI4-Lite Register Map

| Offset | Name | Width | R/W | Description |
|--------|------|-------|-----|-------------|
| 0x00 | CTRL | 32 | W | [0] start, [2:1] op_sel (0=KeyGen, 1=Encaps, 2=Decaps) |
| 0x04 | STATUS | 32 | R | [0] done, [1] idle, [2] error |
| 0x08 | CYCLES | 32 | R | Performance counter (cycles since start) |
| 0x10–0x2C | SEED_D | 256 | W | 32-byte seed d (KeyGen only) |
| 0x30–0x4C | SEED_Z | 256 | W | 32-byte seed z (KeyGen only) |
| 0x50 | PK_ADDR | 32 | W | DDR base address for pk (AXI-MM) |
| 0x54 | SK_ADDR | 32 | W | DDR base address for sk |
| 0x58 | CT_ADDR | 32 | W | DDR base address for ct |
| 0x5C | SS_ADDR | 32 | W | DDR base address for shared secret |
| 0x60 | M_ADDR | 32 | W | DDR base address for random m (Encaps) |

## Flow cho mỗi Operation

### KeyGen
```
CPU: Viết seed_d, seed_z vào registers
CPU: Set op_sel=0, assert start
PL:  ml_kem_keygen chạy → ghi pk, sk vào internal buffer
PL:  AXI-MM burst write pk → DDR[PK_ADDR], sk → DDR[SK_ADDR]
PL:  Assert done
CPU: Đọc STATUS.done, bốc pk/sk từ DDR
```

### Encaps
```
CPU: Viết PK_ADDR, M_ADDR
CPU: Set op_sel=1, assert start
PL:  AXI-MM burst read pk ← DDR[PK_ADDR], m ← DDR[M_ADDR]
PL:  ml_kem_encaps chạy → ghi ct, ss vào buffer
PL:  AXI-MM burst write ct → DDR[CT_ADDR], ss → DDR[SS_ADDR]
PL:  Assert done
```

### Decaps
```
CPU: Viết SK_ADDR, CT_ADDR
CPU: Set op_sel=2, assert start
PL:  AXI-MM burst read sk ← DDR[SK_ADDR], ct ← DDR[CT_ADDR]
PL:  ml_kem_decaps chạy → ghi ss vào buffer
PL:  AXI-MM burst write ss → DDR[SS_ADDR]
PL:  Assert done
```

## Timing Constraints (XDC)

```tcl
# Primary clock from PS
create_clock -period 10.000 -name clk_pl [get_pins zynq_ps/pl_clk0]

# AXI clock (same domain — no CDC needed if single clock)
set_false_path -from [get_clocks clk_pl] -to [get_clocks clk_pl]

# Max delay for AXI4-Lite paths
set_max_delay 8.0 -from [get_cells -hier -filter {NAME =~ *axi_lite*}]
```

## Verification

### RTL Simulation
- AXI BFM (Bus Functional Model) hoặc hand-written AXI master TB
- Sequence: KeyGen → Encaps → Decaps → verify K_enc == K_dec

### On-Board (PYNQ)
```python
from pynq import Overlay, allocate
ol = Overlay("ml_kem.bit")
ip = ol.ml_kem_top_0

# KeyGen
seed_d_buf = allocate(shape=(32,), dtype=np.uint8)
pk_buf = allocate(shape=(1184,), dtype=np.uint8)
sk_buf = allocate(shape=(2400,), dtype=np.uint8)
# ... write seeds, set addresses, start, wait done ...

# Encaps → Decaps → verify
```

---
---

# Tổng Kết Timeline

| Batch | Module | Est. Lines | Est. Cycles | Dependency |
|-------|--------|-----------|-------------|------------|
| 3 | `kpke_decrypt.v` | ~500 | ~11,000 | Batch 1 |
| 4a | `kpke_encrypt.v` | ~900 | ~80,000 | Batch 1,2,3 |
| 4b | `ml_kem_encaps.v` | ~300 | ~82,000 | Batch 4a |
| 5 | `ml_kem_decaps.v` | ~1200 | ~99,000 | Batch 3,4 |
| 6 | `ml_kem_top.v` + AXI | ~600 | N/A | All |

> [!TIP]
> **Gợi ý thứ tự code:**
> 1. `kpke_decrypt.v` — đơn giản nhất, test độc lập được
> 2. `poly_frommsg.v` — module phụ nhỏ, cần cho Encrypt
> 3. `kpke_encrypt.v` — phức tạp nhất, nhưng logic giống KeyGen 80%
> 4. `tb_kpke_encrypt.sv` — **Roundtrip test là milestone chính**
> 5. `ml_kem_encaps.v` — thin wrapper
> 6. `ml_kem_decaps.v` — gộp logic Decrypt+Encrypt+Security
> 7. `ml_kem_top.v` — AXI integration cuối cùng
