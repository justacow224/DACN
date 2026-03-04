# ML-KEM PYNQ Driver

PYNQ overlay driver cho 3 HLS accelerator IPs trên Kria KR260.

## Cấu trúc

```
pynq_driver/
├── ml_kem_driver.py   ← Driver chính (3 class + CLI demo)
└── README.md          ← File này
```

## Yêu cầu

- Kria KR260 board chạy PYNQ image
- Python 3.8+ với `pynq` và `numpy`

## Deploy lên board

1. Copy cặp `.bit` + `.hwh` lên board:
```bash
scp ../bitstream/Keygen/ml_kem_keygen_0.{bit,hwh} xilinx@<BOARD_IP>:~/
scp ../bitstream/Encaps/ml_kem_encaps_0.{bit,hwh} xilinx@<BOARD_IP>:~/
scp ../bitstream/Decaps/ml_kem_decaps_0.{bit,hwh} xilinx@<BOARD_IP>:~/
scp ml_kem_driver.py xilinx@<BOARD_IP>:~/
```

2. SSH vào board và chạy demo:
```bash
ssh xilinx@<BOARD_IP>
sudo python3 ml_kem_driver.py /path/to/bitstream/dir
```

## API

```python
from ml_kem_driver import MLKEMAccelerator
import os

accel = MLKEMAccelerator("/path/to/bitstream")

# Full flow
result = accel.full_flow(
    seed_d=os.urandom(32),
    seed_z=os.urandom(32),
    randomness_m=os.urandom(32)
)
print(f"Match: {result['match']}")

# Hoặc gọi riêng từng bước
pk, sk = accel.keygen(seed_d, seed_z)
ct, ss = accel.encaps(pk, rand_m)
ss2    = accel.decaps(sk, ct)
```

## Register Map (từ .hwh)

### Chung (offset 0x00–0x0C)

| Offset | Register | Mô tả |
|--------|----------|-------|
| 0x00 | CTRL | AP_START/DONE/IDLE/READY |
| 0x04 | GIER | Global Interrupt Enable |
| 0x08 | IER | IP Interrupt Enable |
| 0x0C | ISR | IP Interrupt Status |

### KeyGen (ml_kem_keygen_0)

| Offset | Register | Type |
|--------|----------|------|
| 0x10 | seed_d ptr | write-only, 64-bit |
| 0x1C | seed_z ptr | write-only, 64-bit |
| 0x28 | pk_out ptr | write-only, 64-bit |
| 0x34 | sk_out ptr | write-only, 64-bit |

### Encaps (ml_kem_encaps_0)

| Offset | Register | Type |
|--------|----------|------|
| 0x10 | pk_in ptr | write-only, 64-bit |
| 0x1C | randomness_m ptr | write-only, 64-bit |
| 0x28 | ct_out ptr | write-only, 64-bit |
| 0x34 | ss_out ptr | write-only, 64-bit |

### Decaps (ml_kem_decaps_0)

| Offset | Register | Type |
|--------|----------|------|
| 0x10 | sk_in ptr | write-only, 64-bit |
| 0x1C | ct_in ptr | write-only, 64-bit |
| 0x28 | ss_out ptr | write-only, 64-bit |
