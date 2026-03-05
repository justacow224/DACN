# Quick Start — Chạy ML-KEM trên Kria KR260 (Ubuntu 22)

## 1. Cài PYNQ trên board

```bash
sudo apt update && sudo apt install -y python3-pip libcma-dev

# Cách 1: pip (nhanh)
sudo pip3 install pynq

# Cách 2: Kria-PYNQ (nếu cách 1 fail)
git clone https://github.com/Xilinx/Kria-PYNQ.git
cd Kria-PYNQ && sudo bash install.sh
```

## 2. Clone repo

```bash
git clone <your-repo-url> DACN
cd DACN
```

## 3. Source XRT environment (bắt buộc)

```bash
source /opt/xilinx/xrt/setup.sh
```

> Nếu file này không tồn tại, cài XRT: `sudo apt install -y xrt`

## 4. Chạy demo

```bash
# Phải dùng sudo -E (PYNQ cần quyền root, -E giữ XRT env vars)
sudo -E python3 vitis_ML_KEM/pynq_driver/ml_kem_driver.py vitis_ML_KEM/bitstream
```

Output mong đợi:
```
ML-KEM 768 FPGA Accelerator Demo
==================================================

[1/3] KeyGen...
  pk: 1184 bytes, sk: 2400 bytes
  Time: xxx ms

[2/3] Encaps...
  ct: 1088 bytes, ss: <hex>
  Time: xxx ms

[3/3] Decaps...
  ss: <hex>
  Time: xxx ms

==================================================
Shared secrets match: ✅ YES
```

## 5. Dùng trong code Python

```python
from ml_kem_driver import MLKEMAccelerator
import os

accel = MLKEMAccelerator("vitis_ML_KEM/bitstream")
result = accel.full_flow(
    seed_d=os.urandom(32),
    seed_z=os.urandom(32),
    randomness_m=os.urandom(32)
)
print(f"Match: {result['match']}")
```

## Lưu ý

- **`sudo -E` là bắt buộc** — PYNQ truy cập `/dev/xdevcfg` hoặc `/sys/class/fpga_manager`, `-E` giữ XRT env
- **`source /opt/xilinx/xrt/setup.sh`** phải chạy trước — nếu thiếu sẽ gặp lỗi "No Devices Found"
- Mỗi bước (keygen/encaps/decaps) sẽ **reload FPGA** vì dùng bitstream riêng
- Board cần kết nối mạng để clone repo
