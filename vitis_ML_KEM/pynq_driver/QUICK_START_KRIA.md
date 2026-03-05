# Quick Start — Chạy ML-KEM trên Kria KR260 (Ubuntu 22)

## 1. Cài PYNQ trên board (dùng Kria-PYNQ)

> ⚠️ **Không dùng `pip install pynq` đơn thuần.** Trên Kria cần cài qua
> Kria-PYNQ script để thiết lập device tree overlay, platform name và
> environment variables đúng cách.

```bash
git clone https://github.com/Xilinx/Kria-PYNQ.git
cd Kria-PYNQ
sudo bash install.sh -b KR260
```

Quá trình này mất ~25 phút. Script sẽ tự động:
- Cài PYNQ 3.0.1 vào virtual env `/usr/local/share/pynq-venv`
- Tạo device tree overlay (`pynq.dtbo`) để Linux kernel nhận FPGA
- Ghi platform name vào `/etc/xocl.txt`
- Tạo `/etc/profile.d/pynq_venv.sh` (chứa `XILINX_XRT=/usr`, PATH, v.v.)

## 2. Kiểm tra PYNQ đã hoạt động

Sau khi cài xong, **reboot** hoặc source environment:

```bash
# Cách 1: Reboot (khuyến khích)
sudo reboot

# Cách 2: Source thủ công (không cần reboot)
source /etc/profile.d/pynq_venv.sh
```

Kiểm tra PYNQ nhận device:

```bash
sudo python3 -c "from pynq import Device; print(Device.devices)"
```

Nếu thấy danh sách device (không rỗng) → sẵn sàng chạy.

## 3. Clone repo

```bash
git clone <your-repo-url> DACN
cd DACN
```

## 4. Chạy demo

```bash
# source env trước (nếu chưa reboot sau khi cài Kria-PYNQ)
source /etc/profile.d/pynq_venv.sh

# Chạy với sudo -E để giữ environment variables
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

## Troubleshooting

### Lỗi "No Devices Found"

1. **Kiểm tra Kria-PYNQ đã cài đúng chưa:**
   ```bash
   cat /etc/xocl.txt          # Phải hiện "KR260"
   ls /etc/profile.d/pynq_venv.sh  # Phải tồn tại
   ```

2. **Source environment:**
   ```bash
   source /etc/profile.d/pynq_venv.sh
   ```

3. **Kiểm tra device tree overlay:**
   ```bash
   ls /sys/class/fpga_manager/
   # Phải thấy fpga0/ hoặc tương tự
   ```

4. **Nếu vẫn lỗi, cài lại Kria-PYNQ:**
   ```bash
   cd Kria-PYNQ
   sudo bash install.sh -b KR260
   sudo reboot
   ```

## Lưu ý

- **`sudo -E` là bắt buộc** — PYNQ cần quyền root để program FPGA, `-E` giữ env vars
- **`source /etc/profile.d/pynq_venv.sh`** phải chạy trước (hoặc reboot sau cài)
- Mỗi bước (keygen/encaps/decaps) sẽ **reload FPGA** vì dùng bitstream riêng
- Board cần kết nối mạng để clone repo
