# ML-KEM KeyGen Automation Scripts

Thư mục này chứa các script Tcl để tự động hóa quy trình chạy trên Vivado (Simulation, Synthesis, Implementation). Hệ thống đã được nâng cấp để **tự động cách ly dữ liệu rác** và **chống treo (hang prevention)**.

---

## 1. Quick Guide: Khi nào dùng script nào?

| Script | Cấp độ | Khi nào cần chạy? | Mục tiêu |
| :--- | :--- | :--- | :--- |
| `sim_direct.tcl` | **Debug** | Vừa sửa logic Verilog xong. | Check tính đúng đắn (Functional) nhanh nhất. |
| `sim_wrapper.tcl` | **Debug** | Check giao tiếp IO/Byte-level. | Đảm bảo Wrapper không làm sai lệ data. |
| `keygen_full_synth_metrics.tcl` | **Iteration** | Muốn check tài nguyên (Area). | Ước tính LUT/FF/BRAM và Timing sơ bộ. |
| `keygen_full_flow.tcl` | **Final Gate** | Trước khi Commit/Push/Chốt Phase. | Pass cả Sim + Synth + Route timing. |

---

## 2. Quản lý File Output (Isolaton)

Tất cả các script hiện tại đều tự động tạo một thư mục con theo thời gian bên trong `verilog_ML_KEM/scripts/keygen_metrics/` (ví dụ: `synth_20260416_0200/`).
- Toàn bộ file log (`vivado.log`, `simulate.log`), journal (`.jou`), và report (`.rpt`) sẽ được gom gọn vào thư mục này.
- Thư mục gốc dự án sẽ sạch sẽ, không còn file rác của Vivado.

---

## 3. Cách chạy (Commands)

Thay thế `<xpr_path>` bằng đường dẫn thực tế đến file project `.xpr`.

### Chạy Simulation nhanh (Direct/Wrapper)
**CMD:**
```cmd
"C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/sim_direct.tcl -tclargs <xpr_path>
"C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/sim_wrapper.tcl -tclargs <xpr_path>
```

### Chạy Synthesis Metrics (Iteration)
**CMD:**
```cmd
"C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/keygen_full_synth_metrics.tcl -tclargs <xpr_path>
```

### Chạy Toàn bộ quy trình (Final Checkpoint)
**CMD:**
```cmd
cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/keygen_full_flow.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr 8
```

---

## 4. Chống treo & Xử lý lỗi
- **Hang Prevention:** Scripts sẽ tự động đóng các session cũ (`close_sim -force`) và reset simulation state nếu phát hiện xung đột.
- **File Lock:** Nếu vẫn gặp lỗi "process cannot access file", hãy đảm bảo bạn đã đóng GUI Vivado hoặc các ứng dụng đang mở file log trong thư mục metrics tương ứng.
