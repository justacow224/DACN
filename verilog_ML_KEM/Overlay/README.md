# ML-KEM-768 RTL Overlay - Kria KR260 Deployment

PYNQ driver and validation harness for the unified `ml_kem_top` RTL accelerator.
Target platform: AMD/Xilinx Kria KR260 (Ubuntu + PYNQ image).

## Files

| File | Purpose |
|---|---|
| `ml_kem_driver.py` | Core `MLKem768` driver. AXI-Lite control + CMA buffers for KeyGen, Encaps, Decaps. |
| `ml_kem_kat_test.py` | End-to-end regression using NIST KAT vectors on hardware. |
| `ml_kem_bench.py` | Latency and throughput benchmark for each operation and full KEM. |
| `ml_kem_driver.ipynb` | Interactive notebook for driver smoke flow. |
| `ml_kem_kat_test.ipynb` | Interactive notebook for KAT regression. |
| `ml_kem_bench.ipynb` | Interactive notebook for latency/throughput benchmarking. |

## Notebook Usage

Start Jupyter on KR260:

```bash
jupyter notebook
```

Suggested order:

1. `ml_kem_driver.ipynb` - run all cells, verify smoke test pass.
2. `ml_kem_kat_test.ipynb` - run with `n_vectors=1`, then increase to `100`.
3. `ml_kem_bench.ipynb` - run with `n=10`, then increase to `100+`.

`.py` scripts remain the source-of-truth for CLI workflows; notebooks are interactive equivalents.

## Deployment Checklist

### 1. Build Artifacts (Vivado machine)

After bitstream generation:

```text
D:\HCMUT\Year_4\252\CA\Vivado\verilog_ML_KEM\verilog_ML_KEM.runs\impl_1\
    ml_kem_bd_wrapper.bit

D:\HCMUT\Year_4\252\CA\Vivado\verilog_ML_KEM\verilog_ML_KEM.gen\sources_1\bd\ml_kem_bd\hw_handoff\
    ml_kem_bd.hwh
```

### 2. Rename and Transfer to KR260

PYNQ matches `.bit` and `.hwh` by basename:

```bash
copy ml_kem_bd_wrapper.bit  ml_kem.bit
copy ml_kem_bd.hwh          ml_kem.hwh

scp ml_kem.bit ml_kem.hwh \
    verilog_ML_KEM/Overlay/ml_kem_driver.py \
    verilog_ML_KEM/Overlay/ml_kem_kat_test.py \
    verilog_ML_KEM/Overlay/ml_kem_bench.py \
    verilog_ML_KEM/Overlay/ml_kem_driver.ipynb \
    verilog_ML_KEM/Overlay/ml_kem_kat_test.ipynb \
    verilog_ML_KEM/Overlay/ml_kem_bench.ipynb \
    verilog_ML_KEM/sim_1/new/KAT_768.txt \
    ubuntu@<KR260_IP>:~/ml_kem/
```

### 3. On KR260

```bash
ssh ubuntu@<KR260_IP>
cd ~/ml_kem
pip3 show pynq
pip3 show numpy
```

Install if missing:

```bash
sudo pip3 install pynq numpy
```

### 4. CLI Smoke / Regression / Bench

```bash
sudo python3 ml_kem_driver.py
sudo python3 ml_kem_kat_test.py 100
sudo python3 ml_kem_bench.py 500
```

## Register Map (Reference)

Base address in block design (example): `0xA000_0000`.

| Offset | Name | Access | Meaning |
|---|---|---|---|
| `0x00` | `CTRL` | W | `[0]=start`, `[2:1]=op_sel` (`00` KG, `01` Enc, `10` Dec) |
| `0x04` | `STATUS` | R | `[0]=done`, `[1]=idle`, `[2]=error` |
| `0x08` | `CYCLES` | R | 32-bit cycle counter (reset each operation) |
| `0x10`-`0x2C` | `SEED_D[0..7]` | W | 256-bit `d` as 8 little-endian 32-bit words |
| `0x30`-`0x4C` | `SEED_Z[0..7]` | W | 256-bit `z` as 8 little-endian 32-bit words |
| `0x50` | `PK_ADDR` | W | DDR physical base for `pk` (1184 B) |
| `0x54` | `SK_ADDR` | W | DDR physical base for `sk` (2400 B) |
| `0x58` | `CT_ADDR` | W | DDR physical base for `ct` (1088 B) |
| `0x5C` | `SS_ADDR` | W | DDR physical base for `ss` (32 B) |
| `0x60` | `M_ADDR` | W | DDR physical base for `m` (32 B) |

DDR pointers must be in `0x0000_0000`-`0x7FFF_FFFF` (HPC0_DDR_LOW mapping).
PYNQ `allocate()` provides contiguous CMA buffers in this range.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `.hwh` not found when loading overlay | `.bit` / `.hwh` basename mismatch | Rename both to the same basename |
| `IP 'ml_kem_top_0' not found` | Different BD instance name | Check `overlay.ip_dict.keys()` and pass `ip_name=` |
| `IP not idle before new op` | Previous operation stalled | Reload bitstream (`Overlay.download()` or recreate overlay) |
| Poll loop timeout | AXI-MM path to DDR incorrect | Recheck PS-HPC0 enable and Address Editor mapping |
| `/dev/mem` permission denied | No root access | Use `sudo python3 ...` |
| KAT mismatch from first vector | Bitstream/RTL mismatch | Regenerate bitstream from current sources |

## Cycle Budget (Reference at 100 MHz)

| Operation | Hardware cycles (simulation reference) | Hardware latency |
|---|---:|---:|
| KeyGen | ~40k | ~400 us |
| Encaps | ~57k | ~570 us |
| Decaps | ~84k | ~840 us |
| Full KEM | ~181k | ~1.8 ms |

Real wall latency is higher due to software overhead (register access, polling, cache operations).
