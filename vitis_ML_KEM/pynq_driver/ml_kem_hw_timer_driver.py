"""
ML-KEM (Kyber-768) PYNQ Driver - HARDWARE BENCHMARK EDITION
===========================================================
Phiên bản chuyên dụng để đo lường chính xác hiệu năng lõi Silicon
bằng khối IP AXI Timer được nhúng bên trong FPGA.
"""

import numpy as np
import time
import os
import sys

try:
    from pynq import Overlay, allocate
    PYNQ_AVAILABLE = True
except ImportError:
    PYNQ_AVAILABLE = False
    print("[WARN] pynq not available. Running in simulation/offline mode.")

# ===========================================================
# Configuration
# ===========================================================
# QUAN TRỌNG: Cập nhật đúng tần số Clock mà khối Kyber và Timer đang chạy trên Vivado
CLOCK_FREQ_HZ = 96_968_727  # ~96.97 MHz (từ .hwh: pl_clk0)

PK_SIZE = 1184   
SK_SIZE = 2400   
CT_SIZE = 1088   
SS_SIZE = 32     
SEED_SIZE = 32   

REG_CTRL = 0x00
AP_START = 0x01
AP_DONE  = 0x02

def _write_pointer(ip, offset_lo, addr):
    """Write a 64-bit physical address into two 32-bit AXI-Lite registers."""
    ip.write(offset_lo, addr & 0xFFFFFFFF)
    ip.write(offset_lo + 4, (addr >> 32) & 0xFFFFFFFF)

def _bytes_to_u64_array(data: bytes) -> np.ndarray:
    assert len(data) % 8 == 0, f"Data length {len(data)} must be multiple of 8"
    return np.frombuffer(data, dtype=np.uint64).copy()

def _check_pynq():
    if not PYNQ_AVAILABLE:
        raise RuntimeError("Must run on Kria KR260 board with PYNQ.")

# ===========================================================
# Keygen Driver (Hardware Benchmark)
# ===========================================================
KEYGEN_REG_SEED_D = 0x10
KEYGEN_REG_SEED_Z = 0x1C
KEYGEN_REG_PK_OUT = 0x28
KEYGEN_REG_SK_OUT = 0x34

class MLKEMKeygenHW:
    def __init__(self, bitstream_path: str):
        _check_pynq()
        self.ol = Overlay(bitstream_path)
        self.ip = self.ol.ml_kem_keygen_0
        self.timer = self.ol.axi_timer_0

    def run(self, seed_d: bytes, seed_z: bytes):
        seed_d_buf = allocate(shape=(4,), dtype=np.uint64)
        seed_z_buf = allocate(shape=(4,), dtype=np.uint64)
        pk_buf = allocate(shape=(PK_SIZE,), dtype=np.uint8)
        sk_buf = allocate(shape=(SK_SIZE,), dtype=np.uint8)

        try:
            seed_d_buf[:] = _bytes_to_u64_array(seed_d)
            seed_z_buf[:] = _bytes_to_u64_array(seed_z)
            seed_d_buf.flush()
            seed_z_buf.flush()

            _write_pointer(self.ip, KEYGEN_REG_SEED_D, seed_d_buf.physical_address)
            _write_pointer(self.ip, KEYGEN_REG_SEED_Z, seed_z_buf.physical_address)
            _write_pointer(self.ip, KEYGEN_REG_PK_OUT, pk_buf.physical_address)
            _write_pointer(self.ip, KEYGEN_REG_SK_OUT, sk_buf.physical_address)

            # --- SETUP TIMER (count-up from 0) ---
            self.timer.write(0x04, 0x00000000)  # TLR0 = 0
            self.timer.write(0x00, 0x00000020)  # LOAD=1 → load TLR0 into counter
            self.timer.write(0x00, 0x00000080)  # LOAD=0, ENT=1 → start counting up

            # --- START IP ---
            self.ip.write(REG_CTRL, AP_START)

            # --- TIGHT POLLING ---
            while (self.ip.read(REG_CTRL) & AP_DONE) == 0:
                pass

            # --- STOP TIMER ---
            self.timer.write(0x00, 0x00000000)  # ENT=0 → halt counter

            # --- READ RESULTS ---
            cycles = self.timer.read(0x08)
            hw_time_ms = (cycles / CLOCK_FREQ_HZ) * 1000

            pk_buf.invalidate()
            sk_buf.invalidate()

            return bytes(pk_buf), bytes(sk_buf), cycles, hw_time_ms

        finally:
            seed_d_buf.freebuffer()
            seed_z_buf.freebuffer()
            pk_buf.freebuffer()
            sk_buf.freebuffer()

    def close(self):
        if hasattr(self, 'ol'): self.ol.free()

# ===========================================================
# Encaps Driver (Hardware Benchmark)
# ===========================================================
ENCAPS_REG_PK_IN  = 0x10
ENCAPS_REG_RAND_M = 0x1C
ENCAPS_REG_CT_OUT = 0x28
ENCAPS_REG_SS_OUT = 0x34

class MLKEMEncapsHW:
    def __init__(self, bitstream_path: str):
        _check_pynq()
        self.ol = Overlay(bitstream_path)
        self.ip = self.ol.ml_kem_encaps_0
        self.timer = self.ol.axi_timer_0

    def run(self, pk: bytes, randomness_m: bytes):
        pk_buf = allocate(shape=(PK_SIZE,), dtype=np.uint8)
        rand_buf = allocate(shape=(SEED_SIZE,), dtype=np.uint8)
        ct_buf = allocate(shape=(CT_SIZE,), dtype=np.uint8)
        ss_buf = allocate(shape=(SS_SIZE,), dtype=np.uint8)

        try:
            pk_buf[:] = np.frombuffer(pk, dtype=np.uint8)
            rand_buf[:] = np.frombuffer(randomness_m, dtype=np.uint8)
            pk_buf.flush()
            rand_buf.flush()

            _write_pointer(self.ip, ENCAPS_REG_PK_IN, pk_buf.physical_address)
            _write_pointer(self.ip, ENCAPS_REG_RAND_M, rand_buf.physical_address)
            _write_pointer(self.ip, ENCAPS_REG_CT_OUT, ct_buf.physical_address)
            _write_pointer(self.ip, ENCAPS_REG_SS_OUT, ss_buf.physical_address)

            # --- SETUP TIMER (count-up from 0) ---
            self.timer.write(0x04, 0x00000000)  # TLR0 = 0
            self.timer.write(0x00, 0x00000020)  # LOAD=1
            self.timer.write(0x00, 0x00000080)  # LOAD=0, ENT=1

            # --- START IP ---
            self.ip.write(REG_CTRL, AP_START)

            while (self.ip.read(REG_CTRL) & AP_DONE) == 0:
                pass

            # --- STOP TIMER ---
            self.timer.write(0x00, 0x00000000)  # ENT=0 

            cycles = self.timer.read(0x08)
            hw_time_ms = (cycles / CLOCK_FREQ_HZ) * 1000

            ct_buf.invalidate()
            ss_buf.invalidate()

            return bytes(ct_buf), bytes(ss_buf), cycles, hw_time_ms

        finally:
            pk_buf.freebuffer()
            rand_buf.freebuffer()
            ct_buf.freebuffer()
            ss_buf.freebuffer()

    def close(self):
        if hasattr(self, 'ol'): self.ol.free()

# ===========================================================
# Decaps Driver (Hardware Benchmark)
# ===========================================================
DECAPS_REG_SK_IN  = 0x10
DECAPS_REG_CT_IN  = 0x1C
DECAPS_REG_SS_OUT = 0x28

class MLKEMDecapsHW:
    def __init__(self, bitstream_path: str):
        _check_pynq()
        self.ol = Overlay(bitstream_path)
        self.ip = self.ol.ml_kem_decaps_0
        self.timer = self.ol.axi_timer_0

    def run(self, sk: bytes, ct: bytes):
        sk_buf = allocate(shape=(SK_SIZE,), dtype=np.uint8)
        ct_buf = allocate(shape=(CT_SIZE,), dtype=np.uint8)
        ss_buf = allocate(shape=(SS_SIZE,), dtype=np.uint8)

        try:
            sk_buf[:] = np.frombuffer(sk, dtype=np.uint8)
            ct_buf[:] = np.frombuffer(ct, dtype=np.uint8)
            sk_buf.flush()
            ct_buf.flush()

            _write_pointer(self.ip, DECAPS_REG_SK_IN, sk_buf.physical_address)
            _write_pointer(self.ip, DECAPS_REG_CT_IN, ct_buf.physical_address)
            _write_pointer(self.ip, DECAPS_REG_SS_OUT, ss_buf.physical_address)

            # --- SETUP TIMER (count-up from 0) ---
            self.timer.write(0x04, 0x00000000)  # TLR0 = 0
            self.timer.write(0x00, 0x00000020)  # LOAD=1
            self.timer.write(0x00, 0x00000080)  # LOAD=0, ENT=1

            # --- START IP ---
            self.ip.write(REG_CTRL, AP_START)

            while (self.ip.read(REG_CTRL) & AP_DONE) == 0:
                pass

            # --- STOP TIMER ---
            self.timer.write(0x00, 0x00000000)  # ENT=0 

            cycles = self.timer.read(0x08)
            hw_time_ms = (cycles / CLOCK_FREQ_HZ) * 1000

            ss_buf.invalidate()

            return bytes(ss_buf), cycles, hw_time_ms

        finally:
            sk_buf.freebuffer()
            ct_buf.freebuffer()
            ss_buf.freebuffer()

    def close(self):
        if hasattr(self, 'ol'): self.ol.free()


# ===========================================================
# CLI DEMO - HARDWARE BENCHMARK
# ===========================================================
if __name__ == "__main__":
    _check_pynq()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_bit_dir = os.path.join(script_dir, "..", "bitstream")
    bit_dir = sys.argv[1] if len(sys.argv) > 1 else default_bit_dir

    print(f"ML-KEM 768 - HARDWARE LEVEL BENCHMARK (AXI Timer)")
    print(f"Clock Frequency: {CLOCK_FREQ_HZ / 1_000_000} MHz")
    print(f"Bitstream dir: {bit_dir}")
    print("=" * 60)

    seed_d = os.urandom(32)
    seed_z = os.urandom(32)
    rand_m = os.urandom(32)

    # KeyGen
    print("\n[1/3] Benchmarking KeyGen...")
    kg = MLKEMKeygenHW(os.path.join(bit_dir, "Keygen", "ml_kem_keygen_0.bit"))
    pk, sk, kg_cyc, kg_ms = kg.run(seed_d, seed_z)
    print(f"  -> Hardware Clock Cycles: {kg_cyc:,}")
    print(f"  -> Hardware Exec Time:    {kg_ms:.4f} ms")
    kg.close()

    # Encaps
    print("\n[2/3] Benchmarking Encaps...")
    enc = MLKEMEncapsHW(os.path.join(bit_dir, "Encaps", "ml_kem_encaps_0.bit"))
    ct, ss_enc, enc_cyc, enc_ms = enc.run(pk, rand_m)
    print(f"  -> Hardware Clock Cycles: {enc_cyc:,}")
    print(f"  -> Hardware Exec Time:    {enc_ms:.4f} ms")
    enc.close()

    # Decaps
    print("\n[3/3] Benchmarking Decaps...")
    dec = MLKEMDecapsHW(os.path.join(bit_dir, "Decaps", "ml_kem_decaps_0.bit"))
    ss_dec, dec_cyc, dec_ms = dec.run(sk, ct)
    print(f"  -> Hardware Clock Cycles: {dec_cyc:,}")
    print(f"  -> Hardware Exec Time:    {dec_ms:.4f} ms")
    dec.close()

    # Verify
    print("\n" + "=" * 60)
    match = ss_enc == ss_dec
    print(f"Shared secrets match: {'✅ YES' if match else '❌ NO'}")
    print(f"Total Pure Hardware Time: {(kg_ms + enc_ms + dec_ms):.4f} ms")