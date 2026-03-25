#!/usr/bin/env python3
"""
ML-KEM (Kyber-768) — IP Execution Time Benchmark (Software-Level)
================================================================

Measures ONLY the HLS IP execution time: AP_START → AP_DONE
using time.perf_counter() with tight busy-wait (no sleep).

Excluded from measurement:
  - Overlay loading time
  - pynq.allocate() buffer allocation
  - Data copy / flush / invalidate
  - Result readback

Included (unavoidable overhead):
  - AXI-Lite register write latency (AP_START)
  - AXI-Lite register read latency (polling AP_DONE)
  - Linux OS scheduling jitter

Usage: Run this script on the Kria KR260 board with PYNQ.
  $ sudo -E python3 benchmark_ip_perf.py
  or copy the cells below into a Jupyter notebook.
"""

import numpy as np
import time
import os

from pynq import Overlay, allocate

# ===========================================================
# Constants
# ===========================================================
PK_SIZE   = 1184
SK_SIZE   = 2400
CT_SIZE   = 1088
SS_SIZE   = 32
SEED_SIZE = 32

REG_CTRL = 0x00
AP_START = 0x01
AP_DONE  = 0x02
AP_IDLE  = 0x04

# KeyGen register offsets
KEYGEN_REG_SEED_D = 0x10
KEYGEN_REG_SEED_Z = 0x1C
KEYGEN_REG_PK_OUT = 0x28
KEYGEN_REG_SK_OUT = 0x34

# Encaps register offsets
ENCAPS_REG_PK_IN  = 0x10
ENCAPS_REG_RAND_M = 0x1C
ENCAPS_REG_CT_OUT = 0x28
ENCAPS_REG_SS_OUT = 0x34

# Decaps register offsets
DECAPS_REG_SK_IN  = 0x10
DECAPS_REG_CT_IN  = 0x1C
DECAPS_REG_SS_OUT = 0x28


# ===========================================================
# Helpers
# ===========================================================
def _write_pointer(ip, offset_lo, addr):
    """Write a 64-bit physical address into two 32-bit AXI-Lite registers."""
    ip.write(offset_lo, addr & 0xFFFFFFFF)
    ip.write(offset_lo + 4, (addr >> 32) & 0xFFFFFFFF)


def _bytes_to_u64_array(data: bytes) -> np.ndarray:
    """Convert raw bytes (multiple of 8) to uint64 array."""
    assert len(data) % 8 == 0
    return np.frombuffer(data, dtype=np.uint64).copy()


def _perf_start_and_wait(ip, timeout_sec=30.0):
    """Start IP and tight-poll AP_DONE. Returns execution time in seconds.

    Uses time.perf_counter() for highest precision.
    NO sleep() in the loop — pure busy-wait for minimum overhead.
    Measures ONLY: AP_START write → AP_DONE detected.
    """
    t_start = time.perf_counter()
    ip.write(REG_CTRL, AP_START)
    while True:
        ctrl = ip.read(REG_CTRL)
        if ctrl & AP_DONE:
            t_end = time.perf_counter()
            return t_end - t_start
        if time.perf_counter() - t_start > timeout_sec:
            raise TimeoutError(
                f"HLS IP did not finish within {timeout_sec}s. "
                f"CTRL=0x{ctrl:08X}"
            )


# ===========================================================
# Benchmark Configuration
# ===========================================================
N_RUNS = 10  # Number of iterations per kernel

script_dir = os.path.dirname(os.path.abspath(__file__))
BIT_DIR = os.path.join(script_dir, "..", "bitstream")


def benchmark_keygen():
    """Benchmark KeyGen IP execution time."""
    print("=" * 60)
    print("  KeyGen Benchmark")
    print("=" * 60)

    keygen_bit = os.path.join(BIT_DIR, "Keygen", "ml_kem_keygen_0.bit")
    ol = Overlay(keygen_bit)
    ip = ol.ml_kem_keygen_0

    seed_d_buf = allocate(shape=(4,), dtype=np.uint64)
    seed_z_buf = allocate(shape=(4,), dtype=np.uint64)
    pk_buf = allocate(shape=(PK_SIZE,), dtype=np.uint8)
    sk_buf = allocate(shape=(SK_SIZE,), dtype=np.uint8)

    times = []
    for run in range(N_RUNS):
        # Prepare data (NOT timed)
        seed_d_buf[:] = _bytes_to_u64_array(os.urandom(32))
        seed_z_buf[:] = _bytes_to_u64_array(os.urandom(32))
        seed_d_buf.flush()
        seed_z_buf.flush()
        _write_pointer(ip, KEYGEN_REG_SEED_D, seed_d_buf.physical_address)
        _write_pointer(ip, KEYGEN_REG_SEED_Z, seed_z_buf.physical_address)
        _write_pointer(ip, KEYGEN_REG_PK_OUT, pk_buf.physical_address)
        _write_pointer(ip, KEYGEN_REG_SK_OUT, sk_buf.physical_address)

        # ---- TIMED: AP_START → AP_DONE only ----
        dt = _perf_start_and_wait(ip)
        times.append(dt)

        # Readback (NOT timed)
        pk_buf.invalidate()
        sk_buf.invalidate()
        print(f"  Run {run+1:2d}/{N_RUNS}: {dt*1000:.4f} ms")

    seed_d_buf.freebuffer()
    seed_z_buf.freebuffer()
    pk_buf.freebuffer()
    sk_buf.freebuffer()
    ol.free()
    return times


def benchmark_encaps():
    """Benchmark Encaps IP execution time."""
    print("\n" + "=" * 60)
    print("  Encaps Benchmark")
    print("=" * 60)

    encaps_bit = os.path.join(BIT_DIR, "Encaps", "ml_kem_encaps_0.bit")
    ol = Overlay(encaps_bit)
    ip = ol.ml_kem_encaps_0

    pk_buf   = allocate(shape=(PK_SIZE,), dtype=np.uint8)
    rand_buf = allocate(shape=(SEED_SIZE,), dtype=np.uint8)
    ct_buf   = allocate(shape=(CT_SIZE,), dtype=np.uint8)
    ss_buf   = allocate(shape=(SS_SIZE,), dtype=np.uint8)

    times = []
    for run in range(N_RUNS):
        pk_buf[:] = np.frombuffer(os.urandom(PK_SIZE), dtype=np.uint8)
        rand_buf[:] = np.frombuffer(os.urandom(SEED_SIZE), dtype=np.uint8)
        pk_buf.flush()
        rand_buf.flush()
        _write_pointer(ip, ENCAPS_REG_PK_IN,  pk_buf.physical_address)
        _write_pointer(ip, ENCAPS_REG_RAND_M, rand_buf.physical_address)
        _write_pointer(ip, ENCAPS_REG_CT_OUT, ct_buf.physical_address)
        _write_pointer(ip, ENCAPS_REG_SS_OUT, ss_buf.physical_address)

        dt = _perf_start_and_wait(ip)
        times.append(dt)

        ct_buf.invalidate()
        ss_buf.invalidate()
        print(f"  Run {run+1:2d}/{N_RUNS}: {dt*1000:.4f} ms")

    pk_buf.freebuffer()
    rand_buf.freebuffer()
    ct_buf.freebuffer()
    ss_buf.freebuffer()
    ol.free()
    return times


def benchmark_decaps():
    """Benchmark Decaps IP execution time."""
    print("\n" + "=" * 60)
    print("  Decaps Benchmark")
    print("=" * 60)

    decaps_bit = os.path.join(BIT_DIR, "Decaps", "ml_kem_decaps_0.bit")
    ol = Overlay(decaps_bit)
    ip = ol.ml_kem_decaps_0

    sk_buf = allocate(shape=(SK_SIZE,), dtype=np.uint8)
    ct_buf = allocate(shape=(CT_SIZE,), dtype=np.uint8)
    ss_buf = allocate(shape=(SS_SIZE,), dtype=np.uint8)

    times = []
    for run in range(N_RUNS):
        sk_buf[:] = np.frombuffer(os.urandom(SK_SIZE), dtype=np.uint8)
        ct_buf[:] = np.frombuffer(os.urandom(CT_SIZE), dtype=np.uint8)
        sk_buf.flush()
        ct_buf.flush()
        _write_pointer(ip, DECAPS_REG_SK_IN,  sk_buf.physical_address)
        _write_pointer(ip, DECAPS_REG_CT_IN,  ct_buf.physical_address)
        _write_pointer(ip, DECAPS_REG_SS_OUT, ss_buf.physical_address)

        dt = _perf_start_and_wait(ip)
        times.append(dt)

        ss_buf.invalidate()
        print(f"  Run {run+1:2d}/{N_RUNS}: {dt*1000:.4f} ms")

    sk_buf.freebuffer()
    ct_buf.freebuffer()
    ss_buf.freebuffer()
    ol.free()
    return times


# ===========================================================
# Main
# ===========================================================
if __name__ == "__main__":
    print("ML-KEM 768 — HLS IP Execution Time Benchmark")
    print(f"  N_RUNS = {N_RUNS}")
    print(f"  Clock  = pl_clk0 @ 100 MHz")
    print(f"  Method = time.perf_counter() [AP_START → AP_DONE]")
    print()

    keygen_times = benchmark_keygen()
    encaps_times = benchmark_encaps()
    decaps_times = benchmark_decaps()

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY — IP Execution Time (Software-level)")
    print("=" * 60)
    print(f"  {'Kernel':<10} {'Avg (ms)':>10} {'Min (ms)':>10} "
          f"{'Max (ms)':>10} {'Std (ms)':>10}")
    print(f"  {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

    for name, times in [("KeyGen", keygen_times),
                        ("Encaps", encaps_times),
                        ("Decaps", decaps_times)]:
        avg = np.mean(times) * 1000
        mn  = np.min(times) * 1000
        mx  = np.max(times) * 1000
        std = np.std(times) * 1000
        print(f"  {name:<10} {avg:>10.4f} {mn:>10.4f} "
              f"{mx:>10.4f} {std:>10.4f}")

    print(f"  {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    total = (np.mean(keygen_times) + np.mean(encaps_times) +
             np.mean(decaps_times)) * 1000
    print(f"  {'TOTAL':<10} {total:>10.4f}")
    print(f"\n  N_RUNS = {N_RUNS} | Clock = pl_clk0 @ 100 MHz")
    print(f"  Measurement: time.perf_counter() [AP_START → AP_DONE]")
    print(f"  Note: Includes AXI-Lite R/W latency + OS scheduling jitter")
