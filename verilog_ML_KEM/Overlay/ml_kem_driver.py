"""
ML-KEM-768 RTL accelerator driver for Kria KR260 (PYNQ).

Wraps the unified `ml_kem_top` IP (AXI-Lite register map + AXI-MM master that
DMAs directly to DDR via HPC0_FPD). Handles all three FIPS 203 operations
through a single register map — op_sel in CTRL picks which one to run.

Register map (from ml_kem_axi_lite_slave.v):
    0x00  CTRL     W   [0]=start (pulse), [2:1]=op_sel (0:KG, 1:Enc, 2:Dec)
    0x04  STATUS   R   [0]=done, [1]=idle, [2]=error
    0x08  CYCLES   R   32-bit cycle counter (reset each op)
    0x10  SEED_D   W   8 × 32-bit little-endian words = 256-bit d
    0x30  SEED_Z   W   8 × 32-bit little-endian words = 256-bit z
    0x50  PK_ADDR  W   physical DDR base for pk (1184 B)
    0x54  SK_ADDR  W   physical DDR base for sk (2400 B)
    0x58  CT_ADDR  W   physical DDR base for ct (1088 B)
    0x5C  SS_ADDR  W   physical DDR base for ss (32 B)
    0x60  M_ADDR   W   physical DDR base for m  (32 B)

DDR buffers must land in HPC0_DDR_LOW (0x0000_0000 – 0x7FFF_FFFF per the
Address Editor in the BD). PYNQ `allocate()` returns cma-backed arrays in
that range automatically.

Usage:
    from ml_kem_driver import MLKem768
    with MLKem768('/home/ubuntu/ml_kem.bit') as kem:
        pk, sk, cyc = kem.keygen(seed_d, seed_z)
        ct, ss, cyc = kem.encaps(pk, m)
        ss,     cyc = kem.decaps(sk, ct)
"""

import os
import struct
import time

import numpy as np
from pynq import Overlay, allocate


# ---- Register offsets ----------------------------------------------------
REG_CTRL         = 0x00
REG_STATUS       = 0x04
REG_CYCLES       = 0x08
REG_SEED_D_BASE  = 0x10
REG_SEED_Z_BASE  = 0x30
REG_PK_ADDR      = 0x50
REG_SK_ADDR      = 0x54
REG_CT_ADDR      = 0x58
REG_SS_ADDR      = 0x5C
REG_M_ADDR       = 0x60
# R-new-D K3 (Method E batched API): outer-loop count for KeyGen.
REG_BATCH_COUNT  = 0x64

# ---- CTRL encoding (start=bit0, op_sel=bits[2:1]) -----------------------
CTRL_START_KEYGEN = 0b001  # op_sel=00, start=1
CTRL_START_ENCAPS = 0b011  # op_sel=01, start=1
CTRL_START_DECAPS = 0b101  # op_sel=10, start=1

# ---- STATUS bits ---------------------------------------------------------
STATUS_DONE  = 0x1
STATUS_IDLE  = 0x2
STATUS_ERROR = 0x4

# ---- ML-KEM-768 buffer sizes (FIPS 203) ---------------------------------
PK_SIZE = 1184
SK_SIZE = 2400
CT_SIZE = 1088
SS_SIZE = 32
M_SIZE  = 32

# Clock period — used for cycle-to-time conversion in prints.
# R-new-D signoff at 100 MHz (the project baseline). 125 MHz variant exists at
# verilog_ML_KEM/bitstream/ml_kem_bd_125mhz.{bit,hwh}; if deploying that,
# update this constant to 124_998_749.
PL_CLK_HZ = 100_000_000


class MLKemError(RuntimeError):
    """Raised when the accelerator reports an error or times out."""


class MLKem768:
    """Driver for the unified ML-KEM-768 accelerator.

    Buffer pointers are programmed once at open-time; per-op only CTRL +
    seeds (for KeyGen) or the input buffers (for Encaps/Decaps) need to
    change. This matches the hardware register map, which latches addr
    pointers until the next write.
    """

    # Per-op timeouts. KeyGen is the longest (matrix-A expansion + NTT chain).
    DEFAULT_TIMEOUTS_S = {
        'keygen': 2.0,
        'encaps': 2.0,
        'decaps': 3.0,
    }

    def __init__(self, bitfile, ip_name='ml_kem_top_0'):
        """Load overlay and allocate buffers.

        Args:
            bitfile: path to the .bit file. The matching .hwh must be in the
                     same directory with the same basename.
            ip_name: hierarchical name of the IP in the block design. Matches
                     the BD instance (default `ml_kem_top_0`).
        """
        self.overlay = Overlay(bitfile)
        if not hasattr(self.overlay, ip_name):
            raise MLKemError(
                f"IP '{ip_name}' not found in overlay. "
                f"Available: {list(self.overlay.ip_dict.keys())}"
            )
        self.ip = getattr(self.overlay, ip_name)

        # CMA-backed buffers (physical address reachable by the IP's m_axi
        # via HPC0_DDR_LOW mapping).
        self.pk = allocate((PK_SIZE,), dtype=np.uint8)
        self.sk = allocate((SK_SIZE,), dtype=np.uint8)
        self.ct = allocate((CT_SIZE,), dtype=np.uint8)
        self.ss = allocate((SS_SIZE,), dtype=np.uint8)
        self.m  = allocate((M_SIZE,),  dtype=np.uint8)

        # Program pointers once. IP latches them until next write, so we
        # don't need to reprogram per-op.
        self.ip.write(REG_PK_ADDR, self.pk.physical_address)
        self.ip.write(REG_SK_ADDR, self.sk.physical_address)
        self.ip.write(REG_CT_ADDR, self.ct.physical_address)
        self.ip.write(REG_SS_ADDR, self.ss.physical_address)
        self.ip.write(REG_M_ADDR,  self.m.physical_address)

    # ----- Low-level helpers ----------------------------------------------

    def _write_seed(self, base_offset, seed_bytes):
        """Write a 32-byte seed as 8 × 32-bit little-endian words."""
        if len(seed_bytes) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed_bytes)}")
        for i in range(8):
            word = struct.unpack_from('<I', seed_bytes, i * 4)[0]
            self.ip.write(base_offset + i * 4, word)

    def _wait_done(self, timeout_s):
        """Poll STATUS until done or timeout. Returns cycle count."""
        deadline = time.monotonic() + timeout_s
        while True:
            status = self.ip.read(REG_STATUS)
            if status & STATUS_ERROR:
                raise MLKemError(
                    f"IP signaled error, STATUS=0x{status:x}"
                )
            if status & STATUS_DONE:
                return self.ip.read(REG_CYCLES)
            if time.monotonic() > deadline:
                raise MLKemError(
                    f"Operation timeout after {timeout_s}s, "
                    f"STATUS=0x{status:x}"
                )

    def _ensure_idle(self):
        status = self.ip.read(REG_STATUS)
        if not (status & STATUS_IDLE):
            raise MLKemError(
                f"IP not idle before new op, STATUS=0x{status:x}"
            )

    # ----- Public API -----------------------------------------------------

    def keygen(self, seed_d, seed_z, timeout_s=None):
        """KeyGen: (d, z) → (pk, sk).

        Args:
            seed_d, seed_z: 32 bytes each.
            timeout_s: override default 2.0 s timeout.

        Returns:
            (pk_bytes, sk_bytes, cycles).
        """
        self._ensure_idle()
        self._write_seed(REG_SEED_D_BASE, seed_d)
        self._write_seed(REG_SEED_Z_BASE, seed_z)

        self.ip.write(REG_CTRL, CTRL_START_KEYGEN)
        cycles = self._wait_done(
            timeout_s if timeout_s is not None
            else self.DEFAULT_TIMEOUTS_S['keygen']
        )

        self.pk.invalidate()
        self.sk.invalidate()
        return bytes(self.pk), bytes(self.sk), cycles

    def batch_keygen(self, seed_d, seed_z, n, timeout_s=None):
        """R-new-D K3 (Method E batched API): N keygens with one trigger.

        Phase A: same seeds for all N iterations (RTL outer loop reuses
        cfg_seed_d/cfg_seed_z). Useful for measuring throughput
        amortization but NOT cryptographically meaningful — all returned
        keypairs are identical. Phase B (future) would source per-
        iteration seeds from a DDR array.

        Args:
            seed_d, seed_z: 32 bytes each. Used for all N iterations.
            n: batch count (1..65535).
            timeout_s: scales linearly with n if not specified.

        Returns:
            (pks_concat: bytes[n*1184], sks_concat: bytes[n*2400], cycles).
            Caller splits with pks_concat[i*PK_SIZE:(i+1)*PK_SIZE].
        """
        if n < 1 or n > 65535:
            raise ValueError(f"n must be 1..65535, got {n}")
        if len(seed_d) != 32 or len(seed_z) != 32:
            raise ValueError("Seeds must be 32 bytes each")
        self._ensure_idle()

        # Allocate combined output buffers.
        pk_arr = allocate((n * PK_SIZE,), dtype=np.uint8)
        sk_arr = allocate((n * SK_SIZE,), dtype=np.uint8)

        try:
            # Reprogram pk/sk pointers for batch buffers. RTL adds the
            # per-iteration offset internally (+i*1184 / +i*2400).
            self.ip.write(REG_PK_ADDR, pk_arr.physical_address)
            self.ip.write(REG_SK_ADDR, sk_arr.physical_address)
            self.ip.write(REG_BATCH_COUNT, n)
            self._write_seed(REG_SEED_D_BASE, seed_d)
            self._write_seed(REG_SEED_Z_BASE, seed_z)

            self.ip.write(REG_CTRL, CTRL_START_KEYGEN)
            cycles = self._wait_done(
                timeout_s if timeout_s is not None
                else self.DEFAULT_TIMEOUTS_S['keygen'] * n
            )

            pk_arr.invalidate()
            sk_arr.invalidate()
            pks_out = bytes(pk_arr)
            sks_out = bytes(sk_arr)

            return pks_out, sks_out, cycles
        finally:
            # Restore single-op state so a follow-up .keygen() Just Works.
            self.ip.write(REG_PK_ADDR, self.pk.physical_address)
            self.ip.write(REG_SK_ADDR, self.sk.physical_address)
            self.ip.write(REG_BATCH_COUNT, 1)
            try:
                pk_arr.freebuffer()
                sk_arr.freebuffer()
            except Exception:
                pass

    def encaps(self, pk_bytes, m_bytes, timeout_s=None):
        """Encaps: (pk, m) → (ct, ss).

        Args:
            pk_bytes: 1184-byte public key.
            m_bytes: 32-byte randomness.
        """
        if len(pk_bytes) != PK_SIZE:
            raise ValueError(f"pk must be {PK_SIZE} bytes")
        if len(m_bytes) != M_SIZE:
            raise ValueError(f"m must be {M_SIZE} bytes")

        self._ensure_idle()
        self.pk[:] = np.frombuffer(pk_bytes, dtype=np.uint8)
        self.m[:]  = np.frombuffer(m_bytes,  dtype=np.uint8)
        self.pk.flush()
        self.m.flush()

        self.ip.write(REG_CTRL, CTRL_START_ENCAPS)
        cycles = self._wait_done(
            timeout_s if timeout_s is not None
            else self.DEFAULT_TIMEOUTS_S['encaps']
        )

        self.ct.invalidate()
        self.ss.invalidate()
        return bytes(self.ct), bytes(self.ss), cycles

    def decaps(self, sk_bytes, ct_bytes, timeout_s=None):
        """Decaps: (sk, ct) → ss. Includes implicit rejection path."""
        if len(sk_bytes) != SK_SIZE:
            raise ValueError(f"sk must be {SK_SIZE} bytes")
        if len(ct_bytes) != CT_SIZE:
            raise ValueError(f"ct must be {CT_SIZE} bytes")

        self._ensure_idle()
        self.sk[:] = np.frombuffer(sk_bytes, dtype=np.uint8)
        self.ct[:] = np.frombuffer(ct_bytes, dtype=np.uint8)
        self.sk.flush()
        self.ct.flush()

        self.ip.write(REG_CTRL, CTRL_START_DECAPS)
        cycles = self._wait_done(
            timeout_s if timeout_s is not None
            else self.DEFAULT_TIMEOUTS_S['decaps']
        )

        self.ss.invalidate()
        return bytes(self.ss), cycles

    # ----- Lifecycle ------------------------------------------------------

    def close(self):
        for buf in (self.pk, self.sk, self.ct, self.ss, self.m):
            try:
                buf.freebuffer()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def cycles_to_us(cycles, clk_hz=PL_CLK_HZ):
    """Helper for pretty-printing latency numbers."""
    return cycles / clk_hz * 1e6


# ====================================================================
# C-bypass fast driver (Method C in perf-optimization-log).
# Replaces the Python `while` polling loop with a compiled C function
# that reads the same mmap'd register region in a tight loop. Saves
# ~1-5 µs per poll (Python wrapper overhead) → tens of µs to ~ms
# per op depending on latency.
#
# Build on board:
#   cd /root/jupyter_notebooks/verilog_ML_KEM/Overlay && make
#
# Usage:
#   from ml_kem_driver import MLKem768Fast
#   with MLKem768Fast(bitfile) as kem: ...
# ====================================================================

import ctypes


_FAST_LIB = None
_FAST_LIB_LOAD_ERR = None


def _load_fast_lib():
    """Lazy-load libmlkemfast.so. Errors are deferred so importing the
    module never fails; the user sees a clear error only if they try to
    instantiate MLKem768Fast / MLKem768FullC without having built the .so."""
    global _FAST_LIB, _FAST_LIB_LOAD_ERR
    if _FAST_LIB is not None or _FAST_LIB_LOAD_ERR is not None:
        return
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, 'libmlkemfast.so'),
        '/root/jupyter_notebooks/verilog_ML_KEM/Overlay/libmlkemfast.so',
        './libmlkemfast.so',
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                lib = ctypes.CDLL(p)
                u32p = ctypes.POINTER(ctypes.c_uint32)
                u8p  = ctypes.POINTER(ctypes.c_uint8)
                lib.mlkem_wait_done.restype = ctypes.c_int64
                lib.mlkem_wait_done.argtypes = [u32p, ctypes.c_uint32]
                # Method C-full per-op entrypoints
                lib.mlkem_keygen_run.restype = ctypes.c_int64
                lib.mlkem_keygen_run.argtypes = [u32p, u8p, u8p, ctypes.c_uint32]
                lib.mlkem_encaps_run.restype = ctypes.c_int64
                lib.mlkem_encaps_run.argtypes = [u32p, ctypes.c_uint32]
                lib.mlkem_decaps_run.restype = ctypes.c_int64
                lib.mlkem_decaps_run.argtypes = [u32p, ctypes.c_uint32]
                _FAST_LIB = lib
                return
            except (OSError, AttributeError) as e:
                _FAST_LIB_LOAD_ERR = f"failed to load {p}: {e}"
                return
    _FAST_LIB_LOAD_ERR = (
        "libmlkemfast.so not found. Build it on the board with "
        "`cd /root/jupyter_notebooks/verilog_ML_KEM/Overlay && make`."
    )


class MLKem768Fast(MLKem768):
    """Drop-in subclass that uses a C busy-poll for `_wait_done`.

    Identical API to `MLKem768`. Only the polling loop is replaced —
    register writes, cache flush/invalidate, and PYNQ buffer mgmt are
    unchanged. Use this for latency-sensitive workloads or for the
    A-vs-C software-stack comparison benchmark.
    """

    def __init__(self, bitfile, ip_name='ml_kem_top_0'):
        super().__init__(bitfile, ip_name=ip_name)
        _load_fast_lib()
        if _FAST_LIB is None:
            raise MLKemError(_FAST_LIB_LOAD_ERR)
        self._fast_lib = _FAST_LIB
        # Raw pointer to the IP's mmap'd register region. PYNQ exposes
        # the region as a numpy uint32 array; we hand its base address
        # to C. The C side only reads STATUS (word 1) and CYCLES (word 2),
        # so any AXI-Lite alignment guarantees the kernel gives us are
        # sufficient.
        self._reg_ptr = self.ip.mmio.array.ctypes.data_as(
            ctypes.POINTER(ctypes.c_uint32)
        )

    def _wait_done(self, timeout_s):
        timeout_us = int(timeout_s * 1_000_000)
        result = self._fast_lib.mlkem_wait_done(self._reg_ptr, timeout_us)
        if result == -1:
            status = self.ip.read(REG_STATUS)
            raise MLKemError(f"IP signaled error, STATUS=0x{status:x}")
        if result == -2:
            status = self.ip.read(REG_STATUS)
            raise MLKemError(
                f"Operation timeout after {timeout_s}s, "
                f"STATUS=0x{status:x}"
            )
        return result & 0xFFFFFFFF


# ====================================================================
# Method C-full driver — entire per-op flow in C (Level 1).
#
# What's in C:    register writes (seeds + start), polling, cycles read.
# What's in Py:   buffer copy + cache flush()/invalidate() (still PYNQ).
#
# Theoretical ceiling: ~−25-45% wall vs Method A (frees up the Python
# overhead of 17 mmio writes + last-poll detect + cycles read). Cache
# ops + buffer copy still cost ~100-200 µs and dominate the residual.
# Level 2 (cache via aarch64 DC instructions) would be a future step.
# ====================================================================
class MLKem768FullC(MLKem768Fast):
    """Per-op execution path is one C call. Cache mgmt stays in Python."""

    def keygen(self, seed_d, seed_z, timeout_s=None):
        if len(seed_d) != 32 or len(seed_z) != 32:
            raise ValueError("Seeds must be 32 bytes each")
        self._ensure_idle()

        timeout_us = int(
            (timeout_s if timeout_s is not None
             else self.DEFAULT_TIMEOUTS_S['keygen']) * 1_000_000
        )

        # 32-byte ctypes views of the user-provided seed buffers.
        d_buf = (ctypes.c_uint8 * 32).from_buffer_copy(seed_d)
        z_buf = (ctypes.c_uint8 * 32).from_buffer_copy(seed_z)

        cycles = self._fast_lib.mlkem_keygen_run(
            self._reg_ptr,
            ctypes.cast(d_buf, ctypes.POINTER(ctypes.c_uint8)),
            ctypes.cast(z_buf, ctypes.POINTER(ctypes.c_uint8)),
            timeout_us,
        )
        self._raise_on_run_error(cycles, timeout_s, 'keygen')

        self.pk.invalidate()
        self.sk.invalidate()
        return bytes(self.pk), bytes(self.sk), cycles & 0xFFFFFFFF

    def encaps(self, pk_bytes, m_bytes, timeout_s=None):
        if len(pk_bytes) != PK_SIZE:
            raise ValueError(f"pk must be {PK_SIZE} bytes")
        if len(m_bytes) != M_SIZE:
            raise ValueError(f"m must be {M_SIZE} bytes")
        self._ensure_idle()

        self.pk[:] = np.frombuffer(pk_bytes, dtype=np.uint8)
        self.m[:]  = np.frombuffer(m_bytes,  dtype=np.uint8)
        self.pk.flush()
        self.m.flush()

        timeout_us = int(
            (timeout_s if timeout_s is not None
             else self.DEFAULT_TIMEOUTS_S['encaps']) * 1_000_000
        )
        cycles = self._fast_lib.mlkem_encaps_run(self._reg_ptr, timeout_us)
        self._raise_on_run_error(cycles, timeout_s, 'encaps')

        self.ct.invalidate()
        self.ss.invalidate()
        return bytes(self.ct), bytes(self.ss), cycles & 0xFFFFFFFF

    def decaps(self, sk_bytes, ct_bytes, timeout_s=None):
        if len(sk_bytes) != SK_SIZE:
            raise ValueError(f"sk must be {SK_SIZE} bytes")
        if len(ct_bytes) != CT_SIZE:
            raise ValueError(f"ct must be {CT_SIZE} bytes")
        self._ensure_idle()

        self.sk[:] = np.frombuffer(sk_bytes, dtype=np.uint8)
        self.ct[:] = np.frombuffer(ct_bytes, dtype=np.uint8)
        self.sk.flush()
        self.ct.flush()

        timeout_us = int(
            (timeout_s if timeout_s is not None
             else self.DEFAULT_TIMEOUTS_S['decaps']) * 1_000_000
        )
        cycles = self._fast_lib.mlkem_decaps_run(self._reg_ptr, timeout_us)
        self._raise_on_run_error(cycles, timeout_s, 'decaps')

        self.ss.invalidate()
        return bytes(self.ss), cycles & 0xFFFFFFFF

    def _raise_on_run_error(self, code, timeout_s, op_name):
        if code == -1:
            status = self.ip.read(REG_STATUS)
            raise MLKemError(
                f"{op_name}: IP signaled error, STATUS=0x{status:x}"
            )
        if code == -2:
            status = self.ip.read(REG_STATUS)
            raise MLKemError(
                f"{op_name}: timeout after {timeout_s}s, "
                f"STATUS=0x{status:x}"
            )


# ====================================================================
# Method B IRQ-driven driver.
#
# Replaces _wait_done's busy-poll with a kernel-IRQ wakeup via PYNQ's
# Interrupt class. The accelerator drives `irq_done = status_done` (level-
# high while op is complete; deasserts at the next start_pulse). The kernel
# UIO driver handles edge detect + masking; PYNQ wraps it in an asyncio
# coroutine. We synchronously wrap with asyncio.run so the API stays
# identical to MLKem768.
#
# Wall-time vs polling: comparable for sub-ms ops (Linux IRQ-to-userspace
# latency is ~50-200 µs on Cortex-A53). The CPU-availability win (CPU sleeps
# during HW execution) is the main benefit — quantified by separate
# experiments where a second thread runs a CPU-bound workload during waits.
# ====================================================================
import asyncio


class MLKem768IRQ(MLKem768):
    """Wait for HW completion via PYNQ Interrupt instead of busy-polling.

    Requires the bitstream where ml_kem_top_0/irq_done is wired to the
    Zynq pl_ps_irq0 path. PYNQ auto-discovers the interrupt object from
    the .hwh on overlay load.
    """

    def __init__(self, bitfile, ip_name='ml_kem_top_0'):
        super().__init__(bitfile, ip_name=ip_name)
        # Discover the interrupt using three escalating strategies.
        self._interrupt = self._find_interrupt(ip_name)
        if self._interrupt is None:
            # Surface what PYNQ saw to make debugging concrete instead of
            # a generic 'no interrupt' error.
            ov = self.overlay
            keys = [a for a in dir(self.ip) if not a.startswith('_')]
            irq_pins = getattr(ov, 'interrupt_pins', {})
            irq_ctrls = getattr(ov, 'interrupt_controllers', {})
            raise MLKemError(
                "Could not locate an Interrupt object for "
                f"{ip_name}/irq_done. PYNQ overlay state:\n"
                f"  interrupt_pins      = {irq_pins}\n"
                f"  interrupt_controllers = {irq_ctrls}\n"
                f"  ip attrs            = {keys}\n"
                "Likely cause: PYNQ requires either an AXI Intc IP "
                "between the irq source and pl_ps_irq, or the .hwh did "
                "not export interrupt metadata for the module_ref pin."
            )

    def _find_interrupt(self, ip_name):
        # Strategy 1: PYNQ may auto-attach `interrupt` on the IP.
        intr = getattr(self.ip, 'interrupt', None)
        if intr is not None:
            return intr

        # Strategy 2: overlay-level interrupt_pins map. Try by pin path.
        ov = self.overlay
        irq_pins = getattr(ov, 'interrupt_pins', {})
        for candidate in (f"{ip_name}/irq_done", "ml_kem_top_0/irq_done"):
            if candidate in irq_pins:
                from pynq import Interrupt
                return Interrupt(candidate)

        # Strategy 3: brute-force — instantiate Interrupt directly. Works
        # if the .hwh has the IRQ wired even if PYNQ didn't auto-attach.
        try:
            from pynq import Interrupt
            intr = Interrupt(f"{ip_name}/irq_done")
            return intr
        except Exception:
            return None

    def _wait_done(self, timeout_s):
        """Block on the PYNQ Interrupt event, then read REG_CYCLES.

        Uses asyncio.run on a fresh wait coroutine each call. asyncio's
        wait_for raises asyncio.TimeoutError on timeout.
        """
        async def _wait():
            await asyncio.wait_for(self._interrupt.wait(), timeout=timeout_s)

        try:
            asyncio.run(_wait())
        except asyncio.TimeoutError:
            status = self.ip.read(REG_STATUS)
            raise MLKemError(
                f"IRQ wait timeout after {timeout_s}s, STATUS=0x{status:x}"
            )

        status = self.ip.read(REG_STATUS)
        if status & STATUS_ERROR:
            raise MLKemError(f"IP signaled error, STATUS=0x{status:x}")
        if not (status & STATUS_DONE):
            # IRQ fired but DONE not set — should not happen given the
            # `irq_done = status_done` wiring. Fall back to a tight poll.
            for _ in range(1000):
                status = self.ip.read(REG_STATUS)
                if status & STATUS_DONE:
                    break
            else:
                raise MLKemError(
                    f"IRQ asserted but STATUS_DONE never observed, "
                    f"STATUS=0x{status:x}"
                )
        return self.ip.read(REG_CYCLES)


if __name__ == '__main__':
    # Tiny smoke test — confirms overlay loads, CTRL reset state is 0,
    # and all three ops run end-to-end with round-trip ss consistency.
    # Board default: bitstream + hwh live under /root/jupyter_notebooks/verilog_ML_KEM/bitstream/
    bitfile = os.environ.get(
        'ML_KEM_BIT',
        '/root/jupyter_notebooks/verilog_ML_KEM/bitstream/ml_kem_bd.bit',
    )
    print(f"Loading overlay: {bitfile}")
    with MLKem768(bitfile) as kem:
        # Reset-state sanity
        status = kem.ip.read(REG_STATUS)
        print(f"  STATUS @ reset = 0x{status:x} "
              f"(expect bit1=idle set)")
        assert status & STATUS_IDLE, "IP not idle after overlay load"

        # Deterministic seeds for smoke test
        d = bytes(range(32))
        z = bytes(range(32, 64))
        m = bytes(range(0x80, 0xA0))

        pk, sk, c1 = kem.keygen(d, z)
        print(f"  KeyGen:  {c1:6d} cycles  ({cycles_to_us(c1):8.1f} µs)")
        print(f"    pk[0:8] = {pk[:8].hex()}")

        ct, ss_enc, c2 = kem.encaps(pk, m)
        print(f"  Encaps:  {c2:6d} cycles  ({cycles_to_us(c2):8.1f} µs)")
        print(f"    ss     = {ss_enc.hex()}")

        ss_dec, c3 = kem.decaps(sk, ct)
        print(f"  Decaps:  {c3:6d} cycles  ({cycles_to_us(c3):8.1f} µs)")
        print(f"    ss     = {ss_dec.hex()}")

        ok = (ss_enc == ss_dec)
        print(f"  Round-trip ss match: {ok}")
        if not ok:
            raise SystemExit(1)
        print(f"  Total: {(c1+c2+c3):6d} cycles "
              f"({cycles_to_us(c1+c2+c3):.1f} µs per full KEM)")
