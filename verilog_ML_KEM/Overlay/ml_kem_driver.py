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


if __name__ == '__main__':
    # Tiny smoke test — confirms overlay loads, CTRL reset state is 0,
    # and all three ops run end-to-end with round-trip ss consistency.
    bitfile = os.environ.get('ML_KEM_BIT', 'ml_kem.bit')
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
