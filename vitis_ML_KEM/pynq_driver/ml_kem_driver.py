"""
ML-KEM (Kyber-768) PYNQ Driver
================================
Python driver to control the 3 HLS accelerator IPs on Kria KR260 via PYNQ.

Each kernel (KeyGen, Encaps, Decaps) is a separate overlay with its own
.bit + .hwh pair. The driver handles:
  - DMA buffer allocation (pynq.allocate)
  - AXI-Lite register programming (pointer + control)
  - Start / poll-done / read-back

Register maps extracted from the .hwh files (Vivado block design).

Usage on Kria KR260:
    from ml_kem_driver import MLKEMKeygen, MLKEMEncaps, MLKEMDecaps

    keygen = MLKEMKeygen("path/to/ml_kem_keygen_0.bit")
    pk, sk = keygen.run(seed_d, seed_z)

    encaps = MLKEMEncaps("path/to/ml_kem_encaps_0.bit")
    ct, ss = encaps.run(pk, randomness_m)

    decaps = MLKEMDecaps("path/to/ml_kem_decaps_0.bit")
    ss2 = decaps.run(sk, ct)

    assert ss == ss2  # Shared secrets must match
"""

import numpy as np
import time

# Try importing pynq - will only work on the actual FPGA board
try:
    from pynq import Overlay, allocate, Device
    PYNQ_AVAILABLE = True

    # On Kria boards, PYNQ uses embedded devices (not XRT).
    # The Kria-PYNQ install script sets up:
    #   - /etc/xocl.txt (platform name)
    #   - /etc/profile.d/pynq_venv.sh (env vars including XILINX_XRT=/usr)
    #   - Device tree overlay (pynq.dtbo)
    # If no devices are found, guide the user to install correctly.
    if len(Device.devices) == 0:
        import os
        hints = []
        if not os.path.exists("/etc/xocl.txt"):
            hints.append("  - /etc/xocl.txt not found (Kria-PYNQ not installed)")
        if not os.path.exists("/etc/profile.d/pynq_venv.sh"):
            hints.append("  - /etc/profile.d/pynq_venv.sh not found")
        if not os.environ.get("XILINX_XRT"):
            hints.append("  - XILINX_XRT env var not set "
                         "(run: source /etc/profile.d/pynq_venv.sh)")
        if os.geteuid() != 0:
            hints.append("  - Not running as root (use: sudo -E)")

        print("[WARN] No PYNQ devices found.")
        if hints:
            print("Possible causes:")
            print("\n".join(hints))
        print("\nFix: Install Kria-PYNQ properly:")
        print("  git clone https://github.com/Xilinx/Kria-PYNQ.git")
        print("  cd Kria-PYNQ && sudo bash install.sh -b KR260")
        print("  sudo reboot")
        print("Then run: source /etc/profile.d/pynq_venv.sh")
        print("     and: sudo -E python3 <your_script.py>")
except ImportError:
    PYNQ_AVAILABLE = False
    print("[WARN] pynq not available. Running in simulation/offline mode.")


# ===========================================================
# Constants - Kyber-768
# ===========================================================
PK_SIZE = 1184   # Public key bytes
SK_SIZE = 2400   # Secret key bytes (s || pk || H(pk) || z)
CT_SIZE = 1088   # Ciphertext bytes
SS_SIZE = 32     # Shared secret bytes
SEED_SIZE = 32   # seed_d / seed_z / randomness_m bytes

# ===========================================================
# AXI-Lite Register Offsets (common to all 3 IPs)
# ===========================================================
REG_CTRL = 0x00    # AP_START(bit0), AP_DONE(bit1), AP_IDLE(bit2), AP_READY(bit3)
REG_GIER = 0x04    # Global Interrupt Enable
REG_IER  = 0x08    # IP Interrupt Enable
REG_ISR  = 0x0C    # IP Interrupt Status

# AP_CTRL bit masks
AP_START = 0x01
AP_DONE  = 0x02
AP_IDLE  = 0x04
AP_READY = 0x08


# ===========================================================
# Helper Functions
# ===========================================================
def _write_pointer(ip, offset_lo, addr):
    """Write a 64-bit physical address into two 32-bit AXI-Lite registers."""
    ip.write(offset_lo, addr & 0xFFFFFFFF)
    ip.write(offset_lo + 4, (addr >> 32) & 0xFFFFFFFF)


def _wait_done(ip, timeout_sec=10.0):
    """Poll CTRL register until AP_DONE is asserted."""
    start = time.time()
    while True:
        ctrl = ip.read(REG_CTRL)
        if ctrl & AP_DONE:
            return
        if time.time() - start > timeout_sec:
            raise TimeoutError(
                f"HLS IP did not finish within {timeout_sec}s. "
                f"CTRL=0x{ctrl:08X}"
            )
        time.sleep(0.0001)  # 100us poll interval


def _bytes_to_u64_array(data: bytes) -> np.ndarray:
    """Convert raw bytes (must be multiple of 8) to uint64 array for seed input."""
    assert len(data) % 8 == 0, f"Data length {len(data)} must be multiple of 8"
    return np.frombuffer(data, dtype=np.uint64).copy()


def _check_pynq():
    """Raise error if pynq is not available."""
    if not PYNQ_AVAILABLE:
        raise RuntimeError(
            "pynq library is not installed. "
            "This driver must run on the Kria KR260 board with PYNQ."
        )


# ===========================================================
# Keygen Driver
# ===========================================================
# Register map (from ml_kem_keygen_0.hwh):
#   0x10-0x14  seed_d pointer (64-bit)
#   0x1C-0x20  seed_z pointer (64-bit)
#   0x28-0x2C  pk_out pointer (64-bit)
#   0x34-0x38  sk_out pointer (64-bit)

KEYGEN_REG_SEED_D = 0x10
KEYGEN_REG_SEED_Z = 0x1C
KEYGEN_REG_PK_OUT = 0x28
KEYGEN_REG_SK_OUT = 0x34


class MLKEMKeygen:
    """
    ML-KEM KeyGen accelerator driver.

    Inputs:  seed_d (32 bytes), seed_z (32 bytes)
    Outputs: pk (1184 bytes), sk (2400 bytes)
    """

    def __init__(self, bitstream_path: str):
        _check_pynq()
        self.ol = Overlay(bitstream_path)
        self.ip = self.ol.ml_kem_keygen_0

    def run(self, seed_d: bytes, seed_z: bytes, timeout: float = 10.0):
        """
        Run KeyGen on FPGA.

        Args:
            seed_d: 32-byte random seed d
            seed_z: 32-byte random seed z
            timeout: Max seconds to wait for completion

        Returns:
            (pk, sk): tuple of bytes (1184, 2400)
        """
        assert len(seed_d) == SEED_SIZE, f"seed_d must be {SEED_SIZE} bytes"
        assert len(seed_z) == SEED_SIZE, f"seed_z must be {SEED_SIZE} bytes"

        # Allocate contiguous DMA buffers
        seed_d_buf = allocate(shape=(4,), dtype=np.uint64)
        seed_z_buf = allocate(shape=(4,), dtype=np.uint64)
        pk_buf = allocate(shape=(PK_SIZE,), dtype=np.uint8)
        sk_buf = allocate(shape=(SK_SIZE,), dtype=np.uint8)

        try:
            # Fill inputs
            seed_d_buf[:] = _bytes_to_u64_array(seed_d)
            seed_z_buf[:] = _bytes_to_u64_array(seed_z)

            # Flush caches
            seed_d_buf.flush()
            seed_z_buf.flush()

            # Program pointer registers
            _write_pointer(self.ip, KEYGEN_REG_SEED_D, seed_d_buf.physical_address)
            _write_pointer(self.ip, KEYGEN_REG_SEED_Z, seed_z_buf.physical_address)
            _write_pointer(self.ip, KEYGEN_REG_PK_OUT, pk_buf.physical_address)
            _write_pointer(self.ip, KEYGEN_REG_SK_OUT, sk_buf.physical_address)

            # Start
            self.ip.write(REG_CTRL, AP_START)

            # Wait for completion
            _wait_done(self.ip, timeout)

            # Invalidate output caches and read
            pk_buf.invalidate()
            sk_buf.invalidate()

            return bytes(pk_buf), bytes(sk_buf)

        finally:
            seed_d_buf.freebuffer()
            seed_z_buf.freebuffer()
            pk_buf.freebuffer()
            sk_buf.freebuffer()

    def close(self):
        """Free overlay resources."""
        if hasattr(self, 'ol'):
            self.ol.free()


# ===========================================================
# Encaps Driver
# ===========================================================
# Register map (from ml_kem_encaps_0.hwh):
#   0x10-0x14  pk_in pointer (64-bit)
#   0x1C-0x20  randomness_m pointer (64-bit)
#   0x28-0x2C  ct_out pointer (64-bit)
#   0x34-0x38  ss_out pointer (64-bit)

ENCAPS_REG_PK_IN  = 0x10
ENCAPS_REG_RAND_M = 0x1C
ENCAPS_REG_CT_OUT = 0x28
ENCAPS_REG_SS_OUT = 0x34


class MLKEMEncaps:
    """
    ML-KEM Encapsulation accelerator driver.

    Inputs:  pk (1184 bytes), randomness_m (32 bytes)
    Outputs: ct (1088 bytes), ss (32 bytes)
    """

    def __init__(self, bitstream_path: str):
        _check_pynq()
        self.ol = Overlay(bitstream_path)
        self.ip = self.ol.ml_kem_encaps_0

    def run(self, pk: bytes, randomness_m: bytes, timeout: float = 10.0):
        """
        Run Encapsulation on FPGA.

        Args:
            pk: 1184-byte public key (from KeyGen)
            randomness_m: 32-byte random message
            timeout: Max seconds to wait for completion

        Returns:
            (ct, ss): tuple of bytes (1088, 32)
        """
        assert len(pk) == PK_SIZE, f"pk must be {PK_SIZE} bytes"
        assert len(randomness_m) == SEED_SIZE, f"randomness_m must be {SEED_SIZE} bytes"

        pk_buf = allocate(shape=(PK_SIZE,), dtype=np.uint8)
        rand_buf = allocate(shape=(SEED_SIZE,), dtype=np.uint8)
        ct_buf = allocate(shape=(CT_SIZE,), dtype=np.uint8)
        ss_buf = allocate(shape=(SS_SIZE,), dtype=np.uint8)

        try:
            # Fill inputs
            pk_buf[:] = np.frombuffer(pk, dtype=np.uint8)
            rand_buf[:] = np.frombuffer(randomness_m, dtype=np.uint8)

            pk_buf.flush()
            rand_buf.flush()

            # Program pointer registers
            _write_pointer(self.ip, ENCAPS_REG_PK_IN, pk_buf.physical_address)
            _write_pointer(self.ip, ENCAPS_REG_RAND_M, rand_buf.physical_address)
            _write_pointer(self.ip, ENCAPS_REG_CT_OUT, ct_buf.physical_address)
            _write_pointer(self.ip, ENCAPS_REG_SS_OUT, ss_buf.physical_address)

            # Start
            self.ip.write(REG_CTRL, AP_START)

            # Wait
            _wait_done(self.ip, timeout)

            ct_buf.invalidate()
            ss_buf.invalidate()

            return bytes(ct_buf), bytes(ss_buf)

        finally:
            pk_buf.freebuffer()
            rand_buf.freebuffer()
            ct_buf.freebuffer()
            ss_buf.freebuffer()

    def close(self):
        """Free overlay resources."""
        if hasattr(self, 'ol'):
            self.ol.free()


# ===========================================================
# Decaps Driver
# ===========================================================
# Register map (from ml_kem_decaps_0.hwh):
#   0x10-0x14  sk_in pointer (64-bit)
#   0x1C-0x20  ct_in pointer (64-bit)
#   0x28-0x2C  ss_out pointer (64-bit)

DECAPS_REG_SK_IN  = 0x10
DECAPS_REG_CT_IN  = 0x1C
DECAPS_REG_SS_OUT = 0x28


class MLKEMDecaps:
    """
    ML-KEM Decapsulation accelerator driver.

    Inputs:  sk (2400 bytes), ct (1088 bytes)
    Outputs: ss (32 bytes)
    """

    def __init__(self, bitstream_path: str):
        _check_pynq()
        self.ol = Overlay(bitstream_path)
        self.ip = self.ol.ml_kem_decaps_0

    def run(self, sk: bytes, ct: bytes, timeout: float = 10.0):
        """
        Run Decapsulation on FPGA.

        Args:
            sk: 2400-byte secret key (from KeyGen)
            ct: 1088-byte ciphertext (from Encaps)
            timeout: Max seconds to wait for completion

        Returns:
            ss: 32-byte shared secret
        """
        assert len(sk) == SK_SIZE, f"sk must be {SK_SIZE} bytes"
        assert len(ct) == CT_SIZE, f"ct must be {CT_SIZE} bytes"

        sk_buf = allocate(shape=(SK_SIZE,), dtype=np.uint8)
        ct_buf = allocate(shape=(CT_SIZE,), dtype=np.uint8)
        ss_buf = allocate(shape=(SS_SIZE,), dtype=np.uint8)

        try:
            # Fill inputs
            sk_buf[:] = np.frombuffer(sk, dtype=np.uint8)
            ct_buf[:] = np.frombuffer(ct, dtype=np.uint8)

            sk_buf.flush()
            ct_buf.flush()

            # Program pointer registers
            _write_pointer(self.ip, DECAPS_REG_SK_IN, sk_buf.physical_address)
            _write_pointer(self.ip, DECAPS_REG_CT_IN, ct_buf.physical_address)
            _write_pointer(self.ip, DECAPS_REG_SS_OUT, ss_buf.physical_address)

            # Start
            self.ip.write(REG_CTRL, AP_START)

            # Wait
            _wait_done(self.ip, timeout)

            ss_buf.invalidate()

            return bytes(ss_buf)

        finally:
            sk_buf.freebuffer()
            ct_buf.freebuffer()
            ss_buf.freebuffer()

    def close(self):
        """Free overlay resources."""
        if hasattr(self, 'ol'):
            self.ol.free()


# ===========================================================
# Full ML-KEM Flow (convenience wrapper)
# ===========================================================
class MLKEMAccelerator:
    """
    High-level wrapper that manages all 3 overlays for a full KEM flow.

    Note: Each call to keygen/encaps/decaps reloads the FPGA,
    since each operation uses a separate bitstream.
    """

    def __init__(self, bitstream_dir: str):
        """
        Args:
            bitstream_dir: Directory containing the 3 subdirectories
                           (Keygen/, Encaps/, Decaps/) with .bit + .hwh files.
        """
        import os
        self.keygen_bit = os.path.join(bitstream_dir, "Keygen", "ml_kem_keygen_0.bit")
        self.encaps_bit = os.path.join(bitstream_dir, "Encaps", "ml_kem_encaps_0.bit")
        self.decaps_bit = os.path.join(bitstream_dir, "Decaps", "ml_kem_decaps_0.bit")

    def keygen(self, seed_d: bytes, seed_z: bytes):
        """Generate keypair. Returns (pk, sk)."""
        drv = MLKEMKeygen(self.keygen_bit)
        try:
            return drv.run(seed_d, seed_z)
        finally:
            drv.close()

    def encaps(self, pk: bytes, randomness_m: bytes):
        """Encapsulate. Returns (ct, ss)."""
        drv = MLKEMEncaps(self.encaps_bit)
        try:
            return drv.run(pk, randomness_m)
        finally:
            drv.close()

    def decaps(self, sk: bytes, ct: bytes):
        """Decapsulate. Returns ss."""
        drv = MLKEMDecaps(self.decaps_bit)
        try:
            return drv.run(sk, ct)
        finally:
            drv.close()

    def full_flow(self, seed_d: bytes, seed_z: bytes, randomness_m: bytes):
        """
        Run complete KEM: KeyGen → Encaps → Decaps.
        Verifies that shared secrets match.

        Returns:
            dict with pk, sk, ct, ss_encaps, ss_decaps, match
        """
        pk, sk = self.keygen(seed_d, seed_z)
        ct, ss_encaps = self.encaps(pk, randomness_m)
        ss_decaps = self.decaps(sk, ct)

        return {
            "pk": pk,
            "sk": sk,
            "ct": ct,
            "ss_encaps": ss_encaps,
            "ss_decaps": ss_decaps,
            "match": ss_encaps == ss_decaps,
        }


# ===========================================================
# CLI demo
# ===========================================================
if __name__ == "__main__":
    import os
    import sys

    _check_pynq()

    # Default bitstream dir: ../bitstream/ relative to this file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_bit_dir = os.path.join(script_dir, "..", "bitstream")
    bit_dir = sys.argv[1] if len(sys.argv) > 1 else default_bit_dir

    print(f"ML-KEM 768 FPGA Accelerator Demo")
    print(f"Bitstream dir: {bit_dir}")
    print("=" * 50)

    # Generate random seeds
    seed_d = os.urandom(32)
    seed_z = os.urandom(32)
    rand_m = os.urandom(32)

    accel = MLKEMAccelerator(bit_dir)

    # KeyGen
    print("\n[1/3] KeyGen...")
    t0 = time.time()
    pk, sk = accel.keygen(seed_d, seed_z)
    t_keygen = time.time() - t0
    print(f"  pk: {len(pk)} bytes, sk: {len(sk)} bytes")
    print(f"  Time: {t_keygen*1000:.2f} ms")

    # Encaps
    print("\n[2/3] Encaps...")
    t0 = time.time()
    ct, ss_enc = accel.encaps(pk, rand_m)
    t_encaps = time.time() - t0
    print(f"  ct: {len(ct)} bytes, ss: {ss_enc.hex()}")
    print(f"  Time: {t_encaps*1000:.2f} ms")

    # Decaps
    print("\n[3/3] Decaps...")
    t0 = time.time()
    ss_dec = accel.decaps(sk, ct)
    t_decaps = time.time() - t0
    print(f"  ss: {ss_dec.hex()}")
    print(f"  Time: {t_decaps*1000:.2f} ms")

    # Verify
    print("\n" + "=" * 50)
    match = ss_enc == ss_dec
    print(f"Shared secrets match: {'✅ YES' if match else '❌ NO'}")
    print(f"Total time: {(t_keygen + t_encaps + t_decaps)*1000:.2f} ms")

    if not match:
        sys.exit(1)
