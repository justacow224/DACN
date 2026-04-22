"""
Latency + throughput benchmark for the ML-KEM-768 accelerator.

Runs N iterations of each operation with random inputs, reports:
- Hardware cycles (median, min, max).
- PYNQ-visible wall time (includes register writes + buffer copy + polling).
- Hardware-only time derived from cycles (pure accelerator latency).
- Ops/second throughput under the pulse-then-poll API.

Usage:
    python3 ml_kem_bench.py               # default N=100
    python3 ml_kem_bench.py 500           # N=500
    ML_KEM_BIT=/path/to/ml_kem.bit python3 ml_kem_bench.py
"""

import os
import secrets
import statistics
import sys
import time

from ml_kem_driver import MLKem768, cycles_to_us


def bench_op(label, fn, n):
    """Run `fn()` n times. fn must return cycle count as its last value."""
    cycles_list = []
    wall_list = []
    for _ in range(n):
        t0 = time.monotonic()
        result = fn()
        wall_list.append(time.monotonic() - t0)
        # result is (..., cycles); accept tuples or plain int
        cyc = result[-1] if isinstance(result, tuple) else result
        cycles_list.append(cyc)

    def us(seconds): return seconds * 1e6

    c_med = statistics.median(cycles_list)
    c_min = min(cycles_list)
    c_max = max(cycles_list)
    w_med = statistics.median(wall_list)
    w_min = min(wall_list)
    w_max = max(wall_list)
    throughput = n / sum(wall_list) if sum(wall_list) > 0 else 0

    print(f"  {label}")
    print(f"    HW cycles   : median={int(c_med):6d}  "
          f"min={c_min:6d}  max={c_max:6d}")
    print(f"    HW latency  : median={cycles_to_us(c_med):6.1f} µs  "
          f"(= {int(c_med)} cyc @ 100MHz)")
    print(f"    Wall time   : median={us(w_med):6.1f} µs  "
          f"min={us(w_min):6.1f}  max={us(w_max):6.1f}")
    print(f"    PYNQ ovhd   : ~{us(w_med)-cycles_to_us(c_med):6.1f} µs "
          f"(wall − hw, register writes + poll + copy)")
    print(f"    Throughput  : {throughput:6.1f} ops/s "
          f"(pulse-then-poll, single-thread)")
    return {
        'cycles': cycles_list,
        'wall_s': wall_list,
    }


def main():
    n = 100
    if len(sys.argv) > 1:
        n = int(sys.argv[1])

    script_dir = os.path.dirname(os.path.abspath(__file__))
    bitfile = os.environ.get(
        'ML_KEM_BIT',
        os.path.join(script_dir, 'ml_kem.bit'),
    )

    print(f"Benchmark: {n} iterations per operation")
    print(f"Bitfile  : {bitfile}")
    print()

    with MLKem768(bitfile) as kem:
        # Warm keys for encaps/decaps bench — use fresh randomness each iter.
        warm_d = secrets.token_bytes(32)
        warm_z = secrets.token_bytes(32)
        pk_warm, sk_warm, _ = kem.keygen(warm_d, warm_z)

        print("--- KeyGen ---")
        bench_op('KeyGen (random d,z)',
                 lambda: kem.keygen(secrets.token_bytes(32),
                                    secrets.token_bytes(32)),
                 n)

        print()
        print("--- Encaps ---")
        bench_op('Encaps (fixed pk, random m)',
                 lambda: kem.encaps(pk_warm, secrets.token_bytes(32)),
                 n)

        print()
        print("--- Decaps (valid ct, match branch) ---")
        # Pre-generate a valid ct for decaps bench.
        ct_warm, _, _ = kem.encaps(pk_warm, secrets.token_bytes(32))
        bench_op('Decaps (fixed sk, fixed ct)',
                 lambda: kem.decaps(sk_warm, ct_warm),
                 n)

        print()
        print("--- Full KEM round-trip (KG + Encaps + Decaps) ---")
        def full_kem():
            d = secrets.token_bytes(32)
            z = secrets.token_bytes(32)
            m = secrets.token_bytes(32)
            pk, sk, c1 = kem.keygen(d, z)
            ct, ss1, c2 = kem.encaps(pk, m)
            ss2, c3 = kem.decaps(sk, ct)
            assert ss1 == ss2, "Round-trip ss mismatch at runtime"
            return (c1 + c2 + c3,)
        bench_op('Full KEM', full_kem, n)


if __name__ == '__main__':
    main()
