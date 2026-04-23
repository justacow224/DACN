"""
Latency + throughput benchmark for the ML-KEM-768 accelerator.

For each selected op, runs N iterations with random inputs and reports:
- Hardware cycles (median, min, max) — pure accelerator latency.
- PYNQ-visible wall time (includes register writes + cache ops + polling).
- Throughput under the pulse-then-poll API.

Usage:
    python3 ml_kem_bench.py                     # N=100, all ops
    python3 ml_kem_bench.py -n 500              # N=500, all ops
    python3 ml_kem_bench.py --op keygen         # only KeyGen
    python3 ml_kem_bench.py --op decaps -n 200  # only Decaps, N=200
    python3 ml_kem_bench.py 500                 # positional N (backwards compat)

Ops:
    keygen  — KeyGen only (random d, z)
    encaps  — Encaps only (warm pk, random m)
    decaps  — Decaps only (warm sk, warm ct)
    full    — Full KEM (KG + Enc + Dec per iteration)
    all     — Run all four (default)
"""

import argparse
import os
import secrets
import statistics
import sys
import time

from ml_kem_driver import MLKem768, cycles_to_us


def bench_op(label, fn, n):
    """Run fn() n times. fn must return (..., cycles) or plain cycles."""
    cycles_list = []
    wall_list = []
    for _ in range(n):
        t0 = time.monotonic()
        result = fn()
        wall_list.append(time.monotonic() - t0)
        cyc = result[-1] if isinstance(result, tuple) else result
        cycles_list.append(cyc)

    def us(seconds):
        return seconds * 1e6

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
          f"(= {int(c_med)} cyc @ 100 MHz)")
    print(f"    Wall time   : median={us(w_med):6.1f} µs  "
          f"min={us(w_min):6.1f}  max={us(w_max):6.1f}")
    print(f"    PYNQ ovhd   : ~{us(w_med) - cycles_to_us(c_med):6.1f} µs "
          f"(wall − hw)")
    print(f"    Throughput  : {throughput:6.1f} ops/s "
          f"(pulse-then-poll, single-thread)")
    return {'cycles': cycles_list, 'wall_s': wall_list}


# ----- Per-op bench wrappers ------------------------------------------------

def bench_keygen(kem, n):
    print("--- KeyGen (random d, z per iter) ---")
    bench_op(
        'KeyGen',
        lambda: kem.keygen(secrets.token_bytes(32), secrets.token_bytes(32)),
        n,
    )


def bench_encaps(kem, n):
    print("--- Encaps (warm pk, random m per iter) ---")
    # Generate a real key pair to encaps against
    pk_warm, _, _ = kem.keygen(secrets.token_bytes(32), secrets.token_bytes(32))
    bench_op(
        'Encaps',
        lambda: kem.encaps(pk_warm, secrets.token_bytes(32)),
        n,
    )


def bench_decaps(kem, n):
    print("--- Decaps (warm sk, warm ct — match branch) ---")
    pk_warm, sk_warm, _ = kem.keygen(secrets.token_bytes(32), secrets.token_bytes(32))
    ct_warm, _, _ = kem.encaps(pk_warm, secrets.token_bytes(32))
    bench_op(
        'Decaps',
        lambda: kem.decaps(sk_warm, ct_warm),
        n,
    )


def bench_full(kem, n):
    print("--- Full KEM round-trip (KG + Encaps + Decaps per iter) ---")

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


OP_DISPATCH = {
    'keygen': bench_keygen,
    'encaps': bench_encaps,
    'decaps': bench_decaps,
    'full':   bench_full,
}


def parse_args():
    # Support both styles:
    #   ml_kem_bench.py 500                  (positional N, backwards compat)
    #   ml_kem_bench.py -n 500 --op decaps   (flagged)
    parser = argparse.ArgumentParser(
        description='ML-KEM-768 hardware benchmark.'
    )
    parser.add_argument(
        'n_positional', type=int, nargs='?', default=None,
        help='Number of iterations per op (positional, backwards compat).',
    )
    parser.add_argument(
        '-n', '--iterations', type=int, default=None,
        help='Number of iterations per op (flagged form).',
    )
    parser.add_argument(
        '--op', choices=list(OP_DISPATCH.keys()) + ['all'],
        default='all',
        help='Which operation to bench. Default: all.',
    )
    parser.add_argument(
        '--bit', default=None,
        help='Path to bitfile (overrides ML_KEM_BIT env var).',
    )
    args = parser.parse_args()

    # Resolve N: flag takes precedence, then positional, else default 100.
    if args.iterations is not None:
        args.n = args.iterations
    elif args.n_positional is not None:
        args.n = args.n_positional
    else:
        args.n = 100
    return args


def main():
    args = parse_args()

    # Board default: /root/jupyter_notebooks/verilog_ML_KEM/bitstream/ml_kem_bd.{bit,hwh}
    bitfile = (
        args.bit
        or os.environ.get('ML_KEM_BIT')
        or '/root/jupyter_notebooks/verilog_ML_KEM/bitstream/ml_kem_bd.bit'
    )

    print(f"Benchmark: {args.n} iterations / op")
    print(f"Op(s)    : {args.op}")
    print(f"Bitfile  : {bitfile}")
    print()

    with MLKem768(bitfile) as kem:
        if args.op == 'all':
            for name in ['keygen', 'encaps', 'decaps', 'full']:
                OP_DISPATCH[name](kem, args.n)
                print()
        else:
            OP_DISPATCH[args.op](kem, args.n)


if __name__ == '__main__':
    main()
