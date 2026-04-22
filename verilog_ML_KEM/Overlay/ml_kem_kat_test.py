"""
NIST KAT regression on the KR260 hardware driver.

Runs all (or first N) KAT vectors from KAT_768.txt through the real hardware
and compares against expected pk / sk / ct / ss per vector. Reports both
correctness and hardware cycle counts.

Usage:
    python3 ml_kem_kat_test.py              # run all vectors
    python3 ml_kem_kat_test.py 10           # run first 10
    ML_KEM_BIT=/path/to/ml_kem.bit \\
      KAT_FILE=/path/to/KAT_768.txt \\
      python3 ml_kem_kat_test.py
"""

import os
import sys
import time

from ml_kem_driver import MLKem768, cycles_to_us


def parse_kat_file(path):
    """Parse a NIST KAT file into a list of per-vector dicts.

    File format: `key = hex` per line, blank line separates vectors.
    Keys used by ML-KEM-768: d, z, pk, sk, m, ct, ss.
    """
    vectors = []
    current = {}
    with open(path, 'r') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                if current:
                    vectors.append(current)
                    current = {}
                continue
            if '=' not in line:
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            val = val.strip()
            try:
                current[key] = bytes.fromhex(val)
            except ValueError:
                # Non-hex value (e.g. the 'count' line in some formats)
                current[key] = val
    if current:
        vectors.append(current)
    return vectors


def run_kat(vectors, kem, stop_on_fail=False):
    """Run all vectors through the hardware. Returns a result summary dict."""
    n = len(vectors)
    pass_ct = 0
    fail_ct = 0
    first_fail = None
    totals = {'keygen': 0, 'encaps': 0, 'decaps': 0}
    fail_reasons = []

    t0 = time.monotonic()
    for i, v in enumerate(vectors):
        try:
            d  = v['d']
            z  = v['z']
            m  = v['m']
            pk_exp = v['pk']
            sk_exp = v['sk']
            ct_exp = v['ct']
            ss_exp = v['ss']
        except KeyError as e:
            fail_ct += 1
            fail_reasons.append((i, f'missing KAT field {e}'))
            if first_fail is None:
                first_fail = i
            if stop_on_fail:
                break
            continue

        # 1) KeyGen
        pk, sk, c_kg = kem.keygen(d, z)
        totals['keygen'] += c_kg
        if pk != pk_exp:
            fail_ct += 1
            fail_reasons.append((i, 'pk mismatch'))
            if first_fail is None:
                first_fail = i
            if stop_on_fail:
                break
            continue
        if sk != sk_exp:
            fail_ct += 1
            fail_reasons.append((i, 'sk mismatch'))
            if first_fail is None:
                first_fail = i
            if stop_on_fail:
                break
            continue

        # 2) Encaps with deterministic m from KAT
        ct, ss_enc, c_enc = kem.encaps(pk, m)
        totals['encaps'] += c_enc
        if ct != ct_exp:
            fail_ct += 1
            fail_reasons.append((i, 'ct mismatch'))
            if first_fail is None:
                first_fail = i
            if stop_on_fail:
                break
            continue
        if ss_enc != ss_exp:
            fail_ct += 1
            fail_reasons.append((i, 'encaps ss mismatch'))
            if first_fail is None:
                first_fail = i
            if stop_on_fail:
                break
            continue

        # 3) Decaps (must round-trip to same ss)
        ss_dec, c_dec = kem.decaps(sk, ct)
        totals['decaps'] += c_dec
        if ss_dec != ss_exp:
            fail_ct += 1
            fail_reasons.append((i, 'decaps ss mismatch'))
            if first_fail is None:
                first_fail = i
            if stop_on_fail:
                break
            continue

        pass_ct += 1
        if (i + 1) % 10 == 0 or (i + 1) == n:
            print(f"  [{i+1:3d}/{n}] pass (KG={c_kg:6d}, "
                  f"Enc={c_enc:6d}, Dec={c_dec:6d} cyc)")

    wall = time.monotonic() - t0

    return {
        'n': n,
        'pass': pass_ct,
        'fail': fail_ct,
        'first_fail': first_fail,
        'reasons': fail_reasons,
        'totals': totals,
        'wall_seconds': wall,
    }


def main():
    n_vectors = None
    if len(sys.argv) > 1:
        n_vectors = int(sys.argv[1])

    script_dir = os.path.dirname(os.path.abspath(__file__))
    kat_path = os.environ.get(
        'KAT_FILE',
        os.path.join(script_dir, 'KAT_768.txt'),
    )
    bitfile = os.environ.get(
        'ML_KEM_BIT',
        os.path.join(script_dir, 'ml_kem.bit'),
    )

    print(f"Bitfile : {bitfile}")
    print(f"KAT file: {kat_path}")
    vectors = parse_kat_file(kat_path)
    if n_vectors is not None:
        vectors = vectors[:n_vectors]
    print(f"Running {len(vectors)} KAT vector(s)...")
    print()

    with MLKem768(bitfile) as kem:
        result = run_kat(vectors, kem)

    print()
    print("===== Summary =====")
    print(f"PASS: {result['pass']:3d} / {result['n']}")
    print(f"FAIL: {result['fail']:3d} / {result['n']}")
    if result['fail']:
        print(f"First failure at index {result['first_fail']}")
        for i, r in result['reasons'][:10]:
            print(f"  vec #{i}: {r}")
        if len(result['reasons']) > 10:
            print(f"  ... and {len(result['reasons']) - 10} more")

    n_ok = result['pass']
    if n_ok > 0:
        t = result['totals']
        print()
        print("Average hardware cycles (successful vectors only):")
        print(f"  KeyGen : {t['keygen']//n_ok:8d} cyc  "
              f"({cycles_to_us(t['keygen']/n_ok):8.1f} µs)")
        print(f"  Encaps : {t['encaps']//n_ok:8d} cyc  "
              f"({cycles_to_us(t['encaps']/n_ok):8.1f} µs)")
        print(f"  Decaps : {t['decaps']//n_ok:8d} cyc  "
              f"({cycles_to_us(t['decaps']/n_ok):8.1f} µs)")
        total = t['keygen'] + t['encaps'] + t['decaps']
        print(f"  Full   : {total//n_ok:8d} cyc  "
              f"({cycles_to_us(total/n_ok):8.1f} µs per full KEM)")
        print()
        print(f"Wall time: {result['wall_seconds']:.1f} s "
              f"({result['wall_seconds']/result['n']*1000:.1f} ms/vec "
              f"including PYNQ overhead)")

    sys.exit(0 if result['fail'] == 0 else 1)


if __name__ == '__main__':
    main()
