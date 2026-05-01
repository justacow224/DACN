"""
Extract KAT vector fields from KAT_768.txt into per-field .mem files
for SystemVerilog $readmemh consumption.

By default extracts vec #0 to verilog_ML_KEM/sim_1/new/kat0/. Pass
--vec N to extract vec #N (still output to kat0/ so the TB picks it up
without changing the `KAT0_DIR define).

Output: verilog_ML_KEM/sim_1/new/kat0/{d,z,m,pk,sk,ct,ss}.mem
        — each file is one byte per line as 2-char hex, no comments,
        ready for $readmemh.

Usage:
    python verilog_ML_KEM/scripts/extract_kat0.py             # vec #0
    python verilog_ML_KEM/scripts/extract_kat0.py --vec 14    # vec #14

The TB tb_ml_kem_top.sv (Gate B branch) reads these files via $readmemh
to drive a real KAT regression.
"""
import argparse
import os
import sys

KAT_PATH    = "verilog_ML_KEM/sim_1/new/KAT_768.txt"
OUT_DIR     = "verilog_ML_KEM/sim_1/new/kat0"
EXPECT_LEN  = {"d": 32, "z": 32, "m": 32, "pk": 1184, "sk": 2400, "ct": 1088, "ss": 32}


def parse_vector_at(path, index):
    """Parse the index-th vector (0-based) from a KAT file. A vector is a
    contiguous block of `key = hex` lines separated from the next block by
    one or more blank lines."""
    vectors = []
    fields = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                if fields:
                    vectors.append(fields)
                    fields = {}
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            fields[key.strip()] = val.strip()
    if fields:
        vectors.append(fields)
    if index >= len(vectors):
        sys.exit(f"requested vec #{index} but only {len(vectors)} vectors in {path}")
    return vectors[index]


def write_mem(name, hex_str, expect_bytes):
    raw = bytes.fromhex(hex_str)
    if len(raw) != expect_bytes:
        sys.exit(f"{name}: expected {expect_bytes} bytes, got {len(raw)}")
    out = os.path.join(OUT_DIR, f"{name}.mem")
    with open(out, "w") as f:
        for b in raw:
            f.write(f"{b:02x}\n")
    print(f"  {name}.mem  ({len(raw)} bytes)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vec", type=int, default=0, help="KAT vector index (0-based)")
    args = parser.parse_args()
    if not os.path.exists(KAT_PATH):
        sys.exit(f"KAT file not found: {KAT_PATH}")
    os.makedirs(OUT_DIR, exist_ok=True)
    fields = parse_vector_at(KAT_PATH, args.vec)
    print(f"Parsed KAT vec #{args.vec} from {KAT_PATH}, writing to {OUT_DIR}/")
    for name, n in EXPECT_LEN.items():
        if name not in fields:
            sys.exit(f"missing field '{name}' in vec #{args.vec}")
        write_mem(name, fields[name], n)
    print("done.")


if __name__ == "__main__":
    main()
