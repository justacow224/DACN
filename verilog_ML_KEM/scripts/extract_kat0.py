"""
Extract KAT vector #0 fields from KAT_768.txt into per-field .mem files
for SystemVerilog $readmemh consumption.

Output: verilog_ML_KEM/sim_1/new/kat0/{d,z,m,pk,sk,ct,ss}.mem
        — each file is one byte per line as 2-char hex, no comments,
        ready for $readmemh.

Run from repo root:
    python verilog_ML_KEM/scripts/extract_kat0.py

The TB tb_ml_kem_top.sv (Gate B branch) reads these files via $readmemh
to drive a real KAT regression instead of placeholder seeds.
"""
import os
import sys

KAT_PATH    = "verilog_ML_KEM/sim_1/new/KAT_768.txt"
OUT_DIR     = "verilog_ML_KEM/sim_1/new/kat0"
EXPECT_LEN  = {"d": 32, "z": 32, "m": 32, "pk": 1184, "sk": 2400, "ct": 1088, "ss": 32}


def parse_first_vector(path):
    fields = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                if fields:
                    return fields
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            fields[key.strip()] = val.strip()
    return fields


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
    if not os.path.exists(KAT_PATH):
        sys.exit(f"KAT file not found: {KAT_PATH}")
    os.makedirs(OUT_DIR, exist_ok=True)
    fields = parse_first_vector(KAT_PATH)
    print(f"Parsed KAT vec #0 from {KAT_PATH}, writing to {OUT_DIR}/")
    for name, n in EXPECT_LEN.items():
        if name not in fields:
            sys.exit(f"missing field '{name}' in vec #0")
        write_mem(name, fields[name], n)
    print("done.")


if __name__ == "__main__":
    main()
