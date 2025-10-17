# REF: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf

# ML-KEM-512    -  AES-128
# ML-KEM-768    -  AES-192
# ML-KEM-1024   -  AES-256

# Currently defined for ML-KEM-512 only
# ML-KEM-512 constants (AES-128)
n = 256
q = 3329

k = 4
eta1 = 2
eta2 = 2
du = 11
dv = 5

# Required RBG strength (bits)      128
# Encapsulation key sizes (bytes)   800
# Decapsulation key sizes (bytes)   1632
# Ciphertext sizes (bytes)          768
# Shared secret key sizes (bytes)   32