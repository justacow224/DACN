# REF: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf

# ML-KEM-512    -  AES-128
# ML-KEM-768    -  AES-192
# ML-KEM-1024   -  AES-256




# """
#     --- ML-KEM-512 constants (AES-128) ---

#     Required RBG strength (bits)      128
#     Encapsulation key sizes (bytes)   800
#     Decapsulation key sizes (bytes)   1632
#     Ciphertext sizes (bytes)          768
#     Shared secret key sizes (bytes)   32

# """
# n = 256
# q = 3329

# k = 2
# eta1 = 3
# eta2 = 2
# du = 10
# dv = 4






# """
#     --- ML-KEM-768 constants (AES-192) ---

#     Required RBG strength (bits)      192
#     Encapsulation key sizes (bytes)   1184
#     Decapsulation key sizes (bytes)   2400
#     Ciphertext sizes (bytes)          1088
#     Shared secret key sizes (bytes)   32

# """
# n = 256
# q = 3329

# k = 3
# eta1 = 2
# eta2 = 2
# du = 10
# dv = 4





"""
    --- ML-KEM-1024 constants (AES-256) ---

    Required RBG strength (bits)      256
    Encapsulation key sizes (bytes)   1568
    Decapsulation key sizes (bytes)   3168
    Ciphertext sizes (bytes)          1568
    Shared secret key sizes (bytes)   32

"""
n = 256
q = 3329

k = 4
eta1 = 2
eta2 = 2
du = 11
dv = 5