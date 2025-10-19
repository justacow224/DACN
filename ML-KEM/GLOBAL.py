# REF: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf

# ML-KEM-512    -  AES-128
# ML-KEM-768    -  AES-192
# ML-KEM-1024   -  AES-256

ML_KEM_512      = 0
ML_KEM_768      = 1
ML_KEM_1024     = 2

ML_KEM_PARAMS = ML_KEM_512





















if ML_KEM_PARAMS == ML_KEM_512:
    """
        --- ML-KEM-512 constants (AES-128) ---

        Required RBG strength (bits)      128
        Encapsulation key sizes (bytes)   800
        Decapsulation key sizes (bytes)   1632
        Ciphertext sizes (bytes)          768
        Shared secret key sizes (bytes)   32

    """
    n = 256
    q = 3329
    k = 2
    eta1 = 3
    eta2 = 2
    du = 10
    dv = 4
    TEST_FILENAME = "KAT_512.txt"


elif ML_KEM_PARAMS == ML_KEM_768:
    """
        --- ML-KEM-768 constants (AES-192) ---

        Required RBG strength (bits)      192
        Encapsulation key sizes (bytes)   1184
        Decapsulation key sizes (bytes)   2400
        Ciphertext sizes (bytes)          1088
        Shared secret key sizes (bytes)   32

    """
    n = 256
    q = 3329
    k = 3
    eta1 = 2
    eta2 = 2
    du = 10
    dv = 4
    TEST_FILENAME = "KAT_768.txt"


elif ML_KEM_PARAMS == ML_KEM_1024:
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
    TEST_FILENAME = "KAT_1024.txt"


else:
    raise Exception("PLEASE DEFINE ML-KEM PARAMETER SET")