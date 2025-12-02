import os
from . import ML_KEM_internal



def KeyGen():
    """
    (Algorithm 19) Generates an encapsulation key and a corresponding
    decapsulation key for ML-KEM.
    
    Returns:
        A tuple (ek, dk) containing the KEM public and private keys as bytes,
        or raises an exception if randomness generation fails.
    """
    # Step 1-2: Generate 32 random bytes for d and z
    try:
        d = os.urandom(32)
        z = os.urandom(32)
    except Exception as e:
        # Step 3-5: Handle potential failure in random byte generation
        raise RuntimeError("Failed to generate random bytes from OS.") from e

    # Step 6: Run the internal key generation algorithm
    ek, dk = ML_KEM_internal.KeyGen_internal(d, z)
    
    # Step 7: Return the key pair
    return (ek, dk)

def Encaps(ek: bytes):
    """
    (Algorithm 20) Generates a shared secret and an associated ciphertext.

    Args:
        ek: The KEM public key (encapsulation key).

    Returns:
        A tuple (K, c) containing the 32-byte shared secret and the ciphertext,
        or raises an exception if randomness generation fails.
    """
    # Step 1: Generate 32 random bytes for m
    try:
        m = os.urandom(32)
    except Exception as e:
        # Step 2-4: Handle potential failure in random byte generation
        raise RuntimeError("Failed to generate random bytes from OS.") from e

    # Step 5: Run the internal encapsulation algorithm
    shared_secret, ciphertext = ML_KEM_internal.Encaps_internal(ek, m)
    
    # Step 6: Return the shared secret and ciphertext
    return (shared_secret, ciphertext)

def Decaps(dk: bytes, c: bytes):
    """
    (Algorithm 21) Produces a shared secret key from a ciphertext
    using the decapsulation key.

    Args:
        dk: The KEM private key (decapsulation key).
        c: The ciphertext.

    Returns:
        The 32-byte shared secret K'.
    """
    # Step 1: Run the internal decapsulation algorithm
    shared_secret = ML_KEM_internal.Decaps_internal(dk, c)
    
    # Step 2: Return the shared secret
    return shared_secret