import K_PKE
from CryptoFunc import *

def KeyGen_internal(d: bytes, z: bytes):
    """
    (Algorithm 16) Generates encapsulation and decapsulation keys for ML-KEM.
    
    Args:
        d: A 32-byte random seed for the PKE key generation.
        z: A 32-byte random seed for the KEM private key.
        
    Returns:
        A tuple (ek, dk) containing the KEM public and private keys as bytes.
    """
    if len(d) != 32 or len(z) != 32:
        raise ValueError("Randomness inputs d and z must both be 32 bytes.")

    # Step 1: Generate the underlying PKE key pair
    ek_PKE, dk_PKE = K_PKE.KeyGen(d)
    
    # Step 2: The KEM encapsulation key is just the PKE encryption key
    ek = ek_PKE
    
    # Step 3: The KEM decapsulation key is the concatenation of:
    #         - PKE decryption key (dk_PKE)
    #         - The full encapsulation key (ek)
    #         - The hash of the encapsulation key (H(ek))
    #         - The random seed z
    # Note: The spec diagram for Alg 16 simplifies the dk content.
    # The full FIPS 203 spec (Section 6.1) clarifies it also includes `ek`.
    dk = dk_PKE + ek + H(ek) + z
    
    # Step 4: Return the KEM key pair
    return (ek, dk)

def Encaps_internal(ek: bytes, m: bytes):
    """
    (Algorithm 17) Generates a shared secret and a ciphertext for ML-KEM.

    Args:
        ek: The KEM public key (encapsulation key).
        m: A 32-byte random seed.

    Returns:
        A tuple (K, c) containing the 32-byte shared secret and the ciphertext.
    """
    if len(m) != 32:
        raise ValueError("Randomness input m must be 32 bytes.")

    # Step 1: Derive the shared secret K and PKE randomness r
    # K and r are derived from the input randomness m and a hash of the public key.
    K, r = G(m + H(ek))
    
    # Step 2: Encrypt m using the PKE scheme with the derived randomness r
    # This creates the ciphertext c that will be sent to the other party.
    c = K_PKE.Encrypt(ek, m, r)
    
    # Step 3: Return the shared secret and the ciphertext
    return (K, c)

def Decaps_internal(dk: bytes, c: bytes):
    """
    (Algorithm 18) Derives a shared secret from a ciphertext using the ML-KEM private key.
    
    Args:
        dk: The KEM private key (decapsulation key).
        c: The ciphertext.
        
    Returns:
        The 32-byte shared secret K'.
    """
    # Step 1-4: Parse the decapsulation key dk
    dk_PKE = dk[0:384*k]
    ek_PKE = dk[384*k : 768*k + 32]
    h = dk[768*k + 32 : 768*k + 64]
    z = dk[768*k + 64 : 768*k + 96]
    
    # Step 5: Decrypt the ciphertext to get the candidate message m'
    m_prime = K_PKE.Decrypt(dk_PKE, c)
    
    # Step 6: Derive candidate shared secret K' and randomness r' from m'
    K_prime, r_prime = G(m_prime + h)
    
    # Step 8: Re-encrypt m' with the derived randomness r'
    c_prime = K_PKE.Encrypt(ek_PKE, m_prime, r_prime)
    
    # Step 9-11: Compare ciphertexts for implicit rejection
    if c != c_prime:
        # If they don't match, overwrite K' with a value derived from z
        K_prime = J(z + c)
        
    # Step 12: Return the final shared secret
    return K_prime