from GLOBAL import *
from CryptoFunc import XOF
from numba import jit


def SampleNTT(B: bytes) -> list[int]:
    """
    (Algorithm 7) Samples a polynomial â ∈ Z_q^256 in the NTT domain.

    Args:
        B: A 34-byte input array (32-byte seed + 2-byte index).

    Returns:
        An array of 256 integer coefficients.
    """
    if len(B) != 34:
        raise ValueError("Input byte array B must be 34 bytes long.")

    xof = XOF()
    xof.Absorb(B)
    a_hat = [0] * 256
    j = 0
    
    while j < 256:
        # Squeeze 3 bytes from the XOF stream
        C = xof.Squeeze(3)

        # Unpack two 12-bit integers d1, d2 from the 3 bytes
        d1 = C[0] + 256 * (C[1] % 16)
        d2 = (C[1] // 16) + 16 * C[2]
        
        # Add d1 to the polynomial if it's in the valid range
        if d1 < q:
            a_hat[j] = d1
            j += 1
        
        # Add d2 if it's valid and we still need coefficients
        if j < 256 and d2 < q:
            a_hat[j] = d2
            j += 1
            
    return a_hat


# ASSERTED
@jit(nopython=True, cache=True)
def SamplePolyCBD(eta: int, B: bytes) -> list[int]:
    """
    (Algorithm 8) Samples a polynomial f from the centered binomial distribution D_η.

    Args:
        eta: The distribution parameter, must be 2 or 3.
        B: A byte array of length 64 * eta.

    Returns:
        An array of 256 integer coefficients.
    """
    if eta not in [2, 3]:
        raise ValueError("Parameter eta must be 2 or 3.")
    expected_len = 64 * eta
    if len(B) != expected_len:
        raise ValueError(f"Input byte array B must have length {expected_len}.")

    ### NON NUMBA ###
    # bits = GeneralAlgr.BytesToBits(B)


    ### NUMBA ###
    bits = [0] * (len(B) * 8)
    for i in range(len(B)):
        for j in range(8):
            bits[i*8 + j] = (B[i] >> j) & 1
    f = [0] * 256
    
    for i in range(256):
        ### NON NUMBA ###
        # # The number of bits needed per coefficient is 2 * eta
        # offset = 2 * i * eta
        
        # # Sum of the first eta bits
        # x1 = sum(bits[offset + j] for j in range(eta))
        # # Sum of the next eta bits
        # y1 = sum(bits[offset + eta + j] for j in range(eta))


        ### NUMBA ###
        x = 0
        y = 0
        for j in range(eta):
            x += bits[2 * i * eta + j]
            y += bits[2 * i * eta + eta + j]
        f[i] = (x - y) % q
        
    return f