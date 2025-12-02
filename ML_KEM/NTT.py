from .GLOBAL import *
from numba import jit

# @jit(nopython=True)
# def bit_reverse(n, bits):
#     """Reverses the bits of an integer."""
#     rev = 0
#     for _ in range(bits):
#         rev <<= 1
#         if n & 1 == 1:
#             rev |= 1
#         n >>= 1
#     return rev

# # Precomputed tables for zeta values
# # ZETAS are used for NTT (Algorithm 9) and InverseNTT (Algorithm 10)
# # The values are ζ^BitRev_7(i) mod q for i = 0,...,127
# ZETAS = [pow(17, bit_reverse(i, 7), q) for i in range(128)]



# # GAMMAS are used for BaseCaseMultiply (Algorithm 12) inside MultiplyNTTs
# # The values are ζ^(2*BitRev_7(i)+1) mod q
# GAMMAS = [pow(17, 2 * bit_reverse(i, 7) + 1, q) for i in range(128)]

ZETAS = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
]

GAMMAS = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154
]




# GAMMAS are used for BaseCaseMultiply (Algorithm 12) inside MultiplyNTTs
# The values are ζ^(2*BitRev_7(i)+1) mod q


# Scaling factor for InverseNTT
F = 3303 # This is 128^-1 mod 3329



def NTT(f: list[int]) -> list[int]:
    """
    (Algorithm 9) Computes the Number-Theoretic Transform (NTT).
    """


    f_hat = f[:] # Work on a copy
    k = 0
    
    # Iterate through layers of the butterfly network
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            k += 1
            zeta = ZETAS[k] # Get precomputed twiddle factor
            
            for j in range(start, start + length):
                # Butterfly operation
                t = (zeta * f_hat[j + length]) % q
                f_hat[j + length] = (f_hat[j] - t) % q
                f_hat[j] = (f_hat[j] + t) % q
            
            start += 2 * length
        length //= 2
        
    return f_hat

def invNTT(f_hat: list[int]) -> list[int]:
    """
    (Algorithm 10) Computes the Inverse Number-Theoretic Transform (NTT⁻¹).
    """
    f = f_hat[:] # Work on a copy
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = ZETAS[k] # Get precomputed twiddle factor
            k -= 1
            
            for j in range(start, start + length):
                # Inverse butterfly operation
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = (zeta * (f[j + length] - t)) % q
            
            start += 2 * length
        length *= 2
    
    # Final scaling
    return [(v * F) % q for v in f]



def MultiplyNTTs(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """
    (Algorithm 11) Computes the product of two NTT representations.
    """


    h_hat = [0] * 256
    for i in range(128):
        # Unpack coefficients for the i-th component
        a0, a1 = f_hat[2 * i], f_hat[2 * i + 1]
        b0, b1 = g_hat[2 * i], g_hat[2 * i + 1]
        
        # Get the precomputed gamma for this component
        gamma = GAMMAS[i]
        
        # Perform the base case multiplication
        ### NON NUMBA ###
        c0, c1 = BaseCaseMultiply(a0, a1, b0, b1, gamma)


        # ### NUMBA ###
        # c0 = (a0 * b0 + a1 * b1 * gamma) % q
        # c1 = (a0 * b1 + a1 * b0) % q
        
        # Pack the results back into the output array
        h_hat[2 * i] = c0
        h_hat[2 * i + 1] = c1
        
    return h_hat

@jit(nopython=True, cache=True)
def BaseCaseMultiply(a0, a1, b0, b1, y):
    """
    (Algorithm 12) Computes the product of two degree-one polynomials.
    This corresponds to (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma).
    """
    c0 = (a0 * b0 + a1 * b1 * y) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1

