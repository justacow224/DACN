from GLOBAL import *


def bit_reverse(n, bits):
    """Reverses the bits of an integer."""
    rev = 0
    for _ in range(bits):
        rev <<= 1
        if n & 1 == 1:
            rev |= 1
        n >>= 1
    return rev

# Precomputed tables for zeta values
# ZETAS are used for NTT (Algorithm 9) and InverseNTT (Algorithm 10)
# The values are ζ^BitRev_7(i) mod q for i = 0,...,127
ZETAS = [pow(17, bit_reverse(i, 7), q) for i in range(128)]

# GAMMAS are used for BaseCaseMultiply (Algorithm 12) inside MultiplyNTTs
# The values are ζ^(2*BitRev_7(i)+1) mod q
GAMMAS = [pow(17, 2 * bit_reverse(i, 7) + 1, q) for i in range(128)]

# Scaling factor for InverseNTT
F = 3303 # This is 128^-1 mod 3329

def NTT(f):
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
def invNTT(f_hat):
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

def MultiplyNTTs(f_hat, g_hat):
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
        c0, c1 = BaseCaseMultiply(a0, a1, b0, b1, gamma)
        
        # Pack the results back into the output array
        h_hat[2 * i] = c0
        h_hat[2 * i + 1] = c1
        
    return h_hat

def BaseCaseMultiply(a0, a1, b0, b1, y):
    """
    (Algorithm 12) Computes the product of two degree-one polynomials.
    This corresponds to (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma).
    """
    c0 = (a0 * b0 + a1 * b1 * y) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1

