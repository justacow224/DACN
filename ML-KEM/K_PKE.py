from GLOBAL import *
from SamplingAlgr import *
from CryptoFunc import *
from NTT import *
from GeneralAlgr import *

def KeyGen(d: bytes):
    """
    (Algorithm 13) Generates a public and private key pair for Kyber PKE.

    Args:
        d: A 32-byte random seed.

    Returns:
        A tuple (ek_PKE, dk_PKE) containing the public and private keys as bytes.
    """
    if len(d) != 32:
        raise ValueError("Input seed d must be 32 bytes.")

    # Step 1: Expand d into two 32-byte seeds
    rho, sigma = G(d)
    
    # Step 2: Initialize nonce N
    N = 0
    
    # Step 3-7: Generate matrix Â
    A_hat = [[None for _ in range(k)] for _ in range(k)]
    for i in range(k):
        for j in range(k):
            # Input to SampleNTT is rho || j || i
            input_bytes = rho + j.to_bytes(1, 'little') + i.to_bytes(1, 'little')
            A_hat[i][j] = SampleNTT(input_bytes)
            
    # Step 8-11: Generate secret vector s
    s = [None] * k
    for i in range(k):
        prf_output = PRF(eta1, sigma, N)
        s[i] = SamplePolyCBD(eta1, prf_output)
        N += 1
        
    # Step 12-15: Generate error vector e
    e = [None] * k
    for i in range(k):
        prf_output = PRF(eta1, sigma, N)
        e[i] = SamplePolyCBD(eta1, prf_output)
        N += 1
        
    # Step 16: Apply NTT to s
    s_hat = [NTT(poly) for poly in s]
    
    # Step 17: Apply NTT to e
    e_hat = [NTT(poly) for poly in e]
    
    # Step 18: Compute t̂ = Â ○ ŝ + ê
    t_hat = [([0] * 256) for _ in range(k)]
    for i in range(k):
        # Matrix-vector multiplication: a_row ○ s_hat
        row_result = MultiplyNTTs(A_hat[i][0], s_hat[0])
        for j in range(1, k):
            term = MultiplyNTTs(A_hat[i][j], s_hat[j])
            # Add component-wise
            row_result = [(x + y) % q for x, y in zip(row_result, term)]
        
        # Add error term: row_result + e_hat_i
        t_hat[i] = [(x + y) % q for x, y in zip(row_result, e_hat[i])]
        
    # Step 19: Form the public key ek_PKE
    # Concatenate the byte-encoded polynomials of t_hat
    ek_PKE_parts = [ByteEncode(12, poly) for poly in t_hat]
    ek_PKE = b"".join(ek_PKE_parts) + rho
    
    # Step 20: Form the private key dk_PKE
    # Concatenate the byte-encoded polynomials of s
    dk_PKE_parts = [ByteEncode(12, poly) for poly in s]
    dk_PKE = b"".join(dk_PKE_parts)
    
    # Step 21: Return key pair
    return (ek_PKE, dk_PKE)

def Encrypt(ek_PKE: bytes, m: bytes, r: bytes):
    """
    (Algorithm 14) Encrypts a message m using the Kyber PKE public key.
    
    Args:
        ek_PKE: The public key.
        m: The 32-byte message to encrypt.
        r: A 32-byte random seed.

    Returns:
        The ciphertext c as bytes.
    """
    if len(m) != 32 or len(r) != 32:
        raise ValueError("Message and randomness must both be 32 bytes.")

    # Step 1: Initialize nonce
    N = 0
    
    # Step 2-3: Decode public key
    pk_len = 384 * k
    t_hat_bytes, rho = ek_PKE[:pk_len], ek_PKE[pk_len:]
    t_hat = [ByteDecode(12, t_hat_bytes[i*384:(i+1)*384]) for i in range(k)]

    # Step 4-8: Re-generate matrix Â from seed ρ
    A_hat = [[SampleNTT(rho + j.to_bytes(1,'little') + i.to_bytes(1,'little')) for j in range(k)] for i in range(k)]
    
    # Step 9-11: Generate ephemeral secret y
    y = [SamplePolyCBD(eta1, PRF(eta1, r, N + i)) for i in range(k)]; N += k
    
    # Step 12-14: Generate error vector e₁
    e1 = [SamplePolyCBD(eta2, PRF(eta2, r, N + i)) for i in range(k)]; N += k
    # Step 15-16: Generate error polynomial e₂
    e2 = SamplePolyCBD(eta2, PRF(eta2, r, N))
    
    # Step 17: Apply NTT to y
    y_hat = [NTT(p) for p in y]
    
    # Step 18-19: Compute u = NTT⁻¹(Âᵀ ○ ŷ) + e₁
    u = [([0] * 256) for _ in range(k)]
    for i in range(k):
        # Transposed matrix-vector multiplication
        row_res = MultiplyNTTs(A_hat[0][i], y_hat[0])
        for j in range(1, k):
            term = MultiplyNTTs(A_hat[j][i], y_hat[j])
            row_res = [(x + y) % q for x, y in zip(row_res, term)]

        u_poly = invNTT(row_res)
        u[i] = [(x + y) % q for x, y in zip(u_poly, e1[i])]
        
    # Step 20: Encode message m into polynomial v
    m_poly_uncompressed = ByteDecode(1, m)
    v = [decompress(1, bit) for bit in m_poly_uncompressed]
    
    # Step 21: Compute v' = NTT⁻¹(t̂ᵀ ○ ŷ) + e₂ + v
    # Dot product in NTT domain
    dot_prod = MultiplyNTTs(t_hat[0], y_hat[0])
    for i in range(1, k):
        term = MultiplyNTTs(t_hat[i], y_hat[i])
        dot_prod = [(x + y) % q for x, y in zip(dot_prod, term)]
    
    v_poly = invNTT(dot_prod)
    v_prime = [(v_poly[i] + e2[i] + v[i]) % q for i in range(256)]
    
    # Step 22: Compress and encode u into c₁
    u_compressed = [[compress(du, coeff) for coeff in poly] for poly in u]
    c1_parts = [ByteEncode(du, poly) for poly in u_compressed]
    c1 = b"".join(c1_parts)
    
    # Step 23: Compress and encode v' into c₂
    v_prime_compressed = [compress(dv, coeff) for coeff in v_prime]
    c2 = ByteEncode(dv, v_prime_compressed)
    
    # Step 24: Return ciphertext
    return c1 + c2

def Decrypt(dk_PKE: bytes, c: bytes):
    """
    (Algorithm 15) Decrypts a Kyber PKE ciphertext.
    
    Args:
        dk_PKE: The private key.
        c: The ciphertext.
    
    Returns:
        The decrypted 32-byte message.
    """
    # Step 1-2: Split ciphertext into c1 and c2
    c1_len = 32 * du * k
    c1 = c[:c1_len]
    c2 = c[c1_len:]

    # Step 3: Decode and decompress u'
    u_compressed = [ByteDecode(du, c1[i*32*du:(i+1)*32*du]) for i in range(k)]
    u_prime = [[decompress(du, coeff) for coeff in poly] for poly in u_compressed]
    
    # Step 4: Decode and decompress v'
    v_prime_compressed = ByteDecode(dv, c2)
    v_prime = [decompress(dv, coeff) for coeff in v_prime_compressed]
    
    # Step 5: Decode the private key s (it's already in NTT form)
    s_poly = [ByteDecode(12, dk_PKE[i*384:(i+1)*384]) for i in range(k)]

    s_hat = [NTT(p) for p in s_poly]
    
    # Step 6: Compute w = v' - NTT⁻¹(ŝᵀ ○ NTT(u'))
    u_prime_hat = [NTT(p) for p in u_prime]
    
    # Dot product in NTT domain: ŝᵀ ○ u'
    dot_prod = MultiplyNTTs(s_hat[0], u_prime_hat[0])
    for i in range(1, k):
        term = MultiplyNTTs(s_hat[i], u_prime_hat[i])
        dot_prod = [(x + y) % q for x, y in zip(dot_prod, term)]
        
    w_poly_sub = invNTT(dot_prod)
    
    w = [(v_prime[i] - w_poly_sub[i]) % q for i in range(256)]
    
    # Step 7: Compress w to recover message bits, then encode to bytes
    message_bits = [compress(1, coeff) for coeff in w]
    m = ByteEncode(1, message_bits)
    
    # Step 8: Return the message
    return m

