import sys

# Set recursion depth for the rc function.
# This is needed for deep recursion in rc() for high round indices.
sys.setrecursionlimit(2000)

##
## =================================================================
## 1. BACKEND: KECCAK-p[1600, 24] PERMUTATION
## (This is your existing, correct code)
## =================================================================
##

# --- 3.2 Step Mappings ---

def ROTL64(a, n):
    """Rotate 64-bit integer 'a' left by 'n' bits."""
    n = n % 64
    return ((a << n) & 0xFFFFFFFFFFFFFFFF) | (a >> (64 - n))

# Table 2: Offsets for rho
RHO_OFFSETS = [
    [0, 1, 190, 28, 91],
    [36, 300, 6, 55, 276],
    [3, 10, 171, 153, 231],
    [105, 45, 15, 21, 136],
    [210, 66, 253, 120, 78]
]

# Use memoization for rc(t) to avoid re-computation
RC_CACHE = {}

def rc(t):
    """ Algorithm 5: rc(t) - Round constant generation"""
    if t in RC_CACHE:
        return RC_CACHE[t]

    if t % 255 == 0:
        return 1

    # R = 10000000
    R = [1, 0, 0, 0, 0, 0, 0, 0]
    
    # For i from 1 to t mod 255
    for _ in range(t % 255):
        # R = 0 || R
        R.insert(0, 0)
        
        # [cite: 494-497] LFSR taps
        R[0] = R[0] ^ R[8]
        R[4] = R[4] ^ R[8]
        R[5] = R[5] ^ R[8]
        R[6] = R[6] ^ R[8]
        
        # R = Trunc_8(R)
        R = R[:8]
        
    # Return R[0]
    result = R[0]
    RC_CACHE[t] = result
    return result

def theta(A):
    """ Algorithm 1: theta"""
    C = [0] * 5
    D = [0] * 5
    A_out = [[0] * 5 for _ in range(5)]

    # Step 1
    for x in range(5):
        C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

    # Step 2
    for x in range(5):
        D[x] = C[(x - 1) % 5] ^ ROTL64(C[(x + 1) % 5], 1)

    # Step 3
    for x in range(5):
        for y in range(5):
            A_out[x][y] = A[x][y] ^ D[x]
            
    return A_out

def rho(A):
    """ Algorithm 2: rho"""
    A_out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            # Rotate lane by offset
            offset = RHO_OFFSETS[y][x] 
            A_out[x][y] = ROTL64(A[x][y], offset)
    return A_out

def pi(A):
    """ Algorithm 3: pi"""
    A_out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            # Step 1
            A_out[x][y] = A[(x + 3 * y) % 5][x]
    return A_out

def chi(A):
    """ Algorithm 4: chi"""
    A_out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            # Step 1
            A_out[x][y] = A[x][y] ^ (
                (~A[(x + 1) % 5][y] & 0xFFFFFFFFFFFFFFFF) & A[(x + 2) % 5][y]
            )
    return A_out

def iota(A, i_r):
    """ Algorithm 6: iota"""
    A_out = [row[:] for row in A] # Deep copy
    
    # Step 2: RC = 0^w
    RC_int = 0
    
    # Step 3: l=6
    for j in range(7): # 0 to l (which is 6)
        bit_pos = (1 << j) - 1 # 2^j - 1
        bit = rc(j + 7 * i_r)
        RC_int |= (bit << bit_pos)
        
    # Step 4
    A_out[0][0] = A_out[0][0] ^ RC_int
    return A_out

def Rnd(A, i_r):
    """ Round function"""
    A = theta(A)
    A = rho(A)
    A = pi(A)
    A = chi(A)
    A = iota(A, i_r)
    return A

# --- 3.1 State Conversions ---

def bytes_to_state(S_bytes):
    """ 3.1.2 Converting Strings to State Arrays"""
    A = [[0] * 5 for _ in range(5)]
    for y in range(5):
        for x in range(5):
            lane_bytes = S_bytes[(5 * y + x) * 8 : (5 * y + x) * 8 + 8]
            A[x][y] = int.from_bytes(lane_bytes, 'little')
    return A

def state_to_bytes(A):
    """ 3.1.3 Converting State Arrays to Strings"""
    S_bytes = bytearray(200)
    for y in range(5):
        for x in range(5):
            lane_bytes = A[x][y].to_bytes(8, 'little')
            S_bytes[(5 * y + x) * 8 : (5 * y + x) * 8 + 8] = lane_bytes
    return bytes(S_bytes)

def keccak_p(S_bytes):
    """ Algorithm 7: KECCAK-p[1600, 24]"""
    A = bytes_to_state(S_bytes)
    # 24 rounds (l=6, n_r=24 -> i_r from 0 to 23)
    for i_r in range(24):
        A = Rnd(A, i_r)
    S_prime_bytes = state_to_bytes(A)
    return S_prime_bytes

##
## =================================================================
## 2. 'Crypto.Hash'-style API CLASSES
## =================================================================
##

class KeccakSponge:
    """Base class for a stateful Keccak sponge."""
    
    def __init__(self, rate_bytes, suffix_type, data=None):
        self.state = bytearray(200)  # b = 1600 bits = 200 bytes
        self.absorb_buffer = bytearray() # Buffer for input data
        self.squeeze_buffer = bytearray() # Buffer for output data
        self.rate_bytes = rate_bytes
        self.suffix_type = suffix_type
        self.squeezing = False # Flag to prevent updates after squeezing

        if data is not None:
            self.update(data)

    def update(self, data):
        """Update the hash object with a bytestring."""
        if self.squeezing:
            raise TypeError("update() called after read() or digest()")
        
        self.absorb_buffer.extend(data)
        
        # Absorb full blocks from the buffer
        while len(self.absorb_buffer) >= self.rate_bytes:
            block = self.absorb_buffer[:self.rate_bytes]
            self.absorb_buffer = self.absorb_buffer[self.rate_bytes:]
            self._absorb_block(block)

    def _absorb_block(self, block):
        """Absorb a single block of rate_bytes."""
        for i in range(self.rate_bytes):
            self.state[i] ^= block[i]
        self.state = bytearray(keccak_p(self.state))

    def _pad_and_absorb_final(self):
        """Apply padding (Table 6) and absorb the final block."""
        if self.squeezing:
            return # Already padded and finalized

        m = len(self.absorb_buffer)
        q = self.rate_bytes - (m % self.rate_bytes) # num padding bytes
        
        if q == 1:
            # Hash: 0x86, XOF: 0x9F
            pad = b'\x86' if self.suffix_type == 'hash' else b'\x9F'
        else:
            # Hash: 0x06...0x80, XOF: 0x1F...0x80
            first = b'\x06' if self.suffix_type == 'hash' else b'\x1F'
            last = b'\x80'
            middle = b'\x00' * (q - 2)
            pad = first + middle + last
            
        final_padded_data = self.absorb_buffer + pad
        
        # Absorb the final padded block(s)
        for i in range(0, len(final_padded_data), self.rate_bytes):
            block = final_padded_data[i : i + self.rate_bytes]
            self._absorb_block(block)
            
        self.squeezing = True
        self.absorb_buffer = None # Clear absorb buffer

    def _squeeze(self, num_bytes):
        """Squeeze num_bytes from the sponge."""
        # Ensure padding is applied before squeezing
        self._pad_and_absorb_final()
        
        output = bytearray()
        
        # 1. First, drain any bytes left in the squeeze buffer
        if len(self.squeeze_buffer) > 0:
            take = min(num_bytes, len(self.squeeze_buffer))
            output.extend(self.squeeze_buffer[:take])
            self.squeeze_buffer = self.squeeze_buffer[take:]
            num_bytes -= take
            
        # 2. If we still need more bytes, generate new blocks
        while num_bytes > 0:
            # Extract the next block of output
            # (The state is already correct from the absorb phase
            # or the previous squeeze's permutation)
            new_block = self.state[:self.rate_bytes]
            
            # Permute the state for the *next* round
            self.state = bytearray(keccak_p(self.state))
            
            # Get the bytes we need and buffer the rest
            take = min(num_bytes, len(new_block))
            output.extend(new_block[:take])
            self.squeeze_buffer.extend(new_block[take:])
            num_bytes -= take
            
        return bytes(output)

class _Sha3Hash(KeccakSponge):
    """Internal base class for fixed-output SHA-3 hashes."""
    
    def __init__(self, output_bytes, rate_bytes, data=None):
        super().__init__(rate_bytes, 'hash', data)
        self.output_bytes = output_bytes
        self._digest_cache = None

    def digest(self):
        """Return the digest as a bytes object."""
        # Fixed hashes always return the same value
        if self._digest_cache:
            return self._digest_cache
        
        self._digest_cache = self._squeeze(self.output_bytes)
        return self._digest_cache

    def hexdigest(self):
        """Return the digest as a hex-encoded string."""
        return self.digest().hex()

class _ShakeXOF(KeccakSponge):
    """Internal base class for extendable-output (SHAKE) functions."""
    
    def __init__(self, rate_bytes, data=None):
        super().__init__(rate_bytes, 'xof', data)

    def read(self, length_bytes):
        """
        Return the next 'length_bytes' of the digest as a bytes object.
        """
        # XOFs continue squeezing, so we don't cache
        return self._squeeze(length_bytes)

##
## =================================================================
## 3. PUBLIC API CLASSES (SHA3)
## =================================================================
##

class SHA3_224(_Sha3Hash):
    """SHA3-224 hash object."""
    def __init__(self, data=None):
        # c = 448, r = 1600 - 448 = 1152 bits = 144 bytes
        super().__init__(output_bytes=28, rate_bytes=144, data=data)
    
    @classmethod
    def new(cls, data=None):
        """Return a new SHA3-224 hash object."""
        return cls(data)

class SHA3_256(_Sha3Hash):
    """SHA3-256 hash object."""
    def __init__(self, data=None):
        # c = 512, r = 1600 - 512 = 1088 bits = 136 bytes
        super().__init__(output_bytes=32, rate_bytes=136, data=data)
    
    @classmethod
    def new(cls, data=None):
        """Return a new SHA3-256 hash object."""
        return cls(data)

class SHA3_384(_Sha3Hash):
    """SHA3-384 hash object."""
    def __init__(self, data=None):
        # c = 768, r = 1600 - 768 = 832 bits = 104 bytes
        super().__init__(output_bytes=48, rate_bytes=104, data=data)
    
    @classmethod
    def new(cls, data=None):
        """Return a new SHA3-384 hash object."""
        return cls(data)

class SHA3_512(_Sha3Hash):
    """SHA3-512 hash object."""
    def __init__(self, data=None):
        # c = 1024, r = 1600 - 1024 = 576 bits = 72 bytes
        super().__init__(output_bytes=64, rate_bytes=72, data=data)
    
    @classmethod
    def new(cls, data=None):
        """Return a new SHA3-512 hash object."""
        return cls(data)

##
## =================================================================
## 4. PUBLIC API CLASSES (SHAKE)
## =================================================================
##

class SHAKE128(_ShakeXOF):
    """SHAKE128 XOF object."""
    def __init__(self, data=None):
        # c = 256, r = 1600 - 256 = 1344 bits = 168 bytes
        super().__init__(rate_bytes=168, data=data)

    @classmethod
    def new(cls, data=None):
        """Return a new SHAKE128 hash object."""
        return cls(data)

class SHAKE256(_ShakeXOF):
    """SHAKE256 XOF object."""
    def __init__(self, data=None):
        # c = 512, r = 1600 - 512 = 1088 bits = 136 bytes
        super().__init__(rate_bytes=136, data=data)

    @classmethod
    def new(cls, data=None):
        """Return a new SHAKE256 hash object."""
        return cls(data)


