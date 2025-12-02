from .GLOBAL import *
from Crypto.Hash import SHAKE256, SHAKE128, SHA3_256, SHA3_512
from .SHA3 import (
    SHAKE256 as my_SHAKE256,
    SHAKE128 as my_SHAKE128,
    SHA3_256 as my_SHA3_256,
    SHA3_512 as my_SHA3_512
)

LIB_HASH    = 0
MY_HASH     = 1


HASH_MODE   = LIB_HASH

def PRF(eta: int, s: bytes, b: int) -> bytes:
    """
    Implements the PRF as defined by SHAKE256(s || b, 8 * 64 * eta).

    Args:
        eta: The distribution parameter, must be 2 or 3.
        s: A 32-byte input string.
        b: A 1-byte input, represented as an integer (0-255).

    Returns:
        A (64 * eta)-byte output.
        
    Raises:
        ValueError: If the inputs do not meet the specified constraints.
    """
    # 1. Validate the inputs to ensure they match the specification
    if eta not in [2, 3]:
        raise ValueError("Parameter eta (η) must be 2 or 3.")
    if not isinstance(s, bytes) or len(s) != 32:
        raise ValueError("Input s must be a 32-byte bytes object.")
    if not isinstance(b, int) or not (0 <= b <= 255):
        raise ValueError("Input b must be an integer between 0 and 255.")

    # 2. Calculate the desired output length in bytes
    output_length_bytes = 64 * eta

    # 3. Convert the integer b to a single byte
    b_byte = b.to_bytes(1, 'little')

    # 4. Concatenate s and b
    input_data = s + b_byte

    # 5. Instantiate SHAKE256, update it with the concatenated data,
    #    and generate the digest of the required length.

    if HASH_MODE == LIB_HASH:
        return SHAKE256.new(input_data).read(output_length_bytes)
    
    elif HASH_MODE == MY_HASH:
        return my_SHAKE256.new(input_data).read(output_length_bytes)
    else:
        raise Exception("Please choose Hash Library")



def H(s: bytes) -> bytes:
    """
    Implements the hash function H(s) := SHA3-256(s).

    Args:
        s: A variable-length byte string.

    Returns:
        A 32-byte hash digest.
    """
    if HASH_MODE == LIB_HASH:
        return SHA3_256.new(s).digest()
    elif HASH_MODE == MY_HASH:
        return my_SHA3_256.new(s).digest()
    else:
        raise Exception("Please choose Hash Library")

def J(s: bytes) -> bytes:
    """
    Implements the hash function J(s) := SHAKE256(s, 8 * 32).

    Args:
        s: A variable-length byte string.

    Returns:
        A 32-byte hash digest.
    """
    # The output length is 32 bytes (256 bits)
    output_length_bytes = 32

    if HASH_MODE == LIB_HASH:
        return SHAKE256.new(s).read(output_length_bytes)
    elif HASH_MODE == MY_HASH:
        return my_SHAKE256.new(s).read(output_length_bytes)
    else:
        raise Exception("Please choose Hash Library")
    

def G(c: bytes) -> tuple[bytes, bytes]:
    """
    Implements the hash function G(c) := SHA3-512(c).
    The 64-byte output is split into two 32-byte outputs.

    Args:
        c: A variable-length byte string.

    Returns:
        A tuple containing two 32-byte hash digests (a, b).
    """
    # SHA3-512 produces a 64-byte digest
    full_digest = None
    if HASH_MODE == LIB_HASH:
        full_digest = SHA3_512.new(c).digest()
    elif HASH_MODE == MY_HASH:
        full_digest = my_SHA3_512.new(c).digest()
    else:
        raise Exception("Please choose Hash Library")
    

    # Split the 64-byte digest into two 32-byte chunks
    a = full_digest[:32]
    b = full_digest[32:]
    
    return (a, b)

class XOF:
    """
    A wrapper for SHAKE128 to match the incremental API defined in the spec.
    XOF.Init()      ->  XOF()
    XOF.Absorb()    ->  xof_instance.absorb()
    XOF.Squeeze()   ->  xof_instance.squeeze()
    """
    def __init__(self):
        """
        Initializes the XOF context. This corresponds to XOF.Init().
        """
        # The shake_128 object holds the internal state (ctx)
        if HASH_MODE == LIB_HASH:
            self._ctx = SHAKE128.new()
        elif HASH_MODE == MY_HASH:
            self._ctx = my_SHAKE128.new()
        else:
            raise Exception("Please choose Hash Library")
        

    def Absorb(self, data: bytes):
        """
        Absorbs an input byte string into the XOF state.
        This corresponds to XOF.Absorb(ctx, str).

        Args:
            data: The input bytes to absorb.
        """
        self._ctx.update(data)

    def Squeeze(self, num_bytes: int):
        """
        Squeezes a specified number of bytes from the XOF state.
        This corresponds to XOF.Squeeze(ctx, l).

        Args:
            num_bytes: The number of output bytes to generate.

        Returns:
            The generated output as a bytes object.
        """
        return self._ctx.read(num_bytes)

