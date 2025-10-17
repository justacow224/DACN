import hashlib

def PRF(eta: int, s: bytes, b: int) -> bytes:
    """
    Implements the PRF as defined by SHAKE256(s || b, 8 * 64 * eta).

    Args:
        eta: An integer, must be 2 or 3. It determines the output length.
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
    b_byte = b.to_bytes(1, 'big')

    # 4. Concatenate s and b
    input_data = s + b_byte

    # 5. Instantiate SHAKE256, update it with the concatenated data,
    #    and generate the digest of the required length.
    shake = hashlib.shake_256()
    shake.update(input_data)
    
    return shake.digest(output_length_bytes)

import hashlib

def H(s: bytes) -> bytes:
    """
    Implements the hash function H(s) := SHA3-256(s).

    Args:
        s: A variable-length byte string.

    Returns:
        A 32-byte hash digest.
    """
    return hashlib.sha3_256(s).digest()

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
    return hashlib.shake_256(s).digest(output_length_bytes)

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
    full_digest = hashlib.sha3_512(c).digest()
    
    # Split the 64-byte digest into two 32-byte chunks
    a = full_digest[:32]
    b = full_digest[32:]
    
    return (a, b)

import hashlib

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
        self._ctx = hashlib.shake_128()

    def absorb(self, data: bytes):
        """
        Absorbs an input byte string into the XOF state.
        This corresponds to XOF.Absorb(ctx, str).

        Args:
            data: The input bytes to absorb.
        """
        self._ctx.update(data)

    def squeeze(self, num_bytes: int) -> bytes:
        """
        Squeezes a specified number of bytes from the XOF state.
        This corresponds to XOF.Squeeze(ctx, ℓ).

        Args:
            num_bytes: The number of output bytes to generate.

        Returns:
            The generated output as a bytes object.
        """
        return self._ctx.digest(num_bytes)

