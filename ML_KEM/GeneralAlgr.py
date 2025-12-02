from .GLOBAL import *
from numba import jit


# ASSERTED
@jit(nopython=True, cache=True)
def BitsToBytes(b: list[int]) -> bytes:
    """
    Converts a bit array into a byte array using little-endian bit packing.

    Args:
        b: A list of bits (0s or 1s). Its length must be a multiple of 8.

    Returns:
        A bytes object representing the packed bits.
        
    Raises:
        ValueError: If the input list length is not a multiple of 8.
    """
    
    if len(b) % 8 != 0:
        raise ValueError("Input bit array length must be a multiple of 8.")

    ### NON NUMBA ###
    # byte_array = bytearray()
    
    # # Process the bit array in chunks of 8
    # for i in range(0, len(b), 8):
    #     chunk = b[i : i+8]
        
    #     # Calculate the integer value of the 8 bits (little-endian)
    #     byte_val = 0
    #     for j in range(8):
    #         # b[0] is LSB, b[7] is MSB
    #         byte_val += chunk[j] * (2**j)
            
    #     byte_array.append(byte_val)
        
    # return bytes(byte_array)


    ### NUMBA ###
    num_bytes = len(b) // 8
    byte_list = [0] * num_bytes
    
    for i in range(num_bytes):
        val = 0
        for j in range(8):
            val += b[i * 8 + j] * (1 << j)
        byte_list[i] = val
            
    # Numba can't return `bytes`, so we return a list of ints
    # The final conversion happens outside the jitted function

    return byte_list



# ASSERTED
@jit(nopython=True, cache=True)
def BytesToBits(B: bytes) -> list[int]:
    """
    Converts a byte array into a bit array using little-endian bit unpacking.

    Args:
        B: A bytes object.

    Returns:
        A list of bits (0s or 1s) representing the unpacked bytes.
    """
    ### NON NUMBA ###
    # bit_array = []
    
    # # Iterate through each byte in the input
    # for byte_val in B:
    #     # Extract the 8 bits for the current byte (little-endian)
    #     for j in range(8):
    #         # Extract j-th bit and append. (byte >> j) & 1 gets the LSB first.
    #         bit = (byte_val >> j) & 1
    #         bit_array.append(bit)
            
    # return bit_array



    ### NUMBA ###
    bit_list = [0] * (len(B) * 8)
    for i in range(len(B)):
        byte_val = B[i]
        for j in range(8):
            bit_list[i * 8 + j] = (byte_val >> j) & 1

    return bit_list

@jit(nopython=True, cache=True)
def compress(d: int, x: int) -> int:
    """
    Implements the Compress function from the specification.
    Compress_d(x) = round((2^d / q) * x) mod 2^d
    
    Args:
        d: The compression parameter (d < 12).
        x: The integer to compress (0 <= x < 3329).

    Returns:
        The compressed integer.
    """
    
    # Using integer arithmetic for round((2**d * x) / Q)
    # This is equivalent to floor(((2**d * x * 2) + Q) / (2 * Q))
    # or more simply ((2**d * x) + (Q // 2)) // Q
    
    two_d = 1 << d  # Efficient way to calculate 2**d
    
    # Step 1: Perform the scaled multiplication and rounding
    compressed_val = (((x * two_d) + (q // 2)) // q)
    
    # Step 2: Apply the modulo
    return compressed_val % two_d

@jit(nopython=True, cache=True)
def decompress(d: int, y: int) -> int:
    """
    Implements the Decompress function from the specification.
    Decompress_d(y) = round((q / 2^d) * y)
    
    Args:
        d: The compression parameter (d < 12).
        y: The integer to decompress (0 <= y < 2**d).

    Returns:
        The decompressed integer.
    """
    
    two_d = 1 << d # Efficient way to calculate 2**d
    
    # Using integer arithmetic for round((Q * y) / 2**d)
    # This is equivalent to ((Q * y) + (2**(d-1))) // 2**d
    decompressed_val = ((q * y) + (two_d >> 1)) // two_d
    
    return decompressed_val

@jit(nopython=True, cache=True)
def ByteEncode(d: int, F: list[int]) -> bytes:
    """
    (Algorithm 5) Encodes an array of 256 d-bit integers into a byte array.
    """
    if not (1 <= d <= 12):
        raise ValueError("Parameter d must be between 1 and 12.")
    if len(F) != 256:
        raise ValueError("Input array F must have 256 integers.")
    
    # Total number of bits will be 256 * d
    bits = [0] * (256 * d)
    
    for i in range(256):
        a = F[i]
        for j in range(d):
            # Extract the LSB (a mod 2) and place it in the bit array
            bits[i * d + j] = a & 1
            # Integer division by 2 (equivalent to a right shift)
            a >>= 1
            
    return BitsToBytes(bits)

@jit(nopython=True, cache=True)
def ByteDecode(d: int, B: bytes) -> list[int]:
    """
    (Algorithm 6) Decodes a byte array into an array of 256 d-bit integers.
    """
    if not (1 <= d <= 12):
        raise ValueError("Parameter d must be between 1 and 12.")
    expected_len = 32 * d
    if len(B) != expected_len:
         raise ValueError(f"Input byte array B must have length {expected_len}.")

    bits = BytesToBits(B)
    F = [0] * 256
    
    for i in range(256):
        val = 0
        # Reconstruct the integer from its d little-endian bits
        for j in range(d):
            val += bits[i * d + j] * (1 << j) # (2**j)
        
        # As per the specification, for d=12, the result is reduced modulo q.
        if d == 12:
            F[i] = val % q
        else:
            F[i] = val
            
    return F