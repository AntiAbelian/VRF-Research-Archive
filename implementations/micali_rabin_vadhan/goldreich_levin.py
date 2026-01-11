"""
goldreich_levin.py
Goldreich-Levin hardcore predicate utilities.

The GL theorem states: if f is a one-way function, then the inner product
⟨f(x), r⟩ over GF(2) is a hardcore predicate (pseudorandom bit).

For VRFs, we use GL to lift a VUF (unpredictable function) to a VRF
(pseudorandom function) by outputting the inner product of the VUF value
with a random string r.

Key insight:
    - VUF gives unpredictable value v ∈ {0,1}^b
    - GL says ⟨v, r⟩ is pseudorandom for random r ∈ {0,1}^b
    - Proof must reveal v (so verifier can check ⟨v, r⟩)
"""

import secrets
from typing import List


def inner_product_gf2(a: bytes, b: bytes) -> int:
    """
    Compute inner product of two byte strings over GF(2).
    
    Returns the XOR of all (a[i] & b[i]) bit-wise products.
    
    Args:
        a: First byte string
        b: Second byte string (must have same length as a)
    
    Returns:
        0 or 1 (the parity bit)
    
    Raises:
        ValueError: If lengths don't match
    """
    if len(a) != len(b):
        raise ValueError(f"Length mismatch: {len(a)} vs {len(b)}")
    
    result = 0
    for byte_a, byte_b in zip(a, b):
        # Compute bitwise AND, then XOR all bits
        product = byte_a & byte_b
        # Count number of 1-bits (parity)
        result ^= bin(product).count('1')
    
    return result & 1  # Return 0 or 1


def inner_product_gf2_bits(a_bits: List[int], b_bits: List[int]) -> int:
    """
    Compute inner product of two bit lists over GF(2).
    
    Args:
        a_bits: List of bits (0 or 1)
        b_bits: List of bits (0 or 1)
    
    Returns:
        0 or 1
    """
    if len(a_bits) != len(b_bits):
        raise ValueError(f"Length mismatch: {len(a_bits)} vs {len(b_bits)}")
    
    result = 0
    for a_bit, b_bit in zip(a_bits, b_bits):
        result ^= (a_bit & b_bit)
    
    return result & 1


def bytes_to_bits(data: bytes) -> List[int]:
    """
    Convert bytes to list of bits (MSB first).
    
    Args:
        data: Bytes to convert
    
    Returns:
        List of bits [0, 1, 0, 1, ...]
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):  # MSB to LSB
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """
    Convert list of bits to bytes (MSB first).
    
    Args:
        bits: List of bits (will be padded to multiple of 8)
    
    Returns:
        Bytes representation
    """
    # Pad to multiple of 8
    padding_needed = (8 - len(bits) % 8) % 8
    bits = bits + [0] * padding_needed
    
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    
    return bytes(result)


def generate_random_string(byte_length: int) -> bytes:
    """
    Generate a random byte string for GL construction.
    
    Args:
        byte_length: Number of random bytes to generate
    
    Returns:
        Random bytes
    """
    return secrets.token_bytes(byte_length)


# For testing
if __name__ == "__main__":
    print("Testing Goldreich-Levin utilities...")
    
    # Test inner product
    a = b'\x0f'  # 00001111
    b = b'\x55'  # 01010101
    
    # Expected: (0&0) ^ (0&1) ^ (0&0) ^ (0&1) ^ (1&0) ^ (1&1) ^ (1&0) ^ (1&1)
    #         = 0 ^ 0 ^ 0 ^ 0 ^ 0 ^ 1 ^ 0 ^ 1 = 0
    ip = inner_product_gf2(a, b)
    print(f"Inner product of {a.hex()} and {b.hex()}: {ip}")
    
    # Test with bits
    a_bits = bytes_to_bits(a)
    b_bits = bytes_to_bits(b)
    print(f"a bits: {a_bits}")
    print(f"b bits: {b_bits}")
    ip_bits = inner_product_gf2_bits(a_bits, b_bits)
    print(f"Inner product (bits): {ip_bits}")
    
    assert ip == ip_bits, "Byte and bit inner product should match"
    
    # Test round-trip conversion
    test_data = b"Hello, GL!"
    bits = bytes_to_bits(test_data)
    recovered = bits_to_bytes(bits)
    print(f"\nOriginal: {test_data}")
    print(f"Bits length: {len(bits)}")
    print(f"Recovered: {recovered}")
    assert test_data == recovered, "Round-trip conversion failed"
    
    # Test random string generation
    r = generate_random_string(32)
    print(f"\nRandom string (32 bytes): {r.hex()[:40]}...")
    
    print("\n✓ Goldreich-Levin utilities tests complete")