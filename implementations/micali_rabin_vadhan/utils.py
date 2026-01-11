"""
utils.py
Utility functions for the Micali-Rabin-Vadhan VRF implementation.

Provides:
    - RSA modulus and prime generation
    - Indexer function (maps input to prime exponent)
    - Modular arithmetic helpers
    - Encoding/serialization utilities
"""

import hashlib
import secrets
from typing import Tuple
from math import gcd


def int_to_bytes(n: int, length: int = None) -> bytes:
    """
    Convert a non-negative integer to bytes (big-endian).
    
    Args:
        n: Non-negative integer
        length: Optional fixed byte length (pads with zeros if needed)
    
    Returns:
        bytes representation
    """
    if length is None:
        # Calculate minimum bytes needed
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """
    Convert bytes to a non-negative integer (big-endian).
    
    Args:
        b: Bytes to convert
    
    Returns:
        Integer representation
    """
    return int.from_bytes(b, byteorder='big')


def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Modular exponentiation: base^exp mod mod.
    
    Args:
        base: Base value
        exp: Exponent
        mod: Modulus
    
    Returns:
        base^exp mod mod
    """
    return pow(base, exp, mod)


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm.
    
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular inverse of a modulo m.
    
    Args:
        a: Integer to invert
        m: Modulus
    
    Returns:
        x such that (a * x) % m == 1
    
    Raises:
        ValueError: If gcd(a, m) != 1
    """
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return (x % m + m) % m


def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    
    Args:
        n: Number to test
        k: Number of rounds (higher = more accurate)
    
    Returns:
        True if n is probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # Random in [2, n-2]
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bit_length: int) -> int:
    """
    Generate a random prime of specified bit length.
    
    Args:
        bit_length: Desired bit length of the prime
    
    Returns:
        A prime number with exactly bit_length bits
    """
    while True:
        # Generate random odd number with exact bit length
        candidate = secrets.randbits(bit_length)
        # Ensure it has the right bit length (MSB = 1)
        candidate |= (1 << (bit_length - 1))
        # Ensure it's odd
        candidate |= 1
        
        if is_prime_miller_rabin(candidate):
            return candidate


def generate_rsa_modulus(bit_length: int) -> Tuple[int, int, int]:
    """
    Generate an RSA modulus and its factors.
    
    Args:
        bit_length: Desired bit length of the modulus (will be split between p and q)
    
    Returns:
        (n, p, q) where n = p*q and p, q are distinct primes
    """
    half_bits = bit_length // 2
    
    p = generate_prime(half_bits)
    q = generate_prime(half_bits)
    
    # Ensure p != q
    while p == q:
        q = generate_prime(half_bits)
    
    n = p * q
    return n, p, q


def euler_phi(p: int, q: int) -> int:
    """
    Compute Euler's totient function φ(n) = (p-1)(q-1) for n = pq.
    
    Args:
        p, q: Prime factors of n
    
    Returns:
        φ(n)
    """
    return (p - 1) * (q - 1)


def hash_to_prime(data: bytes, bit_length: int, max_attempts: int = 1000000) -> int:
    """
    Indexer function: deterministically map input data to a prime.
    
    Uses a counter-based approach: H(data || counter) until we find a prime.
    This is the I() function from the paper that maps x to p_x.
    
    Args:
        data: Input bytes to hash
        bit_length: Desired bit length of output prime
        max_attempts: Maximum number of attempts before giving up
    
    Returns:
        A prime derived from data
    
    Raises:
        RuntimeError: If no prime found within max_attempts
    """
    for counter in range(max_attempts):
        # Hash data with counter
        h = hashlib.sha256(data + counter.to_bytes(4, 'big')).digest()
        
        # Expand hash to desired bit length by repeated hashing if needed
        expanded = b''
        chunk = h
        while len(expanded) * 8 < bit_length:
            expanded += chunk
            chunk = hashlib.sha256(chunk).digest()
        
        # Convert to integer and ensure correct bit length
        candidate = bytes_to_int(expanded[:((bit_length + 7) // 8)])
        # Set MSB to ensure bit_length
        candidate |= (1 << (bit_length - 1))
        # Ensure odd
        candidate |= 1
        
        if is_prime_miller_rabin(candidate, k=20):
            return candidate
    
    raise RuntimeError(f"Failed to find prime after {max_attempts} attempts")


def generate_random_string(byte_length: int) -> bytes:
    """
    Generate a random byte string for GL construction.
    
    Args:
        byte_length: Number of random bytes to generate
    
    Returns:
        Random bytes
    """
    return secrets.token_bytes(byte_length)


def random_element_zn_star(n: int) -> int:
    """
    Sample a random element from Z_n^*.
    
    Args:
        n: RSA modulus
    
    Returns:
        Random element coprime to n
    """
    while True:
        r = secrets.randbelow(n)
        if r > 0 and gcd(r, n) == 1:
            return r


def compute_eth_root(y: int, e: int, phi_n: int, n: int) -> int:
    """
    Compute the e-th root of y modulo n.
    
    Given y = x^e mod n, compute x = y^d mod n where d = e^(-1) mod φ(n).
    
    Args:
        y: Value to take root of
        e: Exponent (must be coprime to φ(n))
        phi_n: Euler's totient φ(n)
        n: RSA modulus
    
    Returns:
        x such that x^e ≡ y (mod n)
    
    Raises:
        ValueError: If e is not coprime to φ(n)
    """
    if gcd(e, phi_n) != 1:
        raise ValueError(f"Exponent {e} is not coprime to φ(n) = {phi_n}")
    
    d = mod_inverse(e, phi_n)
    return mod_exp(y, d, n)


def serialize_proof_components(*components) -> bytes:
    """
    Serialize multiple components into a single byte string.
    
    Each component is prefixed with its length (4 bytes, big-endian).
    
    Args:
        *components: Variable number of bytes objects
    
    Returns:
        Serialized bytes
    """
    result = b''
    for component in components:
        if isinstance(component, int):
            component = int_to_bytes(component)
        length = len(component)
        result += length.to_bytes(4, 'big') + component
    return result


def deserialize_proof_components(data: bytes, num_components: int) -> list:
    """
    Deserialize components from a byte string.
    
    Args:
        data: Serialized bytes
        num_components: Expected number of components
    
    Returns:
        List of bytes objects
    
    Raises:
        ValueError: If deserialization fails
    """
    components = []
    offset = 0
    
    for _ in range(num_components):
        if offset + 4 > len(data):
            raise ValueError("Truncated serialized data")
        
        length = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        if offset + length > len(data):
            raise ValueError("Truncated component data")
        
        component = data[offset:offset+length]
        components.append(component)
        offset += length
    
    if offset != len(data):
        raise ValueError(f"Excess data in serialization: {len(data) - offset} bytes")
    
    return components