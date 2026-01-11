"""
rsa_vuf.py
RSA-based Verifiable Unpredictable Function (VUF).

This implements Construction 1 from Micali-Rabin-Vadhan (FOCS 1999):
    - Secret key: RSA modulus n = pq and random seed r ∈ Z_n^*
    - Public key: n and r
    - Indexer I: maps input x to a prime p_x > n
    - Evaluation: v_x = r^(1/p_x) mod n
    - Proof: π = v_x (the witness itself is the proof)
    - Verification: Check v_x^(p_x) ≡ r (mod n)

Security relies on the hardness of extracting RSA roots with random large prime exponents.
"""

from typing import Tuple, Dict, Any
from .utils import (
    generate_rsa_modulus,
    euler_phi,
    random_element_zn_star,
    hash_to_prime,
    compute_eth_root,
    mod_exp,
    int_to_bytes,
    bytes_to_int,
    serialize_proof_components,
    deserialize_proof_components,
)


class RSAVUF:
    """
    RSA-based Verifiable Unpredictable Function.
    
    This is the base primitive (Construction 1) that will be lifted to a VRF
    via the Goldreich-Levin construction.
    
    Key properties:
        - Unique provability: Only one valid (v, π) pair per input x
        - Verifiability: Anyone can check correctness using public key
        - Unpredictability: Cannot predict v_x at fresh input without SK
    """
    
    def __init__(self, security_parameter: int = 1024, prime_bit_length: int = None):
        """
        Initialize RSA VUF parameters.
        
        Args:
            security_parameter: Bit length of RSA modulus (default 1024)
            prime_bit_length: Bit length of prime exponents p_x (default: security_parameter + 1)
        """
        self.security_parameter = security_parameter
        # Prime exponents must be larger than modulus to ensure gcd(p_x, φ(n)) = 1
        self.prime_bit_length = prime_bit_length or (security_parameter + 1)
    
    def keygen(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Generate RSA VUF key pair.
        
        Returns:
            (sk, pk) where:
                sk = {'n': modulus, 'p': prime1, 'q': prime2, 'r': seed}
                pk = {'n': modulus, 'r': seed}
        """
        # Generate RSA modulus
        n, p, q = generate_rsa_modulus(self.security_parameter)
        
        # Generate random seed r ∈ Z_n^*
        r = random_element_zn_star(n)
        
        # Secret key includes factorization (needed to compute roots)
        sk = {
            'n': n,
            'p': p,
            'q': q,
            'r': r,
        }
        
        # Public key
        pk = {
            'n': n,
            'r': r,
        }
        
        return sk, pk
    
    def evaluate(self, sk: Dict[str, Any], x: bytes) -> Tuple[bytes, bytes]:
        """
        Evaluate VUF on input x.
        
        Computes v_x = r^(1/p_x) mod n where p_x = I(x) is a prime derived from x.
        
        Args:
            sk: Secret key
            x: Input bytes
        
        Returns:
            (v, π) where:
                v: VUF output (the root value)
                π: Proof (which is just v itself in this construction)
        """
        n = sk['n']
        p_factor = sk['p']
        q_factor = sk['q']
        r = sk['r']
        
        # Compute φ(n) = (p-1)(q-1)
        phi_n = euler_phi(p_factor, q_factor)
        
        # Compute prime exponent p_x from input using indexer function
        p_x = hash_to_prime(x, self.prime_bit_length)
        
        # Compute v_x = r^(1/p_x) mod n
        # This is equivalent to r^d mod n where d = p_x^(-1) mod φ(n)
        v_x = compute_eth_root(r, p_x, phi_n, n)
        
        # Convert to bytes
        v_bytes = int_to_bytes(v_x, (self.security_parameter + 7) // 8)
        
        # In this construction, the proof is simply v_x itself
        # (Verifier can check v_x^(p_x) ≡ r mod n)
        pi = v_bytes
        
        return v_bytes, pi
    
    def verify(self, pk: Dict[str, Any], x: bytes, v: bytes, pi: bytes) -> bool:
        """
        Verify VUF output and proof.
        
        Checks that v^(p_x) ≡ r (mod n) where p_x = I(x).
        
        Args:
            pk: Public key
            x: Input bytes
            v: Claimed VUF output
            pi: Proof (should equal v in this construction)
        
        Returns:
            True if verification succeeds, False otherwise
        """
        n = pk['n']
        r = pk['r']
        
        # Check that proof equals claimed output (structural check)
        if pi != v:
            return False
        
        # Convert v to integer
        v_int = bytes_to_int(v)
        
        # Check that v is in valid range [1, n-1]
        if v_int <= 0 or v_int >= n:
            return False
        
        # Compute prime exponent p_x from input
        p_x = hash_to_prime(x, self.prime_bit_length)
        
        # Verify: v^(p_x) ≡ r (mod n)
        v_to_p = mod_exp(v_int, p_x, n)
        
        return v_to_p == r
    
    def get_output_length(self) -> int:
        """
        Get the byte length of VUF outputs.
        
        Returns:
            Number of bytes in VUF output
        """
        return (self.security_parameter + 7) // 8


# For testing the VUF in isolation
if __name__ == "__main__":
    print("Testing RSA VUF...")
    
    # Create VUF instance
    vuf = RSAVUF(security_parameter=512)  # Small for testing
    
    # Generate keys
    print("Generating keys...")
    sk, pk = vuf.keygen()
    print(f"Modulus bit length: {sk['n'].bit_length()}")
    
    # Test evaluation and verification
    test_inputs = [b"hello", b"world", b"test input 123"]
    
    for x in test_inputs:
        print(f"\nTesting input: {x}")
        
        # Evaluate
        v, pi = vuf.evaluate(sk, x)
        print(f"  Output length: {len(v)} bytes")
        print(f"  Proof length: {len(pi)} bytes")
        
        # Verify
        valid = vuf.verify(pk, x, v, pi)
        print(f"  Verification: {'PASS' if valid else 'FAIL'}")
        
        # Test that wrong output fails
        wrong_v = bytes([b ^ 1 for b in v])  # Flip some bits
        valid_wrong = vuf.verify(pk, x, wrong_v, pi)
        print(f"  Wrong output verification: {'FAIL (unexpected)' if valid_wrong else 'PASS (correctly rejected)'}")
    
    print("\n✓ RSA VUF tests complete")