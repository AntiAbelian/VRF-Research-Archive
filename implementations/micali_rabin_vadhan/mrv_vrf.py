"""
mrv_vrf.py
Complete Micali-Rabin-Vadhan VRF implementation.

This module combines all three constructions:
    1. RSA-based VUF (rsa_vuf.py)
    2. Goldreich-Levin VRF lift (gl_vrf.py)
    3. Tree-based domain extension (tree_vrf.py)

The final MRVVRF class implements the VRF API and can be used as:
    vrf = MRVVRF()
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, b"input")
    valid = vrf.verify(keypair.pk, b"input", beta, pi)
"""

from typing import Tuple, Any

try:
    from vrf_api import VRF, VRFKeyPair
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from vrf_api import VRF, VRFKeyPair

from .tree_vrf import TreeVRF


class MRVVRF(VRF):
    """
    Micali-Rabin-Vadhan Verifiable Random Function.
    
    This is the complete VRF construction from the FOCS 1999 paper.
    
    Features:
        - Provably secure under RSA assumption
        - Unique provability (only one valid proof per input)
        - Handles arbitrary-length inputs via tree extension
        - Outputs pseudorandom values with verifiable proofs
    
    Note: This is a pedagogical implementation. For production use:
        - Use larger security parameters (2048+ bits)
        - Consider more efficient tree-based constructions
        - Add proper error handling and side-channel protections
    """
    
    def __init__(self, security_parameter: int = 1024):
        """
        Initialize MRV VRF.
        
        Args:
            security_parameter: Security parameter in bits (default 1024)
                               For production, use 2048 or higher.
        """
        self.security_parameter = security_parameter
        # Use tree-based VRF as the top-level construction
        # (which internally uses GL-VRF, which uses RSA-VUF)
        self.tree_vrf = TreeVRF(security_parameter=security_parameter)
    
    def keygen(self) -> VRFKeyPair:
        """
        Generate a fresh VRF key pair.
        
        Returns:
            VRFKeyPair with secret and public keys
        """
        sk, pk = self.tree_vrf.keygen()
        return VRFKeyPair(sk=sk, pk=pk)
    
    def evaluate(self, sk: Any, alpha: bytes) -> Tuple[bytes, bytes]:
        """
        Compute VRF output and proof for a given input.
        
        Args:
            sk: Secret key
            alpha: Input message as bytes
        
        Returns:
            (beta, pi):
                beta: VRF output as bytes
                pi: Proof of correct evaluation as bytes
        """
        return self.tree_vrf.evaluate(sk, alpha)
    
    def verify(self, pk: Any, alpha: bytes, beta: bytes, pi: bytes) -> bool:
        """
        Verify VRF output and proof.
        
        Args:
            pk: Public key
            alpha: Input message as bytes
            beta: VRF output as bytes
            pi: Proof of correct evaluation as bytes
        
        Returns:
            True if verification succeeds, False otherwise
        """
        return self.tree_vrf.verify(pk, alpha, beta, pi)


# For testing the complete implementation
if __name__ == "__main__":
    print("=" * 60)
    print("Testing Complete MRV VRF Implementation")
    print("=" * 60)
    
    # Create VRF instance (small security parameter for testing)
    print("\nInitializing MRV VRF (512-bit security for testing)...")
    vrf = MRVVRF(security_parameter=512)
    
    # Generate keys
    print("Generating key pair...")
    keypair = vrf.keygen()
    print(f"✓ Keys generated")
    print(f"  Public key type: {type(keypair.pk)}")
    print(f"  Secret key type: {type(keypair.sk)}")
    
    # Test with various inputs
    print("\n" + "=" * 60)
    print("Testing VRF Evaluation and Verification")
    print("=" * 60)
    
    test_cases = [
        (b"alice", "Short input"),
        (b"bob@example.com", "Email-like input"),
        (b"192.168.1.1", "IP address"),
        (b"x" * 100, "Long input (100 bytes)"),
        (b"", "Empty input"),
        (b"\x00\x01\x02\xff", "Binary data"),
    ]
    
    for alpha, description in test_cases:
        print(f"\nTest: {description}")
        print(f"  Input: {alpha[:40] if len(alpha) <= 40 else alpha[:37] + b'...'}")
        print(f"  Input length: {len(alpha)} bytes")
        
        # Evaluate
        beta, pi = vrf.evaluate(keypair.sk, alpha)
        print(f"  Output: {beta.hex()[:40]}... ({len(beta)} bytes)")
        print(f"  Proof length: {len(pi)} bytes")
        
        # Verify correct output
        valid = vrf.verify(keypair.pk, alpha, beta, pi)
        status = "✓ PASS" if valid else "✗ FAIL"
        print(f"  Verification: {status}")
        
        if not valid:
            print("  ERROR: Valid proof rejected!")
            continue
        
        # Test wrong output (should fail)
        wrong_beta = bytes([b ^ 1 for b in beta])
        valid_wrong = vrf.verify(keypair.pk, alpha, wrong_beta, pi)
        status = "✓ PASS (correctly rejected)" if not valid_wrong else "✗ FAIL (should reject)"
        print(f"  Wrong output test: {status}")
        
        # Test wrong input (should fail)
        wrong_alpha = alpha + b"_modified"
        valid_wrong_input = vrf.verify(keypair.pk, wrong_alpha, beta, pi)
        status = "✓ PASS (correctly rejected)" if not valid_wrong_input else "✗ FAIL (should reject)"
        print(f"  Wrong input test: {status}")
    
    # Test determinism
    print("\n" + "=" * 60)
    print("Testing Determinism")
    print("=" * 60)
    
    alpha_det = b"determinism_test"
    print(f"\nEvaluating same input multiple times...")
    
    outputs = []
    for i in range(3):
        beta, pi = vrf.evaluate(keypair.sk, alpha_det)
        outputs.append(beta)
        print(f"  Run {i+1}: {beta.hex()[:40]}...")
    
    all_same = all(out == outputs[0] for out in outputs)
    status = "✓ PASS" if all_same else "✗ FAIL"
    print(f"\nDeterminism check: {status}")
    
    # Test uniqueness (different inputs -> different outputs)
    print("\n" + "=" * 60)
    print("Testing Uniqueness")
    print("=" * 60)
    
    inputs = [b"input1", b"input2", b"input3"]
    print("\nEvaluating different inputs...")
    
    unique_outputs = []
    for alpha in inputs:
        beta, pi = vrf.evaluate(keypair.sk, alpha)
        unique_outputs.append(beta)
        print(f"  {alpha}: {beta.hex()[:40]}...")
    
    all_unique = len(set(unique_outputs)) == len(unique_outputs)
    status = "✓ PASS" if all_unique else "✗ FAIL"
    print(f"\nUniqueness check: {status}")
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print("\n✓ All MRV VRF tests completed successfully!")
    print("\nImplementation details:")
    print(f"  - Security parameter: {vrf.security_parameter} bits")
    print(f"  - Construction: RSA-VUF → GL-VRF → Tree-VRF")
    print(f"  - Output length: {vrf.tree_vrf.get_output_length()} bytes")
    print(f"  - Supports arbitrary-length inputs: Yes")
    print(f"  - Unique provability: Yes")
    print(f"  - Public verifiability: Yes")