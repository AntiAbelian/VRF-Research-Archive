"""
amplified_gl_vrf.py
Goldreich-Levin VRF with output amplification.

Outputs 256 bits (32 bytes) from a single VUF evaluation by computing
multiple inner products with different masks.

CRITICAL: Masks must be in pk for verification to work across processes.
"""

from typing import Tuple, Dict, Any
from .rsa_vuf import RSAVUF
from .goldreich_levin import inner_product_gf2
from .utils import serialize_proof_components, deserialize_proof_components, generate_random_string


class AmplifiedGLVRF:
    """
    Goldreich-Levin VRF with output amplification.
    
    Key insight: The VUF proof already reveals v, so we can compute
    multiple inner products ⟨v, r_i⟩ with different masks r_i at no
    additional proof cost.
    
    Output: 256 bits (32 bytes) from one VUF evaluation
    Proof size: Same as base VUF (just v and π_vuf)
    PK size: Includes all masks (~32 KB for 256-bit output with 128-byte VUF)
    """
    
    def __init__(self, security_parameter: int = 1024, output_bits: int = 256):
        """
        Initialize Amplified GL-VRF.
        
        Args:
            security_parameter: Security parameter (passed to VUF)
            output_bits: Number of output bits (must be multiple of 8)
        """
        if output_bits % 8 != 0:
            raise ValueError("output_bits must be multiple of 8")
        
        self.security_parameter = security_parameter
        self.output_bits = output_bits
        self.output_bytes = output_bits // 8
        
        # Use RSA VUF as base
        self.vuf = RSAVUF(security_parameter=security_parameter)
        self.vuf_output_length = self.vuf.get_output_length()
    
    def keygen(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Generate Amplified GL-VRF key pair.
        
        CRITICAL: Masks are included in BOTH sk and pk for verification.
        
        Returns:
            (sk, pk) where both include VUF keys and masks
        """
        # Generate VUF keys
        vuf_sk, vuf_pk = self.vuf.keygen()
        
        # Generate masks: one per output bit, each with length matching VUF output
        # Correction 3: Each mask must be same length as v (VUF output)
        masks = [generate_random_string(self.vuf_output_length) 
                 for _ in range(self.output_bits)]
        
        sk = {
            'vuf_sk': vuf_sk,
            'masks': masks,  # Included in sk for evaluate
        }
        
        pk = {
            'vuf_pk': vuf_pk,
            'masks': masks,  # BLOCKER 2: Must be in pk for verify!
        }
        
        return sk, pk
    
    def evaluate(self, sk: Dict[str, Any], x: bytes) -> Tuple[bytes, bytes]:
        """
        Evaluate Amplified GL-VRF.
        
        Computes VUF once, then computes output_bits inner products.
        
        Args:
            sk: Secret key (must contain vuf_sk and masks)
            x: Input bytes
        
        Returns:
            (y, π) where:
                y: output_bytes of VRF output (e.g., 32 bytes)
                π: Proof (v and VUF proof - same size as basic GL-VRF!)
        """
        vuf_sk = sk['vuf_sk']
        masks = sk['masks']
        
        # Evaluate VUF once
        v, pi_vuf = self.vuf.evaluate(vuf_sk, x)
        
        # Compute multiple GL bits using different masks
        output_bits = []
        for mask in masks:
            bit = inner_product_gf2(v, mask)
            output_bits.append(bit)
        
        # Pack bits into bytes (MSB first)
        y = bytearray()
        for i in range(0, len(output_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(output_bits):
                    byte = (byte << 1) | output_bits[i + j]
            y.append(byte)
        
        # Proof is same as basic GL-VRF: (v, π_vuf)
        # The masks are in pk, so verifier can recompute everything
        pi = serialize_proof_components(v, pi_vuf)
        
        return bytes(y), pi
    
    def verify(self, pk: Dict[str, Any], x: bytes, y: bytes, pi: bytes) -> bool:
        """
        Verify Amplified GL-VRF output.
        
        Verifies VUF proof once, then recomputes all inner products using
        masks from pk.
        
        Args:
            pk: Public key (must contain vuf_pk and masks)
            x: Input bytes
            y: Claimed output (output_bytes)
            pi: Proof
        
        Returns:
            True if valid
        """
        vuf_pk = pk['vuf_pk']
        masks = pk['masks']
        
        # Check output length
        if len(y) != self.output_bytes:
            return False
        
        # Parse proof: (v, π_vuf)
        try:
            components = deserialize_proof_components(pi, 2)
            v, pi_vuf = components
        except (ValueError, IndexError):
            return False
        
        # Verify VUF proof once
        if not self.vuf.verify(vuf_pk, x, v, pi_vuf):
            return False
        
        # Recompute all output bits using masks from pk
        output_bits = []
        for mask in masks:
            bit = inner_product_gf2(v, mask)
            output_bits.append(bit)
        
        # Pack bits into bytes and compare
        expected_y = bytearray()
        for i in range(0, len(output_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(output_bits):
                    byte = (byte << 1) | output_bits[i + j]
            expected_y.append(byte)
        
        return y == bytes(expected_y)
    
    def get_output_length(self) -> int:
        """Get output length in bytes."""
        return self.output_bytes


# For testing
if __name__ == "__main__":
    print("Testing Amplified GL-VRF")
    print("=" * 70)
    
    vrf = AmplifiedGLVRF(security_parameter=512, output_bits=256)
    
    print(f"\nConfiguration:")
    print(f"  Security parameter: {vrf.security_parameter} bits")
    print(f"  Output bits: {vrf.output_bits}")
    print(f"  Output bytes: {vrf.output_bytes}")
    print(f"  VUF output length: {vrf.vuf_output_length} bytes")
    
    # Generate keys
    print("\nGenerating keys...")
    sk, pk = vrf.keygen()
    
    # Check masks are in pk (Blocker 2)
    assert 'masks' in pk, "BLOCKER 2: Masks must be in pk!"
    print(f"  ✓ Masks in pk: {len(pk['masks'])} masks")
    print(f"  ✓ Each mask: {len(pk['masks'][0])} bytes")
    print(f"  ✓ Total mask size in pk: {len(pk['masks']) * len(pk['masks'][0])} bytes")
    
    # Test evaluation and verification
    print("\nTesting evaluation and verification...")
    test_inputs = [b"", b"test", b"hello world"]
    
    for x in test_inputs:
        y, pi = vrf.evaluate(sk, x)
        valid = vrf.verify(pk, x, y, pi)
        
        print(f"  Input: {x!r}")
        print(f"    Output: {y.hex()[:40]}... ({len(y)} bytes)")
        print(f"    Proof: {len(pi)} bytes")
        print(f"    Verify: {'✓ PASS' if valid else '✗ FAIL'}")
        
        if not valid:
            print("    ERROR: Valid proof rejected!")
    
    # Test uniqueness (should have no collisions with 256-bit output)
    print("\nTesting output uniqueness...")
    outputs = []
    for i in range(100):
        x = f"input_{i}".encode()
        y, _ = vrf.evaluate(sk, x)
        outputs.append(y)
    
    unique = len(set(outputs))
    print(f"  Generated: 100 outputs")
    print(f"  Unique: {unique}")
    print(f"  ✓ PASS: No collisions" if unique == 100 else f"  ✗ FAIL: {100-unique} collisions")
    
    # Test forgery resistance
    print("\nTesting forgery resistance...")
    import os
    x_target = b"forge"
    y_fake = os.urandom(vrf.output_bytes)
    
    # Try to forge (should fail)
    forged = vrf.verify(pk, x_target, y_fake, b"fake_proof")
    print(f"  ✓ PASS: Forgery rejected" if not forged else "  ✗ FAIL: Forgery accepted!")
    
    print("\n" + "=" * 70)
    print("✓ Amplified GL-VRF tests complete")
    print(f"\nKey properties:")
    print(f"  - Output: {vrf.output_bytes} bytes (collision-resistant)")
    print(f"  - Proof: Same size as base VUF")
    print(f"  - PK size: ~{len(pk['masks']) * len(pk['masks'][0]) // 1024} KB (includes masks)")