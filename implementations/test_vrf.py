"""
test_vrf.py

Lightweight tests for VRF implementations.

You can run this file directly:

    python test_vrf.py

or integrate it with unittest/pytest later if desired.

To test another implementation, import it and add a corresponding test function.
"""

from __future__ import annotations
from typing import List, Dict

from vrf_api import VRF


def check_vrf_correctness(vrf: VRF, alpha: bytes) -> None:
    """
    Basic correctness check for a VRF implementation.

    Steps:
        1. Generate keys.
        2. Evaluate VRF on input alpha.
        3. Verify resulting output and proof.
        4. Raise AssertionError if verification fails.
    """
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, alpha)
    assert vrf.verify(keypair.pk, alpha, beta, pi), "VRF verification failed"


def test_determinism(vrf: VRF, alpha: bytes) -> None:
    """
    Test that VRF is deterministic (same input → same output).
    
    Args:
        vrf: VRF instance
        alpha: Input bytes
        
    Raises:
        AssertionError: If outputs differ across evaluations
    """
    keypair = vrf.keygen()
    
    beta1, pi1 = vrf.evaluate(keypair.sk, alpha)
    beta2, pi2 = vrf.evaluate(keypair.sk, alpha)
    
    assert beta1 == beta2, f"Non-deterministic output: {beta1.hex()} != {beta2.hex()}"
    assert pi1 == pi2, "Non-deterministic proof"


def test_uniqueness(vrf: VRF, inputs: List[bytes]) -> None:
    """
    Test that different inputs produce different outputs.
    
    Args:
        vrf: VRF instance
        inputs: List of distinct input bytes
        
    Raises:
        AssertionError: If any two inputs produce the same output
    """
    keypair = vrf.keygen()
    outputs = []
    
    for alpha in inputs:
        beta, _ = vrf.evaluate(keypair.sk, alpha)
        outputs.append(beta)
    
    unique_outputs = len(set(outputs))
    total_outputs = len(outputs)
    
    assert unique_outputs == total_outputs, \
        f"Non-unique outputs: {unique_outputs}/{total_outputs} unique"


def test_wrong_output_rejected(vrf: VRF, alpha: bytes) -> None:
    """
    Test that verification rejects incorrect outputs.
    
    Args:
        vrf: VRF instance
        alpha: Input bytes
        
    Raises:
        AssertionError: If wrong output is accepted
    """
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, alpha)
    
    # Flip bits in output
    wrong_beta = bytes([b ^ 1 for b in beta])
    
    result = vrf.verify(keypair.pk, alpha, wrong_beta, pi)
    assert not result, "Verification accepted wrong output"


def test_wrong_input_rejected(vrf: VRF, alpha: bytes) -> None:
    """
    Test that verification rejects proofs for different inputs.
    
    Args:
        vrf: VRF instance
        alpha: Input bytes
        
    Raises:
        AssertionError: If proof verifies for wrong input
    """
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, alpha)
    
    # Different input
    wrong_alpha = alpha + b"_modified"
    
    result = vrf.verify(keypair.pk, wrong_alpha, beta, pi)
    assert not result, "Verification accepted proof for wrong input"


def test_corrupted_proof_rejected(vrf: VRF, alpha: bytes) -> None:
    """
    Test that verification rejects corrupted proofs.
    
    Args:
        vrf: VRF instance
        alpha: Input bytes
        
    Raises:
        AssertionError: If corrupted proof is accepted
    """
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, alpha)
    
    if len(pi) > 10:
        # Corrupt proof
        corrupted_pi = pi[:-5] + bytes([pi[-5] ^ 1]) + pi[-4:]
        result = vrf.verify(keypair.pk, alpha, beta, corrupted_pi)
        assert not result, "Verification accepted corrupted proof"


def test_edge_cases(vrf: VRF) -> None:
    """
    Test VRF with edge case inputs.
    
    Args:
        vrf: VRF instance
        
    Raises:
        AssertionError: If any edge case fails
    """
    keypair = vrf.keygen()
    
    edge_cases = [
        (b"", "empty input"),
        (b"x", "single byte"),
        (b"a" * 100, "100 bytes"),
        (bytes(range(256)), "all byte values"),
    ]
    
    for alpha, description in edge_cases:
        beta, pi = vrf.evaluate(keypair.sk, alpha)
        valid = vrf.verify(keypair.pk, alpha, beta, pi)
        assert valid, f"Edge case failed: {description}"


def run_all_tests(vrf: VRF, verbose: bool = True) -> Dict[str, bool]:
    """
    Run comprehensive test suite on a VRF implementation.
    
    Args:
        vrf: VRF instance to test
        verbose: Print test progress
        
    Returns:
        Dictionary mapping test names to pass/fail status
    """
    results = {}
    
    tests = [
        ("correctness", lambda: check_vrf_correctness(vrf, b"test")),
        ("determinism", lambda: test_determinism(vrf, b"test")),
        ("uniqueness", lambda: test_uniqueness(vrf, [b"a", b"b", b"c", b"d"])),
        ("wrong_output_rejected", lambda: test_wrong_output_rejected(vrf, b"test")),
        ("wrong_input_rejected", lambda: test_wrong_input_rejected(vrf, b"test")),
        ("corrupted_proof_rejected", lambda: test_corrupted_proof_rejected(vrf, b"test")),
        ("edge_cases", lambda: test_edge_cases(vrf)),
    ]
    
    for test_name, test_func in tests:
        try:
            if verbose:
                print(f"Running {test_name}...", end=" ")
            test_func()
            results[test_name] = True
            if verbose:
                print("✓ PASS")
        except AssertionError as e:
            results[test_name] = False
            if verbose:
                print(f"✗ FAIL: {e}")
        except Exception as e:
            results[test_name] = False
            if verbose:
                print(f"✗ ERROR: {e}")
    
    return results


if __name__ == "__main__":
    # Test MRV VRF implementation
    try:
        # Try common import patterns
        try:
            from implementations.micali_rabin_vadhan.mrv_vrf import MRVVRF
        except ImportError:
            try:
                from micali_rabin_vadhan.mrv_vrf import MRVVRF
            except ImportError:
                from micali_rabin_vadhan import MRVVRF
        
        print("=" * 70)
        print("Testing Micali-Rabin-Vadhan VRF Implementation")
        print("=" * 70)
        print()
        
        vrf = MRVVRF(security_parameter=2048)
        results = run_all_tests(vrf, verbose=True)
        
        print()
        print("=" * 70)
        passed = sum(results.values())
        total = len(results)
        print(f"Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("✓ All tests passed!")
        else:
            print("✗ Some tests failed:")
            for name, status in results.items():
                if not status:
                    print(f"  - {name}")
        print("=" * 70)
        
    except ImportError as e:
        print(f"Could not import MRV VRF: {e}")
        print("\nTo test your own VRF implementation:")
        print("  from test_vrf import run_all_tests")
        print("  from your_module import YourVRF")
        print("  vrf = YourVRF()")
        print("  results = run_all_tests(vrf)")