"""
benchmark_vrf.py

Benchmark helpers for VRF implementations.

Structure and usage:

    from vrf_api import VRF
    from implementations.micali_rabin_vadhan.mrv_vrf import MRVVRF

    vrf = MRVVRF()
    run_basic_benchmark(vrf, b"benchmark-input", n_eval=1000, n_verify=1000)

You can swap MRVVRF for any other implementation that subclasses VRF.
"""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

from vrf_api import VRF


def benchmark_keygen(vrf: VRF, n: int = 10) -> Dict[str, float]:
    """
    Benchmark key generation for a VRF implementation.
    
    Args:
        vrf: VRF instance
        n: Number of repetitions
        
    Returns:
        dict with timing statistics
    """
    times = []
    
    for _ in range(n):
        t_start = time.perf_counter()
        vrf.keygen()
        t_end = time.perf_counter()
        times.append(t_end - t_start)
    
    total = sum(times)
    avg = total / n if n > 0 else 0.0
    min_time = min(times) if times else 0.0
    max_time = max(times) if times else 0.0
    
    return {
        "n": n,
        "total": total,
        "avg": avg,
        "min": min_time,
        "max": max_time,
    }


def benchmark_evaluate(vrf: VRF, alpha: bytes, n: int = 1000) -> Dict[str, float]:
    """
    Benchmark the evaluate() method for a VRF implementation.

    Args:
        vrf:  VRF instance (subclass of VRF).
        alpha: Input message as bytes.
        n:    Number of repetitions.

    Returns:
        dict with total and average evaluation time.
    """
    keypair = vrf.keygen()

    t_start = time.perf_counter()
    for _ in range(n):
        vrf.evaluate(keypair.sk, alpha)
    t_end = time.perf_counter()

    total = t_end - t_start
    return {
        "n": n,
        "eval_time_total": total,
        "eval_time_avg": total / n if n > 0 else 0.0,
    }


def benchmark_verify(vrf: VRF, alpha: bytes, n: int = 1000) -> Dict[str, float]:
    """
    Benchmark the verify() method for a VRF implementation.

    Args:
        vrf:  VRF instance (subclass of VRF).
        alpha: Input message as bytes.
        n:    Number of repetitions.

    Returns:
        dict with total and average verification time.
    """
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, alpha)

    t_start = time.perf_counter()
    for _ in range(n):
        vrf.verify(keypair.pk, alpha, beta, pi)
    t_end = time.perf_counter()

    total = t_end - t_start
    return {
        "n": n,
        "verify_time_total": total,
        "verify_time_avg": total / n if n > 0 else 0.0,
    }


def benchmark_by_input_size(vrf: VRF, input_sizes: List[int], n: int = 100) -> Dict[int, Dict]:
    """
    Benchmark VRF operations for various input sizes.
    
    Args:
        vrf: VRF instance
        input_sizes: List of input sizes to test (in bytes)
        n: Number of repetitions per size
        
    Returns:
        Dictionary mapping input_size -> {eval_time, verify_time, proof_size}
    """
    keypair = vrf.keygen()
    results = {}
    
    for size in input_sizes:
        alpha = b"x" * size
        
        # Benchmark evaluation
        eval_times = []
        for _ in range(n):
            t_start = time.perf_counter()
            beta, pi = vrf.evaluate(keypair.sk, alpha)
            t_end = time.perf_counter()
            eval_times.append(t_end - t_start)
        
        # Benchmark verification
        verify_times = []
        for _ in range(n):
            t_start = time.perf_counter()
            vrf.verify(keypair.pk, alpha, beta, pi)
            t_end = time.perf_counter()
            verify_times.append(t_end - t_start)
        
        results[size] = {
            "eval_avg": sum(eval_times) / n,
            "verify_avg": sum(verify_times) / n,
            "proof_size": len(pi),
            "output_size": len(beta),
        }
    
    return results


def format_time(seconds: float) -> str:
    """Format time in appropriate units."""
    if seconds < 1e-6:
        return f"{seconds * 1e9:.2f} ns"
    elif seconds < 1e-3:
        return f"{seconds * 1e6:.2f} µs"
    elif seconds < 1:
        return f"{seconds * 1e3:.2f} ms"
    else:
        return f"{seconds:.2f} s"


def format_size(bytes_val: int) -> str:
    """Format size in appropriate units."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.2f} KB"
    else:
        return f"{bytes_val / (1024 * 1024):.2f} MB"


def run_basic_benchmark(vrf: VRF, alpha: bytes, n_eval: int = 1000, n_verify: int = 1000) -> None:
    """
    Run a basic benchmark for a given VRF implementation and print results.

    Args:
        vrf:      VRF instance (e.g., MRVVRF()).
        alpha:    Input message as bytes.
        n_eval:   Number of evaluate() repetitions.
        n_verify: Number of verify() repetitions.
    """
    eval_stats = benchmark_evaluate(vrf, alpha, n_eval)
    verify_stats = benchmark_verify(vrf, alpha, n_verify)

    print("=== VRF Benchmark ===")
    print(f"Input length: {len(alpha)} bytes")
    print(f"Evaluations: {eval_stats['n']}, "
          f"total {eval_stats['eval_time_total']:.6f}s, "
          f"avg {eval_stats['eval_time_avg']:.6e}s")
    print(f"Verifications: {verify_stats['n']}, "
          f"total {verify_stats['verify_time_total']:.6f}s, "
          f"avg {verify_stats['verify_time_avg']:.6e}s")


def run_comprehensive_benchmark(vrf: VRF, verbose: bool = True) -> Dict:
    """
    Run comprehensive benchmark suite on a VRF implementation.
    
    Args:
        vrf: VRF instance to benchmark
        verbose: Print results to console
        
    Returns:
        Dictionary containing all benchmark results
    """
    results = {}
    
    if verbose:
        print("=" * 70)
        print("Comprehensive VRF Benchmark")
        print("=" * 70)
    
    # Key generation benchmark
    if verbose:
        print("\n[1/3] Benchmarking key generation...")
    keygen_stats = benchmark_keygen(vrf, n=10)
    results["keygen"] = keygen_stats
    
    if verbose:
        print(f"  Average: {format_time(keygen_stats['avg'])}")
        print(f"  Min: {format_time(keygen_stats['min'])}")
        print(f"  Max: {format_time(keygen_stats['max'])}")
    
    # Input size scaling benchmark
    if verbose:
        print("\n[2/3] Benchmarking by input size...")
    
    input_sizes = [0, 1, 10, 50, 100, 500]
    size_stats = benchmark_by_input_size(vrf, input_sizes, n=50)
    results["by_size"] = size_stats
    
    if verbose:
        print(f"\n  {'Size':<8} {'Eval':<12} {'Verify':<12} {'Proof':<10}")
        print("  " + "-" * 50)
        for size in input_sizes:
            stats = size_stats[size]
            print(f"  {size:<8} {format_time(stats['eval_avg']):<12} "
                  f"{format_time(stats['verify_avg']):<12} "
                  f"{format_size(stats['proof_size']):<10}")
    
    # Throughput benchmark
    if verbose:
        print("\n[3/3] Benchmarking throughput...")
    
    test_input = b"benchmark_test_input"
    eval_stats = benchmark_evaluate(vrf, test_input, n=100)
    verify_stats = benchmark_verify(vrf, test_input, n=1000)
    
    results["throughput"] = {
        "eval": eval_stats,
        "verify": verify_stats,
    }
    
    if verbose:
        eval_throughput = 1.0 / eval_stats['eval_time_avg']
        verify_throughput = 1.0 / verify_stats['verify_time_avg']
        
        print(f"  Evaluation: {eval_throughput:.2f} ops/sec")
        print(f"  Verification: {verify_throughput:.2f} ops/sec")
    
    if verbose:
        print("\n" + "=" * 70)
    
    return results


if __name__ == "__main__":
    # Benchmark MRV VRF implementation
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
        print("Benchmarking Micali-Rabin-Vadhan VRF Implementation")
        print("=" * 70)
        print()
        
        vrf = MRVVRF(security_parameter=512)
        results = run_comprehensive_benchmark(vrf, verbose=True)
        
        print()
        print("Quick benchmark with specific input:")
        print("-" * 70)
        run_basic_benchmark(vrf, b"example-input", n_eval=100, n_verify=500)
        print("=" * 70)
        
    except ImportError as e:
        print(f"Could not import MRV VRF: {e}")
        print("\nTo benchmark your own VRF implementation:")
        print("  from benchmark_vrf import run_comprehensive_benchmark")
        print("  from your_module import YourVRF")
        print("  vrf = YourVRF()")
        print("  results = run_comprehensive_benchmark(vrf)")