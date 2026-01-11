"""
Micali-Rabin-Vadhan VRF Implementation (FOCS 1999)

This package implements the three-stage construction:
    1. RSA-based VUF (rsa_vuf.py)
    2. Goldreich-Levin VRF lift (gl_vrf.py)  
    3. Tree-based domain extension (tree_vrf.py)

The final combined VRF is exported as MRVVRF.
"""

from .mrv_vrf import MRVVRF

__all__ = ['MRVVRF']