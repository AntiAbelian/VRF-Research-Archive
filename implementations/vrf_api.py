"""
vrf_api.py

Core abstract interface for Verifiable Random Function (VRF) implementations.

Typical usage:

    from vrf_api import VRF, VRFKeyPair
    from implementations.micali_rabin_vadhan.mrv_vrf import MRVVRF

    vrf: VRF = MRVVRF()
    keypair = vrf.keygen()
    beta, pi = vrf.evaluate(keypair.sk, b"example input")
    ok = vrf.verify(keypair.pk, b"example input", beta, pi)

All concrete VRF implementations should subclass VRF and implement:

    - keygen(self) -> VRFKeyPair
    - evaluate(self, sk, alpha: bytes) -> (beta: bytes, pi: bytes)
    - verify(self, pk, alpha: bytes, beta: bytes, pi: bytes) -> bool
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Tuple


@dataclass
class VRFKeyPair:
    """
    Container for a VRF key pair.

    Attributes:
        sk: Secret key (implementation-specific type, often a dict or tuple).
        pk: Public key (implementation-specific type, often a dict or tuple).
    """
    sk: Any
    pk: Any


class VRF(ABC):
    """
    Abstract base class for a Verifiable Random Function.

    Implementations must provide:
        - keygen
        - evaluate
        - verify

    Notes on types:
        - alpha (input) should always be bytes (canonical encoding chosen by caller).
        - beta (output) is bytes (the VRF output, often derived from a group element or hash).
        - pi (proof) is bytes (serialized proof of correct evaluation).
    """

    @abstractmethod
    def keygen(self) -> VRFKeyPair:
        """
        Generate a fresh VRF key pair.

        Returns:
            VRFKeyPair: secret and public keys.
        """
        raise NotImplementedError

    @abstractmethod
    def evaluate(self, sk: Any, alpha: bytes) -> Tuple[bytes, bytes]:
        """
        Compute VRF output and proof for a given input.

        Args:
            sk:   Secret key corresponding to the VRF instance.
            alpha: Input message as bytes.

        Returns:
            (beta, pi):
                beta: VRF output as bytes.
                pi:   Proof of correct evaluation as bytes.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, pk: Any, alpha: bytes, beta: bytes, pi: bytes) -> bool:
        """
        Verify VRF output and proof for a given input and public key.

        Args:
            pk:   Public key corresponding to the VRF instance.
            alpha: Input message as bytes.
            beta:  VRF output as bytes.
            pi:    Proof of correct evaluation as bytes.

        Returns:
            bool: True if verification succeeds, False otherwise.
        """
        raise NotImplementedError
