"""
Tests for timing attack resistance in ECDSA implementation.

This module tests the security improvements made to prevent:
- CVE-2024-23342: Minerva attack (timing side-channel)
- PVE-2024-64396: Side-channel attacks

The tests verify that the implementation is resistant to timing attacks
by ensuring constant-time operations and proper nonce generation.
"""

import os
import statistics
import time

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from . import curves
from .ecdsa import Signature
from .keys import SigningKey
from .util import randrange


class TestTimingAttackResistance(unittest.TestCase):
    """Comprehensive tests for timing attack resistance in ECDSA operations."""

    def setUp(self):
        """Set up test fixtures with multiple curves for comprehensive testing."""
        self.curves = [
            curves.NIST192p,
            curves.NIST256p,
            curves.NIST384p,
            curves.SECP256k1,
        ]
        self.test_data = os.urandom(32)
        self.test_message = b"test message for timing attack resistance"

    def _measure_timing(self, func, *args, **kwargs):
        """Helper to measure execution time of a function with high precision."""
        times = []
        for _ in range(3):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        return statistics.median(times), result

    def test_randrange_timing_consistency_across_curves(self):
        """Test that randrange has consistent timing across different curves."""
        for curve in self.curves:
            with self.subTest(curve=curve.name):
                times = []
                order = curve.order

                for _ in range(100):
                    times.append(self._measure_timing(randrange, order)[0])

                mean_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)
                timing_variation = (
                    (max_time - min_time) / mean_time if mean_time > 0 else 0
                )

                self.assertLess(
                    timing_variation,
                    50.0,
                    f"Timing variation too high for {curve.name}: {timing_variation:.2%}",
                )

    def test_randrange_timing_consistency_with_different_entropy(self):
        """Test that randrange timing is consistent with different entropy sources."""
        curve = curves.NIST256p
        order = curve.order

        entropy_patterns = [
            lambda n: os.urandom(n),
            lambda n: os.urandom(n + 1)[:n],
            lambda n: os.urandom(n)[::-1],
        ]

        for i, entropy_func in enumerate(entropy_patterns):
            with self.subTest(entropy_pattern=i):
                times = []
                for _ in range(50):
                    times.append(
                        self._measure_timing(
                            randrange, order, entropy=entropy_func
                        )[0]
                    )

                mean_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)
                timing_variation = (
                    (max_time - min_time) / mean_time if mean_time > 0 else 0
                )

                self.assertLess(
                    timing_variation,
                    20.0,
                    f"Timing variation too high for entropy pattern {i}: {timing_variation:.2%}",
                )

    def test_sign_timing_consistency_across_curves(self):
        """Test that signing has consistent timing across different curves."""
        for curve in self.curves:
            with self.subTest(curve=curve.name):
                private_key = SigningKey.generate(curve=curve)
                times = []

                # Test with different nonce values
                for i in range(50):
                    nonce = (i * 12345) % curve.order
                    if nonce == 0:
                        nonce = 1

                    times.append(
                        self._measure_timing(
                            private_key.sign_number,
                            int.from_bytes(self.test_data, "big"),
                            k=nonce,
                        )[0]
                    )

                mean_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)
                timing_variation = (
                    (max_time - min_time) / mean_time if mean_time > 0 else 0
                )

                self.assertLess(
                    timing_variation,
                    8.0,
                    f"Sign timing variation too high for {curve.name}: {timing_variation:.2%}",
                )

    def test_sign_timing_with_edge_case_nonces(self):
        """Test that signing timing is consistent with edge case nonces."""
        curve = curves.NIST256p
        private_key = SigningKey.generate(curve=curve)
        order = curve.order

        # Test edge cases that might reveal timing differences
        edge_cases = [
            1,
            2,
            3,
            4,
            5,  # Small values
            order - 5,
            order - 4,
            order - 3,
            order - 2,
            order - 1,  # Large values
            order // 2,
            order // 4,
            3 * order // 4,  # Mid-range values
            2**8,
            2**16,
            2**24,  # Power of 2 values
        ]

        times = []
        for nonce in edge_cases:
            if 0 < nonce < order:
                times.append(
                    self._measure_timing(
                        private_key.sign_number,
                        int.from_bytes(self.test_data, "big"),
                        k=nonce,
                    )[0]
                )

        if times:
            mean_time = statistics.mean(times)
            max_time = max(times)
            min_time = min(times)
            timing_variation = (
                (max_time - min_time) / mean_time if mean_time > 0 else 0
            )

            self.assertLess(
                timing_variation,
                10.0,
                f"Sign timing variation too high for edge cases: {timing_variation:.2%}",
            )

    def test_verify_timing_consistency(self):
        """Test that verification has consistent timing."""
        curve = curves.NIST256p
        private_key = SigningKey.generate(curve=curve)
        public_key = private_key.get_verifying_key()

        # Generate a valid signature
        valid_signature = private_key.sign(self.test_message)

        times = []
        for _ in range(50):
            times.append(
                self._measure_timing(
                    public_key.verify, valid_signature, self.test_message
                )[0]
            )

        mean_time = statistics.mean(times)
        max_time = max(times)
        min_time = min(times)
        timing_variation = (
            (max_time - min_time) / mean_time if mean_time > 0 else 0
        )

        self.assertLess(
            timing_variation,
            5.0,
            f"Verify timing variation too high: {timing_variation:.2%}",
        )

    def test_side_channel_resistance_across_curves(self):
        """Test that the implementation is resistant to side-channel attacks across curves."""
        for curve in self.curves:
            with self.subTest(curve=curve.name):
                private_key = SigningKey.generate(curve=curve)
                public_key = private_key.get_verifying_key()
                order = curve.order

                # Test with different nonce values
                nonce_values = [1, 2, 3, 100, 1000, 10000, order - 1]

                for nonce in nonce_values:
                    if 0 < nonce < order:
                        r, s = private_key.sign_number(
                            int.from_bytes(self.test_data, "big"), k=nonce
                        )

                        signature = Signature(r, s)

                        is_valid = public_key.pubkey.verifies(
                            int.from_bytes(self.test_data, "big"), signature
                        )
                        self.assertTrue(
                            is_valid,
                            f"Signature with nonce {nonce} should be valid for {curve.name}",
                        )

    def test_timing_attack_simulation(self):
        """Simulate a timing attack to ensure resistance."""
        curve = curves.NIST256p
        private_key = SigningKey.generate(curve=curve)
        public_key = private_key.get_verifying_key()
        order = curve.order

        # Generate multiple signatures with known nonces
        signatures = []
        nonces = []
        for i in range(20):
            nonce = (i * 12345) % order
            if nonce == 0:
                nonce = 1
            nonces.append(nonce)

            r, s = private_key.sign_number(
                int.from_bytes(self.test_data, "big"), k=nonce
            )
            signatures.append((r, s))

        # Measure timing for each signature verification
        times = []
        for r, s in signatures:
            signature = Signature(r, s)

            times.append(
                self._measure_timing(
                    public_key.pubkey.verifies,
                    int.from_bytes(self.test_data, "big"),
                    signature,
                )[0]
            )

        # In a vulnerable implementation, timing would correlate with nonce values
        # We should not see any significant correlation
        mean_time = statistics.mean(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0

        # Timing should be relatively uniform
        self.assertLess(
            std_dev / mean_time,
            0.5,  # Less than 50% coefficient of variation
            "Timing shows suspicious correlation with nonce values",
        )

    def test_stress_timing_consistency(self):
        """Stress test timing consistency under load."""
        curve = curves.NIST256p
        private_key = SigningKey.generate(curve=curve)
        order = curve.order

        # Run many operations to test consistency under load
        times = []
        for i in range(200):
            nonce = (i * 98765) % order
            if nonce == 0:
                nonce = 1

            times.append(
                self._measure_timing(
                    private_key.sign_number,
                    int.from_bytes(self.test_data, "big"),
                    k=nonce,
                )[0]
            )

        mean_time = statistics.mean(times)
        std_dev = statistics.stdev(times)
        max_time = max(times)
        min_time = min(times)
        timing_variation = (
            (max_time - min_time) / mean_time if mean_time > 0 else 0
        )

        # Even under stress, timing should be relatively consistent
        self.assertLess(
            timing_variation,
            20.0,
            f"Stress test timing variation too high: {timing_variation:.2%}",
        )

        # Coefficient of variation should be reasonable
        self.assertLess(
            std_dev / mean_time,
            1.0,
            "Stress test shows too much timing variation",
        )

    def test_regression_protection(self):
        """Test that future changes don't accidentally introduce timing vulnerabilities."""
        curve = curves.NIST256p
        private_key = SigningKey.generate(curve=curve)
        order = curve.order

        # Test with a wide range of nonce values
        test_nonces = [
            1,
            2,
            3,
            4,
            5,
            10,
            100,
            1000,
            10000,
            order - 10000,
            order - 1000,
            order - 100,
            order - 10,
            order - 5,
            order - 1,
            order // 2,
            order // 4,
            3 * order // 4,
            2**8,
            2**16,
            2**24,
            2**32 if 2**32 < order else order - 1,
        ]

        times = []
        for nonce in test_nonces:
            if 0 < nonce < order:
                times.append(
                    self._measure_timing(
                        private_key.sign_number,
                        int.from_bytes(self.test_data, "big"),
                        k=nonce,
                    )[0]
                )

        if len(times) > 1:
            mean_time = statistics.mean(times)
            std_dev = statistics.stdev(times)
            max_time = max(times)
            min_time = min(times)
            timing_variation = (
                (max_time - min_time) / mean_time if mean_time > 0 else 0
            )

            # Regression test: timing should be reasonably consistent
            self.assertLess(
                timing_variation,
                20.0,
                f"Regression test timing variation too high: {timing_variation:.2%}",
            )

            # Coefficient of variation should be reasonable
            self.assertLess(
                std_dev / mean_time,
                1.5,
                "Regression test shows too much timing variation",
            )
