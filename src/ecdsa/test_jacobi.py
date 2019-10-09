
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import hypothesis.strategies as st
from hypothesis import given, assume, settings, example

from .ellipticcurve import Point, PointJacobi, INFINITY
from .ecdsa import generator_256, curve_256, generator_224
from .numbertheory import inverse_mod

class TestJacobi(unittest.TestCase):
    def test___init__(self):
        curve = object()
        x = object()
        y = object()
        z = 1
        order = object()
        pj = PointJacobi(curve, x, y, z, order)

        self.assertIs(pj.order(), order)
        self.assertIs(pj.curve(), curve)
        self.assertIs(pj.x(), x)
        self.assertIs(pj.y(), y)

    def test_add_with_different_curves(self):
        p_a = PointJacobi.from_affine(generator_256)
        p_b = PointJacobi.from_affine(generator_224)

        with self.assertRaises(ValueError):
            p_a + p_b

    def test_compare_different_curves(self):
        self.assertNotEqual(generator_256, generator_224)

    def test_conversion(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = pj.to_affine()

        self.assertEqual(generator_256, pw)

    def test_single_double(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256.double()

        pj = pj.double()

        self.assertEqual(pj.x(), pw.x())
        self.assertEqual(pj.y(), pw.y())

    def test_double_with_zero_point(self):
        pj = PointJacobi(curve_256, 0, 0, 1)

        pj = pj.double()

        self.assertIs(pj, INFINITY)

    def test_double_with_zero_equivalent_point(self):
        pj = PointJacobi(curve_256, 0, curve_256.p(), 1)

        pj = pj.double()

        self.assertIs(pj, INFINITY)

    def test_compare_with_affine_point(self):
        pj = PointJacobi.from_affine(generator_256)
        pa = pj.to_affine()

        self.assertEqual(pj, pa)
        self.assertEqual(pa, pj)

    def test_add_with_affine_point(self):
        pj = PointJacobi.from_affine(generator_256)
        pa = pj.to_affine()

        s = pj + pa

        self.assertEqual(s, pj.double())

    def test_radd_with_affine_point(self):
        pj = PointJacobi.from_affine(generator_256)
        pa = pj.to_affine()

        s = pa + pj

        self.assertEqual(s, pj.double())

    def test_add_with_infinity(self):
        pj = PointJacobi.from_affine(generator_256)

        s = pj + INFINITY

        self.assertEqual(s, pj)

    def test_add_zero_point_to_affine(self):
        pa = PointJacobi.from_affine(generator_256).to_affine()
        pj = PointJacobi(curve_256, 0, 0, 1)

        s = pj + pa

        self.assertIs(s, pa)

    def test_multiply_by_zero(self):
        pj = PointJacobi.from_affine(generator_256)

        pj = pj * 0

        self.assertIs(pj, INFINITY)

    def test_zero_point_multiply_by_one(self):
        pj = PointJacobi(curve_256, 0, 0, 1)

        pj = pj * 1

        self.assertIs(pj, INFINITY)

    def test_multiply_by_one(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256 * 1

        pj = pj * 1

        self.assertEqual(pj.x(), pw.x())
        self.assertEqual(pj.y(), pw.y())

    def test_multiply_by_two(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256 * 2

        pj = pj * 2

        self.assertEqual(pj.x(), pw.x())
        self.assertEqual(pj.y(), pw.y())

    def test_rmul_by_two(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256 * 2

        pj = 2 * pj

        self.assertEqual(pj, pw)

    def test_compare_non_zero_with_infinity(self):
        pj = PointJacobi.from_affine(generator_256)

        self.assertNotEqual(pj, INFINITY)

    def test_compare_zero_point_with_infinity(self):
        pj = PointJacobi(curve_256, 0, 0, 1)

        self.assertEqual(pj, INFINITY)

    def test_compare_double_with_multiply(self):
        pj = PointJacobi.from_affine(generator_256)
        dbl = pj.double()
        mlpl = pj * 2

        self.assertEqual(dbl, mlpl)

    @settings(max_examples=10)
    @given(st.integers(min_value=0, max_value=generator_256.order()))
    def test_multiplications(self, mul):
        pj = PointJacobi.from_affine(generator_256)
        pw = pj.to_affine() * mul

        pj = pj * mul

        self.assertEqual((pj.x(), pj.y()), (pw.x(), pw.y()))
        self.assertEqual(pj, pw)

    @settings(max_examples=10)
    @given(st.integers(min_value=0, max_value=generator_256.order()))
    @example(0)
    @example(generator_256.order())
    def test_precompute(self, mul):
        precomp = PointJacobi.from_affine(generator_256, True)
        pj = PointJacobi.from_affine(generator_256)

        a = precomp * mul
        b = pj * mul

        self.assertEqual(a, b)

    @settings(max_examples=10)
    @given(st.integers(min_value=1, max_value=generator_256.order()),
           st.integers(min_value=1, max_value=generator_256.order()))
    @example(3, 3)
    def test_add_scaled_points(self, a_mul, b_mul):
        j_g = PointJacobi.from_affine(generator_256)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    @settings(max_examples=10)
    @given(st.integers(min_value=1, max_value=generator_256.order()),
           st.integers(min_value=1, max_value=generator_256.order()),
           st.integers(min_value=1, max_value=curve_256.p()-1))
    def test_add_one_scaled_point(self, a_mul, b_mul, new_z):
        j_g = PointJacobi.from_affine(generator_256)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        p = curve_256.p()

        assume(inverse_mod(new_z, p))

        new_zz = new_z * new_z % p

        b = PointJacobi(
            curve_256, b.x() * new_zz % p, b.y() * new_zz * new_z % p, new_z)

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    @settings(max_examples=10)
    @given(st.integers(min_value=1, max_value=generator_256.order()),
           st.integers(min_value=1, max_value=generator_256.order()),
           st.integers(min_value=1, max_value=curve_256.p()-1))
    @example(1, 1, 1)
    @example(3, 3, 3)
    @example(2, generator_256.order()-2, 1)
    @example(2, generator_256.order()-2, 3)
    def test_add_same_scale_points(self, a_mul, b_mul, new_z):
        j_g = PointJacobi.from_affine(generator_256)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        p = curve_256.p()

        assume(inverse_mod(new_z, p))

        new_zz = new_z * new_z % p

        a = PointJacobi(
            curve_256, a.x() * new_zz % p, a.y() * new_zz * new_z % p, new_z)
        b = PointJacobi(
            curve_256, b.x() * new_zz % p, b.y() * new_zz * new_z % p, new_z)

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    @settings(max_examples=14)
    @given(st.integers(min_value=1, max_value=generator_256.order()),
           st.integers(min_value=1, max_value=generator_256.order()),
           st.lists(st.integers(min_value=1, max_value=curve_256.p()-1),
                    min_size=2, max_size=2, unique=True))
    @example(2, 2, [2, 1])
    @example(2, 2, [2, 3])
    @example(2, generator_256.order()-2, [2, 3])
    @example(2, generator_256.order()-2, [2, 1])
    def test_add_different_scale_points(self, a_mul, b_mul, new_z):
        j_g = PointJacobi.from_affine(generator_256)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        p = curve_256.p()

        assume(inverse_mod(new_z[0], p))
        assume(inverse_mod(new_z[1], p))

        new_zz0 = new_z[0] * new_z[0] % p
        new_zz1 = new_z[1] * new_z[1] % p

        a = PointJacobi(
            curve_256,
            a.x() * new_zz0 % p,
            a.y() * new_zz0 * new_z[0] % p,
            new_z[0])
        b = PointJacobi(
            curve_256,
            b.x() * new_zz1 % p,
            b.y() * new_zz1 * new_z[1] % p,
            new_z[1])

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))
