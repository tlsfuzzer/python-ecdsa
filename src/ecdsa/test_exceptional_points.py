"""Regressions for exceptional points on short Weierstrass curves."""

import pytest

from .ellipticcurve import CurveFp, INFINITY, Point, PointJacobi


def test_horizontal_and_vertical_tangents():
    curve = CurveFp(17, 0, 1)
    assert Point(curve, 0, 1).double() == Point(curve, 0, 16)
    assert Point(curve, 16, 0).double() == INFINITY


def test_negation_of_order_two_point_is_canonical():
    point = Point(CurveFp(17, 0, 1), 16, 0)
    assert (-point).x() == 16
    assert (-point).y() == 0


@pytest.mark.parametrize("scalar", range(-4, 5))
@pytest.mark.parametrize("scale", [1, 2, 16])
def test_finite_order_two_multiplication(scalar, scale):
    curve = CurveFp(17, 0, 1)
    point = PointJacobi(curve, 16 * scale**2 % 17, 0, scale)
    expected = Point(curve, 16, 0) if scalar % 2 else INFINITY
    assert point * scalar == expected
    assert scalar * point == expected


@pytest.mark.parametrize("x,y", [(3, -3), (8, 2), (8, -3)])
def test_equal_projective_points_use_doubling(x, y):
    curve = CurveFp(5, 0, 2)
    point = PointJacobi(curve, 3, 2, 1)
    assert point + PointJacobi(curve, x, y, 1) == point.double()


@pytest.mark.parametrize("representation", [Point, PointJacobi])
def test_order_three_subgroup(representation):
    curve = CurveFp(17, 0, 1)
    members = []
    for x in range(17):
        for y in range(17):
            if curve.contains_point(x, y):
                point = Point(curve, x, y)
                if representation is PointJacobi:
                    point = PointJacobi.from_affine(point)
                if point * 3 == INFINITY:
                    members.append((x, y))
    assert members == [(0, 1), (0, 16)]
    assert INFINITY * 3 == INFINITY
