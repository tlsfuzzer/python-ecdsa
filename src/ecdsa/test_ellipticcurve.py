import pytest
from six import print_
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from hypothesis import given, settings
import hypothesis.strategies as st
try:
    from hypothesis import HealthCheck
    HC_PRESENT=True
except ImportError:
    HC_PRESENT=False
from .numbertheory import inverse_mod
from .ellipticcurve import CurveFp, INFINITY, Point


HYP_SETTINGS={}
if HC_PRESENT:
    HYP_SETTINGS['suppress_health_check']=[HealthCheck.too_slow]
    HYP_SETTINGS['deadline'] = 5000


# NIST Curve P-192:
p = 6277101735386680763835789423207666416083908700390324961279
r = 6277101735386680763835789423176059013767194773182842284081
# s = 0x3045ae6fc8422f64ed579528d38120eae12196d5
# c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811


c192 = CurveFp(p, -3, b)
p192 = Point(c192, Gx, Gy, r)


def test_p192():
    # Checking against some sample computations presented
    # in X9.62:
    d = 651056770906015076056810763456358567190100156695615665659
    Q = d * p192
    assert Q.x() == 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5

    k = 6140507067065001063065065565667405560006161556565665656654
    R = k * p192
    assert R.x() == 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD \
        and R.y() == 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835

    u1 = 2563697409189434185194736134579731015366492496392189760599
    u2 = 6266643813348617967186477710235785849136406323338782220568
    temp = u1 * p192 + u2 * Q
    assert temp.x() == 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD \
        and temp.y() == 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835


@settings(**HYP_SETTINGS)
@given(st.integers(min_value=1, max_value=r+1))
def test_p192_mult_tests(multiple):
    inv_m = inverse_mod(multiple, r)

    p1 = p192 * multiple
    assert p1 * inv_m == p192


def add_n_times(point, n):
    ret = INFINITY
    i = 0
    while i <= n:
        yield ret
        ret = ret + point
        i += 1


c_23 = CurveFp(23, 1, 1)


g_23 = Point(c_23, 13, 7, 7)


# Trivial tests from X9.62 B.3:
@pytest.mark.parametrize(
    "c,x1,y1,x2,y2,x3,y3",
    [(c_23, 3, 10, 9, 7, 17, 20),
     (c_23, 3, 10, 3, 10, 7, 12)],
    ids=["real add", "double"])
def test_add(c, x1, y1, x2, y2, x3, y3):
    """We expect that on curve c, (x1,y1) + (x2, y2 ) = (x3, y3)."""
    p1 = Point(c, x1, y1)
    p2 = Point(c, x2, y2)
    p3 = p1 + p2
    assert p3.x() == x3 and p3.y() == y3


@pytest.mark.parametrize(
    "c, x1, y1, x3, y3",
    [(c_23, 3, 10, 7, 12)],
    ids=["real add"])
def test_double(c, x1, y1, x3, y3):
    p1 = Point(c, x1, y1)
    p3 = p1.double()
    assert p3.x() == x3 and p3.y() == y3


def test_double_infinity():
    p1 = INFINITY
    p3 = p1.double()
    assert p1 == p3
    assert p3.x() == p1.x() and p3.y() == p3.y()


@pytest.mark.parametrize(
    "c, x1, y1, m, x3, y3",
    [(c_23, 3, 10, 2, 7, 12)],
    ids=["multiply by 2"])
def test_multiply(c, x1, y1, m, x3, y3):
    p1 = Point(c, x1, y1)
    p3 = p1 * m
    assert p3.x() == x3 and p3.y() == y3


# From X9.62 I.1 (p. 96):
@pytest.mark.parametrize(
    "p, m, check",
    [(g_23, n, exp) for n, exp in enumerate(add_n_times(g_23, 8))],
    ids=["g_23 test with mult {0}".format(i) for i in range(9)])
def test_add_and_mult_equivalence(p, m, check):
    assert p * m == check
