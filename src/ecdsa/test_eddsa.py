import pickle

try:
    import unittest2 as unittest
except ImportError:
    import unittest
from hypothesis import given, settings, example
import hypothesis.strategies as st
from .ellipticcurve import PointEdwards, INFINITY, CurveEdTw
from .eddsa import (
    generator_ed25519,
    curve_ed25519,
    generator_ed448,
    curve_ed448,
)
from .ecdsa import generator_256, curve_256
from .errors import MalformedPointError


def test_ed25519_curve_compare():
    assert curve_ed25519 != curve_256


def test_ed25519_and_ed448_compare():
    assert curve_ed448 != curve_ed25519


def test_ed25519_and_custom_curve_compare():
    a = CurveEdTw(curve_ed25519.p(), -curve_ed25519.a(), 1)

    assert curve_ed25519 != a


def test_ed25519_and_almost_exact_curve_compare():
    a = CurveEdTw(curve_ed25519.p(), curve_ed25519.a(), 1)

    assert curve_ed25519 != a


def test_ed25519_and_same_curve_params():
    a = CurveEdTw(curve_ed25519.p(), curve_ed25519.a(), curve_ed25519.d())

    assert curve_ed25519 == a
    assert not (curve_ed25519 != a)


def test_ed25519_contains_point():
    g = generator_ed25519
    assert curve_ed25519.contains_point(g.x(), g.y())


def test_ed25519_contains_point_bad():
    assert not curve_ed25519.contains_point(1, 1)


def test_ed25519_double():
    a = generator_ed25519

    z = a.double()

    assert isinstance(z, PointEdwards)

    x2 = int(
        "24727413235106541002554574571675588834622768167397638456726423"
        "682521233608206"
    )
    y2 = int(
        "15549675580280190176352668710449542251549572066445060580507079"
        "593062643049417"
    )

    b = PointEdwards(curve_ed25519, x2, y2, 1, x2 * y2)

    assert z == b
    assert a != b


def test_ed25519_add_as_double():
    a = generator_ed25519

    z = a + a

    assert isinstance(z, PointEdwards)

    b = generator_ed25519.double()

    assert z == b


def test_ed25519_double_infinity():
    a = PointEdwards(curve_ed25519, 0, 1, 1, 0)

    z = a.double()

    assert z is INFINITY


def test_ed25519_double_badly_encoded_infinity():
    # invalid point, mostly to make instrumental happy
    a = PointEdwards(curve_ed25519, 1, 1, 1, 0)

    z = a.double()

    assert z is INFINITY


def test_ed25519_eq_with_different_z():
    x = generator_ed25519.x()
    y = generator_ed25519.y()
    p = curve_ed25519.p()

    a = PointEdwards(curve_ed25519, x * 2 % p, y * 2 % p, 2, x * y * 2 % p)
    b = PointEdwards(curve_ed25519, x * 3 % p, y * 3 % p, 3, x * y * 3 % p)

    assert a == b

    assert not (a != b)


def test_ed25519_eq_against_infinity():
    assert generator_ed25519 != INFINITY


def test_ed25519_eq_encoded_infinity_against_infinity():
    a = PointEdwards(curve_ed25519, 0, 1, 1, 0)
    assert a == INFINITY


def test_ed25519_eq_bad_encode_of_infinity_against_infinity():
    # technically incorrect encoding of the point at infinity, but we check
    # both X and T, so verify that just T==0 works
    a = PointEdwards(curve_ed25519, 1, 1, 1, 0)
    assert a == INFINITY


def test_ed25519_eq_against_non_Edwards_point():
    assert generator_ed25519 != generator_256


def test_ed25519_eq_against_negated_point():
    g = generator_ed25519
    neg = PointEdwards(curve_ed25519, -g.x(), g.y(), 1, -g.x() * g.y())
    assert g != neg


def test_ed25519_eq_x_different_y():
    # not points on the curve, but __eq__ doesn't care
    a = PointEdwards(curve_ed25519, 1, 1, 1, 1)
    b = PointEdwards(curve_ed25519, 1, 2, 1, 2)

    assert a != b


def test_ed25519_test_normalisation_and_scaling():
    x = generator_ed25519.x()
    y = generator_ed25519.y()
    p = curve_ed25519.p()

    a = PointEdwards(curve_ed25519, x * 11 % p, y * 11 % p, 11, x * y * 11 % p)

    assert a.x() == x
    assert a.y() == y

    a.scale()

    assert a.x() == x
    assert a.y() == y

    a.scale()  # second execution should be a noop

    assert a.x() == x
    assert a.y() == y


def test_ed25519_add_three_times():
    a = generator_ed25519

    z = a + a + a

    x3 = int(
        "468967334644549386571235445953867877890461982801326656862413"
        "21779790909858396"
    )
    y3 = int(
        "832484377853344397649037712036920113830141722629755531674120"
        "2210403726505172"
    )

    b = PointEdwards(curve_ed25519, x3, y3, 1, x3 * y3)

    assert z == b


def test_ed25519_add_to_infinity():
    # generator * (order-1)
    x1 = int(
        "427838232691226969392843410947554224151809796397784248136826"
        "78720006717057747"
    )
    y1 = int(
        "463168356949264781694283940034751631413079938662562256157830"
        "33603165251855960"
    )
    inf_m_1 = PointEdwards(curve_ed25519, x1, y1, 1, x1 * y1)

    inf = inf_m_1 + generator_ed25519

    assert inf is INFINITY


def test_ed25519_add_and_mul_equivalence():
    g = generator_ed25519

    assert g + g == g * 2
    assert g + g + g == g * 3


def test_ed25519_add_literal_infinity():
    g = generator_ed25519
    z = g + INFINITY

    assert z == g


def test_ed25519_add_infinity():
    inf = PointEdwards(curve_ed25519, 0, 1, 1, 0)
    g = generator_ed25519
    z = g + inf

    assert z == g

    z = inf + g

    assert z == g


class TestEd25519(unittest.TestCase):
    def test_add_wrong_curves(self):
        with self.assertRaises(ValueError) as e:
            generator_ed25519 + generator_ed448

        self.assertIn("different curve", str(e.exception))

    def test_add_wrong_point_type(self):
        with self.assertRaises(ValueError) as e:
            generator_ed25519 + generator_256

        self.assertIn("different curve", str(e.exception))


def test_ed25519_mul_to_order_min_1():
    x1 = int(
        "427838232691226969392843410947554224151809796397784248136826"
        "78720006717057747"
    )
    y1 = int(
        "463168356949264781694283940034751631413079938662562256157830"
        "33603165251855960"
    )
    inf_m_1 = PointEdwards(curve_ed25519, x1, y1, 1, x1 * y1)

    assert generator_ed25519 * (generator_ed25519.order() - 1) == inf_m_1


def test_ed25519_mul_to_infinity():
    assert generator_ed25519 * generator_ed25519.order() == INFINITY


def test_ed25519_mul_to_infinity_plus_1():
    g = generator_ed25519
    assert g * (g.order() + 1) == g


def test_ed25519_mul_and_add():
    g = generator_ed25519
    a = g * 128
    b = g * 64 + g * 64

    assert a == b


def test_ed25519_mul_and_add_2():
    g = generator_ed25519

    a = g * 123
    b = g * 120 + g * 3

    assert a == b


def test_ed25519_mul_infinity():
    inf = PointEdwards(curve_ed25519, 0, 1, 1, 0)

    z = inf * 11

    assert z == INFINITY


def test_ed25519_mul_by_zero():
    z = generator_ed25519 * 0

    assert z == INFINITY


def test_ed25519_mul_by_one():
    z = generator_ed25519 * 1

    assert z == generator_ed25519


def test_ed25519_mul_custom_point():
    # verify that multiplication without order set works

    g = generator_ed25519

    a = PointEdwards(curve_ed25519, g.x(), g.y(), 1, g.x() * g.y())

    z = a * 11

    assert z == g * 11


def test_ed25519_pickle():
    g = generator_ed25519
    assert pickle.loads(pickle.dumps(g)) == g


def test_ed448_eq_against_different_curve():
    assert generator_ed25519 != generator_ed448


def test_ed448_double():
    g = generator_ed448
    z = g.double()

    assert isinstance(z, PointEdwards)

    x2 = int(
        "4845591495304045936995492052586696895690942404582120401876"
        "6013278705691214670908136440114445572635086627683154494739"
        "7859048262938744149"
    )
    y2 = int(
        "4940887598674337276743026725267350893505445523037277237461"
        "2648447308771911703729389009346215770388834286503647778745"
        "3078312060500281069"
    )

    b = PointEdwards(curve_ed448, x2, y2, 1, x2 * y2)

    assert z == b
    assert g != b


def test_ed448_add_as_double():
    g = generator_ed448
    z = g + g

    b = g.double()

    assert z == b


def test_ed448_mul_as_double():
    g = generator_ed448
    z = g * 2
    b = g.double()

    assert z == b


def test_ed448_add_to_infinity():
    # generator * (order - 1)
    x1 = int(
        "5022586839996825903617194737881084981068517190547539260353"
        "6473749366191269932473977736719082931859264751085238669719"
        "1187378895383117729"
    )
    y1 = int(
        "2988192100784814926760179304439306734375440401540802420959"
        "2824137233150618983587600353687865541878473398230323350346"
        "2500531545062832660"
    )
    inf_m_1 = PointEdwards(curve_ed448, x1, y1, 1, x1 * y1)

    inf = inf_m_1 + generator_ed448

    assert inf is INFINITY


def test_ed448_mul_to_infinity():
    g = generator_ed448
    inf = g * g.order()

    assert inf is INFINITY


def test_ed448_mul_to_infinity_plus_1():
    g = generator_ed448

    z = g * (g.order() + 1)

    assert z == g


def test_ed448_add_and_mul_equivalence():
    g = generator_ed448

    assert g + g == g * 2
    assert g + g + g == g * 3


def test_ed25519_encode():
    g = generator_ed25519
    g_bytes = g.to_bytes()
    assert len(g_bytes) == 32
    exp_bytes = (
        b"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
        b"\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
    )
    assert g_bytes == exp_bytes


def test_ed25519_decode():
    exp_bytes = (
        b"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
        b"\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
    )
    a = PointEdwards.from_bytes(curve_ed25519, exp_bytes)

    assert a == generator_ed25519


class TestEdwardsMalformed(unittest.TestCase):
    def test_invalid_point(self):
        exp_bytes = (
            b"\x78\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
            b"\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
        )
        with self.assertRaises(MalformedPointError):
            PointEdwards.from_bytes(curve_ed25519, exp_bytes)

    def test_invalid_length(self):
        exp_bytes = (
            b"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
            b"\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
            b"\x66"
        )
        with self.assertRaises(MalformedPointError) as e:
            PointEdwards.from_bytes(curve_ed25519, exp_bytes)

        self.assertIn("length", str(e.exception))

    def test_ed448_invalid(self):
        exp_bytes = b"\xff" * 57
        with self.assertRaises(MalformedPointError):
            PointEdwards.from_bytes(curve_ed448, exp_bytes)


def test_ed448_encode():
    g = generator_ed448
    g_bytes = g.to_bytes()
    assert len(g_bytes) == 57
    exp_bytes = (
        b"\x14\xfa\x30\xf2\x5b\x79\x08\x98\xad\xc8\xd7\x4e\x2c\x13\xbd"
        b"\xfd\xc4\x39\x7c\xe6\x1c\xff\xd3\x3a\xd7\xc2\xa0\x05\x1e\x9c"
        b"\x78\x87\x40\x98\xa3\x6c\x73\x73\xea\x4b\x62\xc7\xc9\x56\x37"
        b"\x20\x76\x88\x24\xbc\xb6\x6e\x71\x46\x3f\x69\x00"
    )
    assert g_bytes == exp_bytes


def test_ed448_decode():
    exp_bytes = (
        b"\x14\xfa\x30\xf2\x5b\x79\x08\x98\xad\xc8\xd7\x4e\x2c\x13\xbd"
        b"\xfd\xc4\x39\x7c\xe6\x1c\xff\xd3\x3a\xd7\xc2\xa0\x05\x1e\x9c"
        b"\x78\x87\x40\x98\xa3\x6c\x73\x73\xea\x4b\x62\xc7\xc9\x56\x37"
        b"\x20\x76\x88\x24\xbc\xb6\x6e\x71\x46\x3f\x69\x00"
    )

    a = PointEdwards.from_bytes(curve_ed448, exp_bytes)

    assert a == generator_ed448


HYP_SETTINGS = dict()
HYP_SETTINGS["max_examples"] = 10


@settings(**HYP_SETTINGS)
@example(1)
@example(5)  # smallest multiple that requires changing sign of x
@given(st.integers(min_value=1, max_value=int(generator_ed25519.order() - 1)))
def test_ed25519_encode_decode(multiple):
    a = generator_ed25519 * multiple

    b = PointEdwards.from_bytes(curve_ed25519, a.to_bytes())

    assert a == b


@settings(**HYP_SETTINGS)
@example(1)
@example(2)  # smallest multiple that requires changing the sign of x
@given(st.integers(min_value=1, max_value=int(generator_ed448.order() - 1)))
def test_ed448_encode_decode(multiple):
    a = generator_ed448 * multiple

    b = PointEdwards.from_bytes(curve_ed448, a.to_bytes())

    assert a == b
