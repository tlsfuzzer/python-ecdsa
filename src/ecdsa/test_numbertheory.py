from six import print_
try:
    import unittest2 as unittest
except ImportError:
    import unittest
import hypothesis.strategies as st
import pytest
from hypothesis import given, settings, example
try:
    from hypothesis import HealthCheck
    HC_PRESENT=True
except ImportError:
    HC_PRESENT=False
from .numbertheory import (SquareRootError, factorization, gcd, lcm,
                           jacobi, inverse_mod,
                           is_prime, next_prime, smallprimes,
                           square_root_mod_prime)

def test_numbertheory():

  # Making sure locally defined exceptions work:
  # p = modular_exp(2, -2, 3)
  # p = square_root_mod_prime(2, 3)

  print_("Testing gcd...")
  assert gcd(3 * 5 * 7, 3 * 5 * 11, 3 * 5 * 13) == 3 * 5
  assert gcd([3 * 5 * 7, 3 * 5 * 11, 3 * 5 * 13]) == 3 * 5
  assert gcd(3) == 3

  print_("Testing lcm...")
  assert lcm(3, 5 * 3, 7 * 3) == 3 * 5 * 7
  assert lcm([3, 5 * 3, 7 * 3]) == 3 * 5 * 7
  assert lcm(3) == 3

  print_("Testing next_prime...")
  bigprimes = (999671,
               999683,
               999721,
               999727,
               999749,
               999763,
               999769,
               999773,
               999809,
               999853,
               999863,
               999883,
               999907,
               999917,
               999931,
               999953,
               999959,
               999961,
               999979,
               999983)

  for i in range(len(bigprimes) - 1):
    assert next_prime(bigprimes[i]) == bigprimes[i + 1]


@pytest.mark.parametrize("prime", smallprimes)
def test_square_root_mod_prime_for_small_primes(prime):
    squares = set()
    for num in range(0, 1 + prime // 2):
        sq = num * num % prime
        squares.add(sq)
        root = square_root_mod_prime(sq, prime)
        # tested for real with TestNumbertheory.test_square_root_mod_prime
        assert root * root % prime == sq

    for nonsquare in range(0, prime):
        if nonsquare in squares:
            continue
        with pytest.raises(SquareRootError):
            square_root_mod_prime(nonsquare, prime)


@st.composite
def st_two_nums_rel_prime(draw):
    # 521-bit is the biggest curve we operate on, use 1024 for a bit
    # of breathing space
    mod = draw(st.integers(min_value=2, max_value=2**1024))
    num = draw(st.integers(min_value=1, max_value=mod-1)
               .filter(lambda x: gcd(x, mod) == 1))
    return num, mod


@st.composite
def st_primes(draw, *args, **kwargs):
    if "min_value" not in kwargs:
        kwargs["min_value"] = 1
    prime = draw(st.sampled_from(smallprimes) |
                 st.integers(*args, **kwargs)
                 .filter(lambda x: is_prime(x)))
    return prime


@st.composite
def st_num_square_prime(draw):
    prime = draw(st_primes(max_value=2**1024))
    num = draw(st.integers(min_value=0, max_value=1 + prime // 2))
    sq = num * num % prime
    return sq, prime


HYP_SETTINGS = {}
if HC_PRESENT:
    HYP_SETTINGS['suppress_health_check']=[HealthCheck.filter_too_much,
                                           HealthCheck.too_slow]
    # the factorization() sometimes takes a long time to finish
    HYP_SETTINGS['deadline'] = 5000


class TestNumbertheory(unittest.TestCase):
    @unittest.skipUnless(HC_PRESENT,
                         "Hypothesis 2.0.0 can't be made tolerant of hard to "
                         "meet requirements (like `is_prime()`)")
    @settings(**HYP_SETTINGS)
    @given(st_num_square_prime())
    def test_square_root_mod_prime(self, vals):
        square, prime = vals

        calc = square_root_mod_prime(square, prime)
        assert calc * calc % prime == square

    @settings(**HYP_SETTINGS)
    @given(st.integers(min_value=1, max_value=10**12))
    @example(265399 * 1526929)
    @example(373297 ** 2 * 553991)
    def test_factorization(self, num):
        factors = factorization(num)
        mult = 1
        for i in factors:
            mult *= i[0] ** i[1]
        assert mult == num

    @settings(**HYP_SETTINGS)
    @given(st.integers(min_value=3, max_value=1000).filter(lambda x: x % 2))
    def test_jacobi(self, mod):
        if is_prime(mod):
            squares = set()
            for root in range(1, mod):
                assert jacobi(root * root, mod) == 1
                squares.add(root * root % mod)
            for i in range(1, mod):
                if i not in squares:
                    assert jacobi(i, mod) == -1
        else:
            factors = factorization(mod)
            for a in range(1, mod):
                c = 1
                for i in factors:
                    c *= jacobi(a, i[0]) ** i[1]
                assert c == jacobi(a, mod)

    @given(st_two_nums_rel_prime())
    def test_inverse_mod(self, nums):
        num, mod = nums

        inv = inverse_mod(num, mod)

        assert 0 < inv < mod
        assert num * inv % mod == 1
