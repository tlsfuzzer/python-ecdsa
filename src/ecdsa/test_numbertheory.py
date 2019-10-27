from six import print_
try:
    import unittest2 as unittest
except ImportError:
    import unittest
import hypothesis.strategies as st
from hypothesis import given
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

  error_tally = 0

  # Test the square_root_mod_prime function:

  for p in smallprimes:
    print_("Testing square_root_mod_prime for modulus p = %d." % p)
    squares = []

    for root in range(0, 1 + p // 2):
      sq = (root * root) % p
      squares.append(sq)
      calculated = square_root_mod_prime(sq, p)
      if (calculated * calculated) % p != sq:
        error_tally = error_tally + 1
        print_("Failed to find %d as sqrt( %d ) mod %d. Said %d." % \
               (root, sq, p, calculated))

    for nonsquare in range(0, p):
      if nonsquare not in squares:
        try:
          calculated = square_root_mod_prime(nonsquare, p)
        except SquareRootError:
          pass
        else:
          error_tally = error_tally + 1
          print_("Failed to report no root for sqrt( %d ) mod %d." % \
                 (nonsquare, p))

  # Test the jacobi function:
  for m in range(3, 400, 2):
    print_("Testing jacobi for modulus m = %d." % m)
    if is_prime(m):
      squares = []
      for root in range(1, m):
        if jacobi(root * root, m) != 1:
          error_tally = error_tally + 1
          print_("jacobi( %d * %d, %d) != 1" % (root, root, m))
        squares.append(root * root % m)
      for i in range(1, m):
        if i not in squares:
          if jacobi(i, m) != -1:
            error_tally = error_tally + 1
            print_("jacobi( %d, %d ) != -1" % (i, m))
    else:       # m is not prime.
      f = factorization(m)
      for a in range(1, m):
        c = 1
        for i in f:
          c = c * jacobi(a, i[0]) ** i[1]
        if c != jacobi(a, m):
          error_tally = error_tally + 1
          print_("%d != jacobi( %d, %d )" % (c, a, m))


  class FailedTest(Exception):
    pass

  print_(error_tally, "errors detected.")
  if error_tally != 0:
    raise FailedTest("%d errors detected" % error_tally)


@st.composite
def st_two_nums_rel_prime(draw):
    # 521-bit is the biggest curve we operate on, use 1024 for a bit
    # of breathing space
    mod = draw(st.integers(min_value=2, max_value=2**1024))
    num = draw(st.integers(min_value=1, max_value=mod-1)
               .filter(lambda x: gcd(x, mod) == 1))
    return num, mod


class TestNumbertheory(unittest.TestCase):
    @given(st_two_nums_rel_prime())
    def test_inverse_mod(self, nums):
        num, mod = nums

        inv = inverse_mod(num, mod)

        assert 0 < inv < mod
        assert num * inv % mod == 1
