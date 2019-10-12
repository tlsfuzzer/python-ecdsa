#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Implementation of elliptic curves, for cryptographic applications.
#
# This module doesn't provide any way to choose a random elliptic
# curve, nor to verify that an elliptic curve was chosen randomly,
# because one can simply use NIST's standard curves.
#
# Notes from X9.62-1998 (draft):
#   Nomenclature:
#     - Q is a public key.
#     The "Elliptic Curve Domain Parameters" include:
#     - q is the "field size", which in our case equals p.
#     - p is a big prime.
#     - G is a point of prime order (5.1.1.1).
#     - n is the order of G (5.1.1.1).
#   Public-key validation (5.2.2):
#     - Verify that Q is not the point at infinity.
#     - Verify that X_Q and Y_Q are in [0,p-1].
#     - Verify that Q is on the curve.
#     - Verify that nQ is the point at infinity.
#   Signature generation (5.3):
#     - Pick random k from [1,n-1].
#   Signature checking (5.4.2):
#     - Verify that r and s are in [1,n-1].
#
# Version of 2008.11.25.
#
# Revision history:
#    2005.12.31 - Initial version.
#    2008.11.25 - Change CurveFp.is_on to contains_point.
#
# Written in 2005 by Peter Pearson and placed in the public domain.

from __future__ import division

from six import python_2_unicode_compatible
from . import numbertheory

@python_2_unicode_compatible
class CurveFp(object):
  """Elliptic Curve over the field of integers modulo a prime."""
  def __init__(self, p, a, b):
    """The curve of points satisfying y^2 = x^3 + a*x + b (mod p)."""
    self.__p = p
    self.__a = a
    self.__b = b
    
  def __eq__(self, other):
    if isinstance(other, CurveFp):    
      """Return True if the curves are identical, False otherwise."""
      return self.__p == other.__p \
        and self.__a == other.__a \
        and self.__b == other.__b
    return NotImplemented

  def p(self):
    return self.__p

  def a(self):
    return self.__a

  def b(self):
    return self.__b

  def contains_point(self, x, y):
    """Is the point (x,y) on this curve?"""
    return (y * y - ((x * x + self.__a) * x + self.__b)) % self.__p == 0

  def __str__(self):
    return "CurveFp(p=%d, a=%d, b=%d)" % (self.__p, self.__a, self.__b)


class PointJacobi(object):
  """
  Point on an elliptic curve. Uses Jacobi coordinates.

  In Jacobian coordinates, there are three parameters, X, Y and Z.
  They correspond to affine parameters 'x' and 'y' like so:

  x = X / Z²
  y = Y / Z³
  """
  def __init__(self, curve, x, y, z, order=None, generator=False):
      """
      :param bool generator: the point provided is a curve generator, as
        such, it will be commonly used with scalar multiplication. This will
        cause to precompute multiplication table for it
      """
      self.__curve = curve
      self.__x = x
      self.__y = y
      self.__z = z
      self.__order = order
      self.__precompute=[]
      if generator:
          assert order
          i = 1
          order *= 2
          doubler = PointJacobi(curve, x, y, z, order)
          order *= 2
          self.__precompute.append(doubler)

          while i < order:
              i *= 2
              doubler = doubler.double().scale()
              self.__precompute.append(doubler)

  def __eq__(self, other):
      """Compare two points with each-other."""
      if (not self.__y or not self.__z) and other is INFINITY:
          return True
      if self.__y and self.__z and other is INFINITY:
          return False
      if isinstance(other, Point):
          x2, y2, z2 = other.x(), other.y(), 1
      elif isinstance(other, PointJacobi):
          x2, y2, z2 = other.__x, other.__y, other.__z
      else:
          return NotImplemented
      if self.__curve != other.curve():
          return False
      x1, y1, z1 = self.__x, self.__y, self.__z
      p = self.__curve.p()

      zz1 = z1 * z1 % p
      zz2 = z2 * z2 % p

      # compare the fractions by bringing them to the same denominator
      # depend on short-circuit to save 4 multiplications in case of inequality
      return (x1 * zz2 - x2 * zz1) % p == 0 and \
              (y1 * zz2 * z2 - y2 * zz1 * z1) % p == 0

  def order(self):
      return self.__order

  def curve(self):
      return self.__curve

  def x(self):
      """
      Return affine x coordinate.

      This method should be used only when the 'y' coordinate is not needed.
      It's computationally more efficient to use `to_affine()` and then
      call x() and y() on the returned instance.
      """
      if self.__z == 1:
          return self.__x
      p = self.__curve.p()
      z = numbertheory.inverse_mod(self.__z, p)
      return self.__x * z**2 % p

  def y(self):
      """
      Return affine y coordinate.

      This method should be used only when the 'x' coordinate is not needed.
      It's computationally more efficient to use `to_affine()` and then
      call x() and y() on the returned instance.
      """
      if self.__z == 1:
          return self.__y
      p = self.__curve.p()
      z = numbertheory.inverse_mod(self.__z, p)
      return self.__y * z**3 % p

  def scale(self):
      """
      Return point scaled so that z == 1.

      Modifies point in place, returns self.
      """
      p = self.__curve.p()
      z_inv = numbertheory.inverse_mod(self.__z, p)
      zz_inv = z_inv * z_inv % p
      self.__x = self.__x * zz_inv % p
      self.__y = self.__y * zz_inv * z_inv % p
      self.__z = 1
      return self

  def to_affine(self):
      """Return point in affine form."""
      if not self.__y or not self.__z:
          return INFINITY
      self.scale()
      return Point(self.__curve, self.__x,
                   self.__y, self.__order)

  @staticmethod
  def from_affine(point, generator=False):
      """Create from an affine point."""
      return PointJacobi(point.curve(), point.x(), point.y(), 1,
                         point.order(), generator)

  # plese note that all the methods that use the equations from hyperelliptic
  # are formatted in a way to maximise performance.
  # Things that make code faster: multiplying instead of taking to the power
  # (`xx = x * x; xxxx = xx * xx % p` is faster than `xxxx = x**4 % p` and
  # `pow(x, 4, p)`),
  # multiple assignments at the same time (`x1, x2 = self.x1, self.x2` is
  # faster than `x1 = self.x1; x2 = self.x2`),
  # similarly, sometimes the `% p` is skipped if it makes the calculation
  # faster and the result of calculation is later reduced modulo `p`

  def double(self):
      """Add a point to itself."""
      if not self.__y:
          return INFINITY

      p = self.__curve.p()
      a = self.__curve.a()

      X1, Y1, Z1 = self.__x, self.__y, self.__z

      # after:
      # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl

      XX, YY = X1 * X1 % p, Y1 * Y1 % p
      if not YY:
          return INFINITY
      YYYY = YY * YY % p
      ZZ = Z1 * Z1 % p
      S = 2 * ((X1 + YY)**2 - XX - YYYY) % p
      M = (3 * XX + a * ZZ * ZZ) % p
      T = (M * M - 2 * S) % p
      # X3 = T
      Y3 = (M * (S - T) - 8 * YYYY) % p
      Z3 = ((Y1 + Z1)**2 - YY - ZZ) % p

      return PointJacobi(self.__curve, T, Y3, Z3, self.__order)

  def _add_with_z_1(self, X1, Y1, X2, Y2):
      """add points when both Z1 and Z2 equal 1"""
      # after:
      # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-mmadd-2007-bl
      p = self.__curve.p()
      H = X2 - X1
      HH = H * H
      I = 4 * HH % p
      J = H * I
      r = 2 * (Y2 - Y1)
      if not H and not r:
          return self.double()
      V = X1 * I
      X3 = (r**2 - J - 2 * V) % p
      Y3 = (r * (V - X3) - 2 * Y1 * J) % p
      Z3 = 2 * H % p
      if not Y3 or not Z3:
          return INFINITY
      return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

  def _add_with_z_eq(self, X1, Y1, Z1, X2, Y2):
      """add points when Z1 == Z2"""
      # after:
      # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-zadd-2007-m
      p = self.__curve.p()
      A = (X2 - X1)**2 % p
      B = X1 * A % p
      C = X2 * A
      D = (Y2 - Y1)**2 % p
      if not A and not D:
          return self.double()
      X3 = (D - B - C) % p
      Y3 = ((Y2 - Y1) * (B - X3) - Y1 * (C - B)) % p
      Z3 = Z1 * (X2 - X1) % p
      if not Y3 or not Z3:
          return INFINITY
      return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

  def _add_with_z2_1(self, X1, Y1, Z1, X2, Y2):
      """add points when Z2 == 1"""
      # after:
      # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl
      p = self.__curve.p()
      Z1Z1 = Z1 * Z1 % p
      U2, S2 = X2 * Z1Z1 % p, Y2 * Z1 * Z1Z1 % p
      H = (U2 - X1) % p
      HH = H * H % p
      I = 4 * HH % p
      J = H * I
      r = 2 * (S2 - Y1) % p
      if not r and not H:
          return self.double()
      V = X1 * I
      X3 = (r * r - J - 2 * V) % p
      Y3 = (r * (V - X3) - 2 * Y1 * J) % p
      Z3 = ((Z1 + H)**2 - Z1Z1 - HH) % p
      if not Y3 or not Z3:
          return INFINITY
      return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

  def __radd__(self, other):
      return self + other

  def __add__(self, other):
      """Add two points on elliptic curve."""
      if self == INFINITY:
          return other
      if other == INFINITY:
          return self
      if isinstance(other, Point):
          other = PointJacobi.from_affine(other)
      if self.__curve != other.__curve:
          raise ValueError("The other point is on different curve")

      p = self.__curve.p()
      X1, Y1, Z1 = self.__x, self.__y, self.__z
      X2, Y2, Z2 = other.__x, other.__y, other.__z
      if Z1 == Z2:
          if Z1 == 1:
              return self._add_with_z_1(X1, Y1, X2, Y2)
          return self._add_with_z_eq(X1, Y1, Z1, X2, Y2)
      if Z1 == 1:
          return self._add_with_z2_1(X2, Y2, Z2, X1, Y1)
      if Z2 == 1:
          return self._add_with_z2_1(X1, Y1, Z1, X2, Y2)

      # after:
      # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
      Z1Z1 = Z1 * Z1 % p
      Z2Z2 = Z2 * Z2 % p
      U1 = X1 * Z2Z2 % p
      U2 = X2 * Z1Z1 % p
      S1 = Y1 * Z2 * Z2Z2 % p
      S2 = Y2 * Z1 * Z1Z1 % p
      H = U2 - U1
      I = 4 * H * H % p
      J = H * I % p
      r = 2 * (S2 - S1) % p
      if not H and not r:
          return self.double()
      V = U1 * I
      X3 = (r * r - J - 2 * V) % p
      Y3 = (r * (V - X3) - 2 * S1 * J) % p
      Z3 = ((Z1 + Z2)**2 - Z1Z1 - Z2Z2) * H % p

      if not Y3 or not Z3:
          return INFINITY

      return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

  def __rmul__(self, other):
      """Multiply point by an integer."""
      return self * other

  def _mul_precompute(self, other):
      result = INFINITY
      for precomp in self.__precompute:
          if other % 2:
              if other % 4 >= 2:
                  other, result = (other + 1)//2, result + (-precomp)
              else:
                  other, result = (other - 1)//2, result + precomp
          else:
              other //= 2
      return result

  def __mul__(self, other):
      """Multiply point by an integer."""
      if not self.__y or not other:
          return INFINITY
      if other == 1:
          return self
      if self.__order:
          # order*2 as a protection for Minerva
          other = other % (self.__order*2)
      if self.__precompute:
          return self._mul_precompute(other)

      def leftmost_bit(x):
        assert x > 0
        result = 1
        while result <= x:
          result = 2 * result
        return result // 2

      e = other
      i = leftmost_bit(e)
      self = self.scale()
      result = self
      while i > 1:
          result = result.double()
          i = i // 2
          if e & i != 0:
              result = result + self
      return result

  @staticmethod
  def _leftmost_bit(x):
    assert x > 0
    result = 1
    while result <= x:
      result = 2 * result
    return result // 2

  def mul_add(self, self_mul, other, other_mul):
      """
      Do two multiplications at the same time, add results.

      calculates self*self_mul + other*other_mul
      """
      if other is INFINITY or other_mul == 0:
          return self * self_mul
      if self_mul == 0:
          return other * other_mul
      if not isinstance(other, PointJacobi):
          other = PointJacobi.from_affine(other)

      i = self._leftmost_bit(max(self_mul, other_mul))*2
      result = INFINITY
      self = self.scale()
      other = other.scale()
      both = (self + other).scale()
      while i > 1:
          result = result.double()
          i = i // 2
          if self_mul & i and other_mul & i:
              result = result + both
          elif self_mul & i:
              result = result + self
          elif other_mul & i:
              result = result + other
      return result

  def __neg__(self):
      return PointJacobi(self.__curve, self.__x, -self.__y, self.__z,
                         self.__order)


class Point(object):
  """A point on an elliptic curve. Altering x and y is forbidding,
     but they can be read by the x() and y() methods."""
  def __init__(self, curve, x, y, order=None):
    """curve, x, y, order; order (optional) is the order of this point."""
    self.__curve = curve
    self.__x = x
    self.__y = y
    self.__order = order
    # self.curve is allowed to be None only for INFINITY:
    if self.__curve:
      assert self.__curve.contains_point(x, y)
    if order:
      assert self * order == INFINITY

  def __eq__(self, other):
    """Return True if the points are identical, False otherwise."""
    if isinstance(other, Point):  
      return self.__curve == other.__curve \
        and self.__x == other.__x \
        and self.__y == other.__y
    return NotImplemented

  def __neg__(self):
    return Point(self.__curve, self.__x, self.__curve.p() - self.__y)

  def __add__(self, other):
    """Add one point to another point."""

    # X9.62 B.3:

    if not isinstance(other, Point):
        return NotImplemented
    if other == INFINITY:
      return self
    if self == INFINITY:
      return other
    assert self.__curve == other.__curve
    if self.__x == other.__x:
      if (self.__y + other.__y) % self.__curve.p() == 0:
        return INFINITY
      else:
        return self.double()

    p = self.__curve.p()

    l = ((other.__y - self.__y) * \
         numbertheory.inverse_mod(other.__x - self.__x, p)) % p

    x3 = (l * l - self.__x - other.__x) % p
    y3 = (l * (self.__x - x3) - self.__y) % p

    return Point(self.__curve, x3, y3)

  def __mul__(self, other):
    """Multiply a point by an integer."""

    def leftmost_bit(x):
      assert x > 0
      result = 1
      while result <= x:
        result = 2 * result
      return result // 2

    e = other
    if e == 0 or (self.__order and e % self.__order == 0):
      return INFINITY
    if self == INFINITY:
      return INFINITY
    if e < 0:
      return (-self) * (-e)

    # From X9.62 D.3.2:

    e3 = 3 * e
    negative_self = Point(self.__curve, self.__x, -self.__y, self.__order)
    i = leftmost_bit(e3) // 2
    result = self
    # print_("Multiplying %s by %d (e3 = %d):" % (self, other, e3))
    while i > 1:
      result = result.double()
      if (e3 & i) != 0 and (e & i) == 0:
        result = result + self
      if (e3 & i) == 0 and (e & i) != 0:
        result = result + negative_self
      # print_(". . . i = %d, result = %s" % ( i, result ))
      i = i // 2

    return result

  def __rmul__(self, other):
    """Multiply a point by an integer."""

    return self * other

  def __str__(self):
    if self == INFINITY:
      return "infinity"
    return "(%d,%d)" % (self.__x, self.__y)

  def double(self):
    """Return a new point that is twice the old."""

    if self == INFINITY:
      return INFINITY

    # X9.62 B.3:

    p = self.__curve.p()
    a = self.__curve.a()

    l = ((3 * self.__x * self.__x + a) * \
         numbertheory.inverse_mod(2 * self.__y, p)) % p

    x3 = (l * l - 2 * self.__x) % p
    y3 = (l * (self.__x - x3) - self.__y) % p

    return Point(self.__curve, x3, y3)

  def x(self):
    return self.__x

  def y(self):
    return self.__y

  def curve(self):
    return self.__curve

  def order(self):
    return self.__order


# This one point is the Point At Infinity for all purposes:
INFINITY = Point(None, None, None)
