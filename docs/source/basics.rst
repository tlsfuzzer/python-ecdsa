==========
ECC basics
==========

The :term:`ECC`, as any asymmetric cryptography system, deals with private
keys and public keys. Private keys are generally used to create signatures,
and are kept, as the name suggest, private. That's because possession of a
private key allows creating a signature that can be verified with a public key.
If the public key is associated with an identity (like a person or an
institution), possession of the private key will allow to impersonate
that identity.

The public keys on the other hand are widely distributed, and they don't
have to be kept private. The primary purpose of them, is to allow
checking if a given signature was made with the associated private key.

On a more low level, the private key is a single number, usually the
size of the curve size: a NIST P-256 private key will have a size of 256 bits,
though as it needs to be selected randomly, it may be a slightly smaller
number (255-bit, 248-bit, etc.).
Public points are a pair of numbers. That pair specifies a point on an
elliptic curve (a pair of points that satisfy the curve equation).
Those two numbers are similarly close in size to the curve size, so both the
``x`` and ``y`` coordinate of a NIST P-256 curve will also be around 256 bit in
size.

.. note::
   To be more precise, the size of the private key is related to the
   curve *order*, i.e. the number of points on a curve. The coordinates
   of the curve depend on the *field* of the curve, which usually means the
   size of the *prime* used for operations on points. While the *order* and
   the *prime* size are related and fairly close in size, it's possible
   to have a curve where either of them is larger by a bit (i.e.
   it's possible to have a curve that uses a 256 bit prime that has a 257 bit
   order).

Since normally computers work with much smaller numbers, like 32 bit or 64 bit,
we need to use special approaches to represent numbers that are hundreds of
bits large.

First is to decide if the numbers should be stored in a big
endian format, or in little endian format. In big endian, the most
significant bits are stored first, so a number like :math:`2^{16}` is saved
as a three of byes: byte with value 1 and two bytes with value 0.
In little endian format the least significant bits are stored first, so
the number like :math:`2^{16}` would be stored as three bytes:
first two bytes with value 0, than a byte with value 1.

For :term:`ECDSA` big endian encoding is usually used, for :term:`EdDSA`
little endian encoding is usually used.

Secondly, we need to decide if the numbers need to be stored as fixed length
strings (zero padded if necessary), or if they should be stored with
minimal number of bytes necessary.
That depends on the format and place it's used, some require strict
sizes (so even if the number encoded is 1, but the curve used is 128 bit large,
that number 1 still needs to be encoded with 16 bytes, with fifteen most
significant bytes equal zero).

Generally, public keys (i.e. points) are expressed as fixed size byte strings.

While public keys can be saved as two integers, one to represent the
``x`` coordinate and one to represent ``y`` coordinate, that actually
provides a lot of redundancy. Because of the specifics of elliptic curves,
for every valid ``x`` value there are only two valid ``y`` values.
Moreover, if you have an ``x`` values, you can compute those two possible
``y`` values (if they exist).
As such, it's possible to save just the ``x`` coordinate and the sign
of the ``y`` coordinate (as the two possible values are negatives of
each-other: :math:`y_1 == -y_2`).

That gives us few options to represent the public point, the most common are:

1. As a concatenation of two fixed-length big-endian integers, so called
   :term:`raw encoding`.
2. As a concatenation of two fixed-length big-endian integers prefixed with
   the type of the encoding, so called :term:`uncompressed` point
   representation (the type is represented by a 0x04 byte).
3. As a fixed-length big-endian integer representing the ``x`` coordinate
   prefixed with the byte representing the combined type of the encoding
   and the sign of the ``y`` coordinate, so called :term:`compressed`
   point representation.

Now, while we can save the byte strings as-is and "remember" which curve
was used to generate those private and public keys, interoperability usually
requires us to also save information about the curve together with the
corresponding key. Here too there are many ways to do it:
save the parameters of the used curve explicitly, use the name of the
well-known curve as a string, use a numerical identifier of the well-known
curve, etc.

For public keys the most interoperable format is the one described
in RFC5912 (look for SubjectPublicKeyInfo structure).
For private keys, the RFC5915 format (also known as the ssleay format)
and the PKCS#8 format (described in RFC5958) are the most popular.
All of those specify a binary encoding, called DER, which can use
bytes with any values. For some uses it's useful to limit byte use
to printable characters, then the PEM formatting of the DER-encoded data
can be used.
