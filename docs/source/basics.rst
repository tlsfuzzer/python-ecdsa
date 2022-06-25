======================
Basics of ECC handling
======================

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

Number representations
======================

On a more low level, the private key is a single number, usually the
size of the curve size: a NIST P-256 private key will have a size of 256 bits,
though as it needs to be selected randomly, it may be a slightly smaller
number (255-bit, 248-bit, etc.).
Public points are a pair of numbers. That pair specifies a point on an
elliptic curve (a pair of integers that satisfy the curve equation).
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
   it's possible to have a curve that uses a 256 bit *prime* that has a 257 bit
   *order*).

Since normally computers work with much smaller numbers, like 32 bit or 64 bit,
we need to use special approaches to represent numbers that are hundreds of
bits large.

First is to decide if the numbers should be stored in a big
endian format, or in little endian format. In big endian, the most
significant bits are stored first, so a number like :math:`2^{16}` is saved
as a three bytes: byte with value 1 and two bytes with value 0.
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

Public key encoding
===================

Generally, public keys (i.e. points) are expressed as fixed size byte strings.

While public keys can be saved as two integers, one to represent the
``x`` coordinate and one to represent ``y`` coordinate, that actually
provides a lot of redundancy. Because of the specifics of elliptic curves,
for every valid ``x`` value there are only two valid ``y`` values.
Moreover, if you have an ``x`` value, you can compute those two possible
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
   point representation (the type is then represented by a 0x02 or a 0x03
   byte).

Interoperable file formats
==========================

Now, while we can save the byte strings as-is and "remember" which curve
was used to generate those private and public keys, interoperability usually
requires to also save information about the curve together with the
corresponding key. Here too there are many ways to do it:
save the parameters of the used curve explicitly, use the name of the
well-known curve as a string, use a numerical identifier of the well-known
curve, etc.

For public keys the most interoperable format is the one described
in RFC5912 (look for SubjectPublicKeyInfo structure).
For private keys, the RFC5915 format (also known as the ssleay format)
and the PKCS#8 format (described in RFC5958) are the most popular.

All three formats effectively support two ways of providing the information
about the curve used: by specifying the curve parameters explicitly or
by specifying the curve using ASN.1 OBJECT IDENTIFIER (OID), which is
called ``named_curve``. ASN.1 OIDs are a hierarchical system of representing
types of objects, for example, NIST P-256 curve is identified by the
1.2.840.10045.3.1.7 OID (in dotted-decimal formatting of the OID, also
known by the ``prime256v1`` OID node name or short name). Those OIDs
uniquely, identify a particular curve, but the receiver needs to know
which numerical OID maps to which curve parameters. Thus the prospect of
using the explicit encoding, where all the needed parameters are provided
is tempting, the downside is that curve parameters may specify a *weak*
curve, which is easy to attack and break (that is to deduce the private key
from the public key). To verify curve parameters is complex and computationally
expensive, thus generally protocols use few specific curves and require
all implementations to carry the parameters of them. As such, use of
``named_curve`` parameters is generally recommended.

All of the mentioned formats specify a binary encoding, called DER. That
encoding uses bytes with all possible numerical values, which means it's not
possible to embed it directly in text files. For uses where it's useful to
limit bytes to printable characters, so that the keys can be embedded in text
files or text-only protocols (like email), the PEM formatting of the
DER-encoded data can be used. The PEM formatting is just a base64 encoding
with appropriate header and footer.

Signature formats
=================

Finally, ECDSA signatures at the lowest level are a pair of numbers, usually
called ``r`` and ``s``. While they are the ``x`` coordinates of special
points on the curve, they are saved modulo *order* of the curve, not
modulo *prime* of the curve (as a coordinate needs to be).

That again means we have multiple ways of encoding those two numbers.
The two most popular formats are to save them as a concatenation of big-endian
integers of fixed size (determined by the curve *order*) or as a DER
structure with two INTEGERS.
The first of those is called the :term:``raw encoding`` inside the Python
ecdsa library.

As ASN.1 signature format requires the encoding of INTEGERS, and DER INTEGERs
must use the fewest possible number of bytes, a numerically small value of
``r`` or ``s`` will require fewer
bytes to represent in the DER structure. Thus, DER encoding isn't fixed
size for a given curve, but has a maximum possible size.

.. note::

    As DER INTEGER uses so-called two's complement representation of
    numbers, the most significant bit of the most significant byte
    represents the *sign* of the number. If that bit is set, then the
    number is considered to be negative. Thus, to represent a number like
    255, which in binary representation is 0b11111111 (i.e. a byte with all
    bits set high), the DER encoding of it will require two bytes, one
    zero byte to make sure the sign bit is 0, and a byte with value 255 to
    encode the numerical value of the integer.
