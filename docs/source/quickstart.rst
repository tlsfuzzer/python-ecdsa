===============
Getting started
===============

The library has just one mandatory dependency: ``six``.
If you install ``python-ecdsa`` through pip, it should automatically
install ``six`` too.

The high level API provided by the library is primarily in the
:py:class:`~ecdsa.keys` module.
There you will find the :py:class:`~ecdsa.keys.SigningKey` (the class
that enables handling of the private keys) and the
:py:class:`~ecdsa.keys.VerifyingKey` (the class that enables handling of
the public keys).

To handle shared key derivation, the :py:class:`~ecdsa.ecdh.ECDH` class
is used.

Finally, in case use of custom elliptic curves is necessary, the
:py:class:`~ecdsa.curves.Curve` class may be needed.

