===============
Getting started
===============

The library has just one mandatory dependency: ``six``.
If you install ``python-ecdsa`` through pip, it should automatically
install ``six`` too.

To install it you can run the following command:

.. code:: bash

    pip install ecdsa

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

Key generation
==============

To generate a key, import the :py:class:`~ecdsa.keys.SigningKey` and
call the :py:func:`~ecdsa.keys.SigningKey.generate` function in it:

.. code:: python

    from ecdsa.keys import SigningKey

    key = SigningKey.generate()

By default, that will create a key that uses the NIST P-192 curve. To
select a more secure curve, like NIST P-256, import it from the
:py:mod:`ecdsa.curves` or from the :py:mod:`ecdsa` module:

.. code:: python

    from ecdsa import SigningKey, NIST256p

    key = SigningKey.generate(curve=NIST256p)

Private key storage and retrieval
=================================

To store a key as string or file, you can serialise it using many formats,
in general we recommend the PKCS#8 PEM encoding.

If you have a :py:class:`~ecdsa.keys.SigningKey` object in ``key`` and
want to save it to a file like ``priv_key.pem`` you can run the following
code:

.. code:: python

    with open("priv_key.pem", "wb") as f:
        f.write(key.to_pem(format="pkcs8"))

.. warning::

    Not specifying the ``format=pkcs8`` will create a file that uses the legacy
    ``ssleay`` file format which is most commonly used by applications
    that use OpenSSL, as that was originally the only format supported by it.
    For a long time though OpenSSL supports the PKCS# 8 format too.

To read that file back, you can run code like this:

.. code:: python

    from ecdsa import SigningKey

    with open("priv_key.pem") as f:
        key = SigningKey.from_pem(f.read())

.. tip::

    As the format is self-describing, the parser will automatically detect
    if the provided file is in the ``ssleay`` or the ``pkcs8`` format
    and process it accordingly.

Public key derivation
=====================

To get the public key associated with the given private key, either
call the :py:func:`~ecdsa.keys.SigningKey.get_verifying_key` method or
access the ``verifying_key`` attribute in
:py:class:`~ecdsa.keys.SigningKey` directly:

.. code:: python

    from ecdsa import SigningKey, NIST256p

    private_key = SigningKey.generate(curve=NIST256p)

    public_key = private_key.verifying_key

Public key storage and retrieval
================================

Similarly to private keys, public keys can be stored in files:

.. code:: python

    from ecdsa import SigningKey

    private_key = SigningKey.generate()

    public_key = private_key.verifying_key

    with open("pub_key.pem", "wb") as f:
        f.write(public_key.to_pem())

And read from files:

.. code:: python

    from ecdsa import VerifyingKey

    with open("pub_key.pem") as f:
        public_key = VerifyingKey.from_pem(f.read())

Signing
=======

To sign a byte string stored in variable ``message`` using SigningKey in
``private_key``, SHA-256, get a signature in the DER format and save it to a
file, you can use the following code:

.. code:: python

    from hashlib import sha256
    from ecdsa.util import sigencode_der

    sig = private_key.sign_deterministic(
        message,
        hashfunc=sha256,
        sigencode=sigencode_der
    )

    with open("message.sig", "wb") as f:
        f.write(sig)

.. note::

    As cryptographic hashes (SHA-256, SHA3-256, etc.) operate on *bytes* not
    text strings, any text needs to be serialised into *bytes* before it can
    be signed. This is because encoding of string "text" results in very
    different bytes when it's encoded using UTF-8 and when it's encoded using
    UCS-2.

Verifying
=========

To verify a signature of a byte string in ``message`` using a VerifyingKey
in ``public_key``, SHA-256 and a DER signature in a ``message.sig`` file,
you can use the following code:

.. code:: python

    from hashlib import sha256
    from ecdsa import BadSignatureError
    from ecdsa.util import sigdecode_der

    with open("message.sig", "rb") as f:
        sig = f.read()

    try:
        ret = public_key.verify(sig, message, sha256, sigdecode=sigdecode_der)
        assert ret
        print("Valid signature")
    except BadSignatureError:
        print("Incorrect signature")
