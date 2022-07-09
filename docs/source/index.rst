.. python-ecdsa documentation master file, created by
   sphinx-quickstart on Sat May 29 18:34:49 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to python-ecdsa's documentation!
========================================

``ecdsa`` implements
`elliptic-curve cryptography (ECC) <https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>`_,
more specifically the
`Elliptic Curve Digital Signature Algorithm (ECDSA) <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>`_,
`Edwards-curve Digital Signature Algorithm (EdDSA) <https://en.wikipedia.org/wiki/EdDSA>`_
and the
`Elliptic Curve Diffie-Hellman (ECDH) <https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman>`_
algorithms.
All of those algorithms are used in many protocols in practice, like
in
`TLS <https://en.wikipedia.org/wiki/Transport_Layer_Security>`_
or
`SSH <https://en.wikipedia.org/wiki/Secure_Shell_Protocol>`_.

This library provides key generation, signing, verifying, and shared secret
derivation for five
popular NIST "Suite B" GF(p) (*prime field*) curves, with key lengths of 192,
224, 256, 384, and 521 bits. The "short names" for these curves, as known by
the OpenSSL tool (``openssl ecparam -list_curves``), are: ``prime192v1``,
``secp224r1``, ``prime256v1``, ``secp384r1``, and ``secp521r1``. It includes
the
256-bit curve ``secp256k1`` used by Bitcoin. There is also support for the
regular (non-twisted) variants of Brainpool curves from 160 to 512 bits. The
"short names" of those curves are: ``brainpoolP160r1``, ``brainpoolP192r1``,
``brainpoolP224r1``, ``brainpoolP256r1``, ``brainpoolP320r1``,
``brainpoolP384r1``,
``brainpoolP512r1``. Few of the small curves from SEC standard are also
included (mainly to speed-up testing of the library), those are:
``secp112r1``, ``secp112r2``, ``secp128r1``, and ``secp160r1``.
Key generation, signing and verifying is also supported for Ed25519 and Ed448
curves.
No other curves are included, but it is not too hard to add support for more
curves over prime fields.

.. toctree::
   :maxdepth: 2
   :caption: Contents:
   :hidden:

   quickstart
   basics
   ec_arithmetic
   glossary
   modules


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`glossary`
* :ref:`search`
