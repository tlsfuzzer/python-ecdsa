from __future__ import with_statement, division

import pytest
import hashlib

from .six import b, binary_type
from .keys import SigningKey, VerifyingKey
from .keys import BadSignatureError
from .util import sigencode_der, sigencode_string
from .util import sigdecode_der, sigdecode_string
from .curves import curves, NIST256p, NIST521p

der_sigs = []
example_data = b("some data to sign")

# Just NIST256p with SHA256 is 560 test cases, all curves with all hashes is
# few thousand slow test cases; execute the most interesting only

#for curve in curves:
for curve in [NIST521p]:
    #for hash_alg in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]:
    for hash_alg in ["sha256"]:
        key = SigningKey.generate(curve)
        signature = key.sign(example_data, hashfunc=getattr(hashlib, hash_alg),
                             sigencode=sigencode_der)
        for pos in range(len(signature)):
            for xor in (1<<i for i in range(8)):
                der_sigs.append(pytest.param(
                    key.verifying_key, hash_alg,
                    signature, pos, xor,
                    id="{0}-{1}-pos-{2}-xor-{3}".format(
                        curve.name, hash_alg, pos, xor)))


@pytest.mark.parametrize("verifying_key,hash_alg,signature,pos,xor", der_sigs)
def test_fuzzed_der_signatures(verifying_key, hash_alg, signature, pos, xor):
    # check if a malformed DER encoded signature causes the same exception
    # to be raised irrespective of the type of error
    sig = bytearray(signature)
    sig[pos] ^= xor
    sig = binary_type(sig)

    try:
        verifying_key.verify(sig, example_data, getattr(hashlib, hash_alg),
                             sigdecode_der)
        assert False
    except BadSignatureError:
        assert True


####
#
# For string encoded signatures, only the length of string is important
#
####

str_sigs = []

#for curve in curves:
for curve in [NIST256p]:
    #for hash_alg in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]:
    for hash_alg in ["sha256"]:
        key = SigningKey.generate(curve)
        signature = key.sign(example_data, hashfunc=getattr(hashlib, hash_alg),
                             sigencode=sigencode_string)
        for trunc in range(len(signature)):
            str_sigs.append(pytest.param(
                key.verifying_key, hash_alg,
                signature, trunc,
                id="{0}-{1}-trunc-{2}".format(
                    curve.name, hash_alg, trunc)))


@pytest.mark.parametrize("verifying_key,hash_alg,signature,trunc", str_sigs)
def test_truncated_string_signatures(verifying_key, hash_alg, signature, trunc):
    # check if a malformed string encoded signature causes the same exception
    # to be raised irrespective of the type of error
    sig = bytearray(signature)
    sig = sig[:trunc]
    sig = binary_type(sig)

    try:
        verifying_key.verify(sig, example_data, getattr(hashlib, hash_alg),
                             sigdecode_string)
        assert False
    except BadSignatureError:
        assert True
