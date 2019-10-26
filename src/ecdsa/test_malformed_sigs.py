from __future__ import with_statement, division

import hashlib
try:
    from hashlib import algorithms_available
except ImportError:
    algorithms_available = [
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
from functools import partial
import pytest
import sys
from six import binary_type
import hypothesis.strategies as st
from hypothesis import note, assume, given, settings

from .keys import SigningKey
from .keys import BadSignatureError
from .util import sigencode_der, sigencode_string
from .util import sigdecode_der, sigdecode_string
from .curves import curves, NIST256p
from .der import encode_integer, encode_sequence


example_data = b"some data to sign"
"""Since the data is hashed for processing, really any string will do."""


hash_and_size = [(name, hashlib.new(name).digest_size)
                 for name in algorithms_available]
"""Pairs of hash names and their output sizes.
Needed for pairing with curves as we don't support hashes
bigger than order sizes of curves."""


keys_and_sigs = []
"""Name of the curve+hash combination, VerifyingKey and DER signature."""


# for hypothesis strategy shrinking we want smallest curves and hashes first
for curve in sorted(curves, key=lambda x: x.baselen):
    for hash_alg in [name for name, size in
                     sorted(hash_and_size, key=lambda x: x[1])
                     if 0 < size <= curve.baselen]:
        sk = SigningKey.generate(
            curve,
            hashfunc=partial(hashlib.new, hash_alg))

        keys_and_sigs.append(
            ("{0} {1}".format(curve, hash_alg),
             sk.verifying_key,
             sk.sign(example_data, sigencode=sigencode_der)))


# first make sure that the signatures can be verified
@pytest.mark.parametrize(
    "verifying_key,signature",
    [pytest.param(vk, sig, id=name) for name, vk, sig in keys_and_sigs])
def test_signatures(verifying_key, signature):
    assert verifying_key.verify(signature, example_data,
                                sigdecode=sigdecode_der)


@st.composite
def st_fuzzed_sig(draw):
    """
    Hypothesis strategy that generates pairs of VerifyingKey and malformed
    signatures created by fuzzing of a valid signature.
    """
    name, verifying_key, old_sig = draw(st.sampled_from(keys_and_sigs))
    note("Configuration: {0}".format(name))

    sig = bytearray(old_sig)

    # decide which bytes should be removed
    to_remove = draw(st.lists(
        st.integers(min_value=0, max_value=len(sig)-1),
        unique=True))
    to_remove.sort()
    for i in reversed(to_remove):
        del sig[i]
    note("Remove bytes: {0}".format(to_remove))

    # decide which bytes of the original signature should be changed
    xors = draw(st.dictionaries(
        st.integers(min_value=0, max_value=len(sig)-1),
        st.integers(min_value=1, max_value=255)))
    for i, val in xors.items():
        sig[i] ^= val
    note("xors: {0}".format(xors))

    # decide where new data should be inserted
    insert_pos = draw(st.integers(min_value=0, max_value=len(sig)))
    # NIST521p signature is about 140 bytes long, test slightly longer
    insert_data = draw(st.binary(max_size=256))

    sig = sig[:insert_pos] + insert_data + sig[insert_pos:]
    note("Inserted at position {0} bytes: {1!r}"
         .format(insert_pos, insert_data))

    sig = bytes(sig)
    # make sure that there was performed at least one mutation on the data
    assume(to_remove or xors or insert_data)
    # and that the mutations didn't cancel each-other out
    assume(sig != old_sig)

    return verifying_key, sig


params = {}
# not supported in hypothesis 2.0.0
if sys.version_info >= (2, 7):
    # deadline=5s because NIST521p are slow to verify
    params["deadline"] = 5000


@settings(**params)
@given(st_fuzzed_sig())
def test_fuzzed_der_signatures(args):
    verifying_key, sig = args

    with pytest.raises(BadSignatureError):
        verifying_key.verify(sig, example_data, sigdecode=sigdecode_der)


@st.composite
def st_random_der_ecdsa_sig_value(draw):
    """
    Hypothesis strategy for selecting random values and encoding them
    to ECDSA-Sig-Value object::

        ECDSA-Sig-Value ::= SEQUENCE {
            r INTEGER,
            s INTEGER
        }
    """
    name, verifying_key, _ = draw(st.sampled_from(keys_and_sigs))
    note("Configuration: {0}".format(name))
    order = verifying_key.curve.order

    # the encode_integer doesn't suport negative numbers, would be nice
    # to generate them too, but we have coverage for remove_integer()
    # verifying that it doesn't accept them, so meh.
    # Test all numbers around the ones that can show up (around order)
    # way smaller and slightly bigger
    r = draw(st.integers(min_value=0, max_value=order << 4) |
             st.integers(min_value=order >> 2, max_value=order+1))
    s = draw(st.integers(min_value=0, max_value=order << 4) |
             st.integers(min_value=order >> 2, max_value=order+1))

    sig = encode_sequence(encode_integer(r), encode_integer(s))

    return verifying_key, sig


@given(st_random_der_ecdsa_sig_value())
def test_random_der_ecdsa_sig_value(params):
    """
    Check if random values encoded in ECDSA-Sig-Value structure are rejected
    as signature.
    """
    verifying_key, sig = params

    with pytest.raises(BadSignatureError):
        verifying_key.verify(sig, example_data, sigdecode=sigdecode_der)


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
