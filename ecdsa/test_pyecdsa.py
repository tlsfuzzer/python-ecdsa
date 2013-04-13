from __future__ import with_statement, division

import unittest
import os
import time
import shutil
import subprocess
from binascii import hexlify, unhexlify
from hashlib import sha1, sha256

from .six import b, print_, binary_type
from .keys import SigningKey, VerifyingKey
from .keys import BadSignatureError
from . import util
from .util import sigencode_der, sigencode_strings
from .util import sigdecode_der, sigdecode_strings
from .curves import Curve, UnknownCurveError
from .curves import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p
from . import der

class SubprocessError(Exception):
    pass

def run_openssl(cmd):
    OPENSSL = "openssl"
    p = subprocess.Popen([OPENSSL] + cmd.split(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    stdout, ignored = p.communicate()
    if p.returncode != 0:
        raise SubprocessError("cmd '%s %s' failed: rc=%s, stdout/err was %s" %
                              (OPENSSL, cmd, p.returncode, stdout))
    return stdout.decode()

BENCH = False

class ECDSA(unittest.TestCase):
    def test_basic(self):
        priv = SigningKey.generate()
        pub = priv.get_verifying_key()

        data = b("blahblah")
        sig = priv.sign(data)

        self.assertTrue(pub.verify(sig, data))
        self.assertRaises(BadSignatureError, pub.verify, sig, data+b("bad"))

        pub2 = VerifyingKey.from_string(pub.to_string())
        self.assertTrue(pub2.verify(sig, data))

    def test_bad_usage(self):
        # sk=SigningKey() is wrong
        self.assertRaises(TypeError, SigningKey)
        self.assertRaises(TypeError, VerifyingKey)

    def test_lengths(self):
        default = NIST192p
        priv = SigningKey.generate()
        pub = priv.get_verifying_key()
        self.assertEqual(len(pub.to_string()), default.verifying_key_length)
        sig = priv.sign(b("data"))
        self.assertEqual(len(sig), default.signature_length)
        if BENCH:
            print_()
        for curve in (NIST192p, NIST224p, NIST256p, NIST384p, NIST521p):
            start = time.time()
            priv = SigningKey.generate(curve=curve)
            pub1 = priv.get_verifying_key()
            keygen_time = time.time() - start
            pub2 = VerifyingKey.from_string(pub1.to_string(), curve)
            self.assertEqual(pub1.to_string(), pub2.to_string())
            self.assertEqual(len(pub1.to_string()),
                                 curve.verifying_key_length)
            start = time.time()
            sig = priv.sign(b("data"))
            sign_time = time.time() - start
            self.assertEqual(len(sig), curve.signature_length)
            if BENCH:
                start = time.time()
                pub1.verify(sig, b("data"))
                verify_time = time.time() - start
                print_("%s: siglen=%d, keygen=%0.3fs, sign=%0.3f, verify=%0.3f" \
                      % (curve.name, curve.signature_length,
                         keygen_time, sign_time, verify_time))

    def test_serialize(self):
        seed = b("secret")
        curve = NIST192p
        secexp1 = util.randrange_from_seed__trytryagain(seed, curve.order)
        secexp2 = util.randrange_from_seed__trytryagain(seed, curve.order)
        self.assertEqual(secexp1, secexp2)
        priv1 = SigningKey.from_secret_exponent(secexp1, curve)
        priv2 = SigningKey.from_secret_exponent(secexp2, curve)
        self.assertEqual(hexlify(priv1.to_string()),
                             hexlify(priv2.to_string()))
        self.assertEqual(priv1.to_pem(), priv2.to_pem())
        pub1 = priv1.get_verifying_key()
        pub2 = priv2.get_verifying_key()
        data = b("data")
        sig1 = priv1.sign(data)
        sig2 = priv2.sign(data)
        self.assertTrue(pub1.verify(sig1, data))
        self.assertTrue(pub2.verify(sig1, data))
        self.assertTrue(pub1.verify(sig2, data))
        self.assertTrue(pub2.verify(sig2, data))
        self.assertEqual(hexlify(pub1.to_string()),
                             hexlify(pub2.to_string()))

    def test_nonrandom(self):
        s = b("all the entropy in the entire world, compressed into one line")
        def not_much_entropy(numbytes):
            return s[:numbytes]
        # we control the entropy source, these two keys should be identical:
        priv1 = SigningKey.generate(entropy=not_much_entropy)
        priv2 = SigningKey.generate(entropy=not_much_entropy)
        self.assertEqual(hexlify(priv1.get_verifying_key().to_string()),
                             hexlify(priv2.get_verifying_key().to_string()))
        # likewise, signatures should be identical. Obviously you'd never
        # want to do this with keys you care about, because the secrecy of
        # the private key depends upon using different random numbers for
        # each signature
        sig1 = priv1.sign(b("data"), entropy=not_much_entropy)
        sig2 = priv2.sign(b("data"), entropy=not_much_entropy)
        self.assertEqual(hexlify(sig1), hexlify(sig2))

    def assertTruePrivkeysEqual(self, priv1, priv2):
        self.assertEqual(priv1.privkey.secret_multiplier,
                             priv2.privkey.secret_multiplier)
        self.assertEqual(priv1.privkey.public_key.generator,
                             priv2.privkey.public_key.generator)

    def failIfPrivkeysEqual(self, priv1, priv2):
        self.failIfEqual(priv1.privkey.secret_multiplier,
                         priv2.privkey.secret_multiplier)

    def test_privkey_creation(self):
        s = b("all the entropy in the entire world, compressed into one line")
        def not_much_entropy(numbytes):
            return s[:numbytes]
        priv1 = SigningKey.generate()
        self.assertEqual(priv1.baselen, NIST192p.baselen)

        priv1 = SigningKey.generate(curve=NIST224p)
        self.assertEqual(priv1.baselen, NIST224p.baselen)

        priv1 = SigningKey.generate(entropy=not_much_entropy)
        self.assertEqual(priv1.baselen, NIST192p.baselen)
        priv2 = SigningKey.generate(entropy=not_much_entropy)
        self.assertEqual(priv2.baselen, NIST192p.baselen)
        self.assertTruePrivkeysEqual(priv1, priv2)

        priv1 = SigningKey.from_secret_exponent(secexp=3)
        self.assertEqual(priv1.baselen, NIST192p.baselen)
        priv2 = SigningKey.from_secret_exponent(secexp=3)
        self.assertTruePrivkeysEqual(priv1, priv2)

        priv1 = SigningKey.from_secret_exponent(secexp=4, curve=NIST224p)
        self.assertEqual(priv1.baselen, NIST224p.baselen)

    def test_privkey_strings(self):
        priv1 = SigningKey.generate()
        s1 = priv1.to_string()
        self.assertEqual(type(s1), binary_type)
        self.assertEqual(len(s1), NIST192p.baselen)
        priv2 = SigningKey.from_string(s1)
        self.assertTruePrivkeysEqual(priv1, priv2)

        s1 = priv1.to_pem()
        self.assertEqual(type(s1), binary_type)
        self.assertTrue(s1.startswith(b("-----BEGIN EC PRIVATE KEY-----")))
        self.assertTrue(s1.strip().endswith(b("-----END EC PRIVATE KEY-----")))
        priv2 = SigningKey.from_pem(s1)
        self.assertTruePrivkeysEqual(priv1, priv2)

        s1 = priv1.to_der()
        self.assertEqual(type(s1), binary_type)
        priv2 = SigningKey.from_der(s1)
        self.assertTruePrivkeysEqual(priv1, priv2)

        priv1 = SigningKey.generate(curve=NIST256p)
        s1 = priv1.to_pem()
        self.assertEqual(type(s1), binary_type)
        self.assertTrue(s1.startswith(b("-----BEGIN EC PRIVATE KEY-----")))
        self.assertTrue(s1.strip().endswith(b("-----END EC PRIVATE KEY-----")))
        priv2 = SigningKey.from_pem(s1)
        self.assertTruePrivkeysEqual(priv1, priv2)

        s1 = priv1.to_der()
        self.assertEqual(type(s1), binary_type)
        priv2 = SigningKey.from_der(s1)
        self.assertTruePrivkeysEqual(priv1, priv2)

    def assertTruePubkeysEqual(self, pub1, pub2):
        self.assertEqual(pub1.pubkey.point, pub2.pubkey.point)
        self.assertEqual(pub1.pubkey.generator, pub2.pubkey.generator)
        self.assertEqual(pub1.curve, pub2.curve)

    def test_pubkey_strings(self):
        priv1 = SigningKey.generate()
        pub1 = priv1.get_verifying_key()
        s1 = pub1.to_string()
        self.assertEqual(type(s1), binary_type)
        self.assertEqual(len(s1), NIST192p.verifying_key_length)
        pub2 = VerifyingKey.from_string(s1)
        self.assertTruePubkeysEqual(pub1, pub2)

        priv1 = SigningKey.generate(curve=NIST256p)
        pub1 = priv1.get_verifying_key()
        s1 = pub1.to_string()
        self.assertEqual(type(s1), binary_type)
        self.assertEqual(len(s1), NIST256p.verifying_key_length)
        pub2 = VerifyingKey.from_string(s1, curve=NIST256p)
        self.assertTruePubkeysEqual(pub1, pub2)

        pub1_der = pub1.to_der()
        self.assertEqual(type(pub1_der), binary_type)
        pub2 = VerifyingKey.from_der(pub1_der)
        self.assertTruePubkeysEqual(pub1, pub2)

        self.assertRaises(der.UnexpectedDER,
                              VerifyingKey.from_der, pub1_der+b("junk"))
        badpub = VerifyingKey.from_der(pub1_der)
        class FakeGenerator:
            def order(self): return 123456789
        badcurve = Curve("unknown", None, FakeGenerator(), (1,2,3,4,5,6))
        badpub.curve = badcurve
        badder = badpub.to_der()
        self.assertRaises(UnknownCurveError, VerifyingKey.from_der, badder)

        pem = pub1.to_pem()
        self.assertEqual(type(pem), binary_type)
        self.assertTrue(pem.startswith(b("-----BEGIN PUBLIC KEY-----")), pem)
        self.assertTrue(pem.strip().endswith(b("-----END PUBLIC KEY-----")), pem)
        pub2 = VerifyingKey.from_pem(pem)
        self.assertTruePubkeysEqual(pub1, pub2)

    def test_signature_strings(self):
        priv1 = SigningKey.generate()
        pub1 = priv1.get_verifying_key()
        data = b("data")

        sig = priv1.sign(data)
        self.assertEqual(type(sig), binary_type)
        self.assertEqual(len(sig), NIST192p.signature_length)
        self.assertTrue(pub1.verify(sig, data))

        sig = priv1.sign(data, sigencode=sigencode_strings)
        self.assertEqual(type(sig), tuple)
        self.assertEqual(len(sig), 2)
        self.assertEqual(type(sig[0]), binary_type)
        self.assertEqual(type(sig[1]), binary_type)
        self.assertEqual(len(sig[0]), NIST192p.baselen)
        self.assertEqual(len(sig[1]), NIST192p.baselen)
        self.assertTrue(pub1.verify(sig, data, sigdecode=sigdecode_strings))

        sig_der = priv1.sign(data, sigencode=sigencode_der)
        self.assertEqual(type(sig_der), binary_type)
        self.assertTrue(pub1.verify(sig_der, data, sigdecode=sigdecode_der))

    def test_hashfunc(self):
        sk = SigningKey.generate(curve=NIST256p, hashfunc=sha256)
        data = b("security level is 128 bits")
        sig = sk.sign(data)
        vk = VerifyingKey.from_string(sk.get_verifying_key().to_string(),
                                      curve=NIST256p, hashfunc=sha256)
        self.assertTrue(vk.verify(sig, data))

        sk2 = SigningKey.generate(curve=NIST256p)
        sig2 = sk2.sign(data, hashfunc=sha256)
        vk2 = VerifyingKey.from_string(sk2.get_verifying_key().to_string(),
                                       curve=NIST256p, hashfunc=sha256)
        self.assertTrue(vk2.verify(sig2, data))

        vk3 = VerifyingKey.from_string(sk.get_verifying_key().to_string(),
                                       curve=NIST256p)
        self.assertTrue(vk3.verify(sig, data, hashfunc=sha256))


class OpenSSL(unittest.TestCase):
    # test interoperability with OpenSSL tools. Note that openssl's ECDSA
    # sign/verify arguments changed between 0.9.8 and 1.0.0: the early
    # versions require "-ecdsa-with-SHA1", the later versions want just
    # "-SHA1" (or to leave out that argument entirely, which means the
    # signature will use some default digest algorithm, probably determined
    # by the key, probably always SHA1).
    #
    # openssl ecparam -name secp224r1 -genkey -out privkey.pem
    # openssl ec -in privkey.pem -text -noout # get the priv/pub keys
    # openssl dgst -ecdsa-with-SHA1 -sign privkey.pem -out data.sig data.txt
    # openssl asn1parse -in data.sig -inform DER
    #  data.sig is 64 bytes, probably 56b plus ASN1 overhead
    # openssl dgst -ecdsa-with-SHA1 -prverify privkey.pem -signature data.sig data.txt ; echo $?
    # openssl ec -in privkey.pem -pubout -out pubkey.pem
    # openssl ec -in privkey.pem -pubout -outform DER -out pubkey.der

    def get_openssl_messagedigest_arg(self):
        v = run_openssl("version")
        # e.g. "OpenSSL 1.0.0 29 Mar 2010", or "OpenSSL 1.0.0a 1 Jun 2010",
        # or "OpenSSL 0.9.8o 01 Jun 2010"
        vs = v.split()[1].split(".")
        if vs >= ["1","0","0"]:
            return "-SHA1"
        else:
            return "-ecdsa-with-SHA1"

    # sk: 1:OpenSSL->python  2:python->OpenSSL
    # vk: 3:OpenSSL->python  4:python->OpenSSL
    # sig: 5:OpenSSL->python 6:python->OpenSSL

    def test_from_openssl_nist192p(self):
        return self.do_test_from_openssl(NIST192p, "prime192v1")
    def test_from_openssl_nist224p(self):
        return self.do_test_from_openssl(NIST224p, "secp224r1")
    def test_from_openssl_nist384p(self):
        return self.do_test_from_openssl(NIST384p, "secp384r1")
    def test_from_openssl_nist521p(self):
        return self.do_test_from_openssl(NIST521p, "secp521r1")

    def do_test_from_openssl(self, curve, curvename):
        # OpenSSL: create sk, vk, sign.
        # Python: read vk(3), checksig(5), read sk(1), sign, check
        mdarg = self.get_openssl_messagedigest_arg()
        if os.path.isdir("t"):
            shutil.rmtree("t")
        os.mkdir("t")
        run_openssl("ecparam -name %s -genkey -out t/privkey.pem" % curvename)
        run_openssl("ec -in t/privkey.pem -pubout -out t/pubkey.pem")
        data = b("data")
        with open("t/data.txt","wb") as e: e.write(data)
        run_openssl("dgst %s -sign t/privkey.pem -out t/data.sig t/data.txt" % mdarg)
        run_openssl("dgst %s -verify t/pubkey.pem -signature t/data.sig t/data.txt" % mdarg)
        with open("t/pubkey.pem","rb") as e: pubkey_pem = e.read()
        vk = VerifyingKey.from_pem(pubkey_pem) # 3
        with open("t/data.sig","rb") as e: sig_der = e.read()
        self.assertTrue(vk.verify(sig_der, data, # 5
                                  hashfunc=sha1, sigdecode=sigdecode_der))

        with open("t/privkey.pem") as e: fp = e.read()
        sk = SigningKey.from_pem(fp) # 1
        sig = sk.sign(data)
        self.assertTrue(vk.verify(sig, data))

    def test_to_openssl_nist192p(self):
        self.do_test_to_openssl(NIST192p, "prime192v1")
    def test_to_openssl_nist224p(self):
        self.do_test_to_openssl(NIST224p, "secp224r1")
    def test_to_openssl_nist384p(self):
        self.do_test_to_openssl(NIST384p, "secp384r1")
    def test_to_openssl_nist521p(self):
        self.do_test_to_openssl(NIST521p, "secp521r1")

    def do_test_to_openssl(self, curve, curvename):
        # Python: create sk, vk, sign.
        # OpenSSL: read vk(4), checksig(6), read sk(2), sign, check
        mdarg = self.get_openssl_messagedigest_arg()
        if os.path.isdir("t"):
            shutil.rmtree("t")
        os.mkdir("t")
        sk = SigningKey.generate(curve=curve)
        vk = sk.get_verifying_key()
        data = b("data")
        with open("t/pubkey.der","wb") as e: e.write(vk.to_der()) # 4
        with open("t/pubkey.pem","wb") as e: e.write(vk.to_pem()) # 4
        sig_der = sk.sign(data, hashfunc=sha1, sigencode=sigencode_der)

        with open("t/data.sig","wb") as e: e.write(sig_der) # 6
        with open("t/data.txt","wb") as e: e.write(data)
        with open("t/baddata.txt","wb") as e: e.write(data+b("corrupt"))

        self.assertRaises(SubprocessError, run_openssl,
                              "dgst %s -verify t/pubkey.der -keyform DER -signature t/data.sig t/baddata.txt" % mdarg)
        run_openssl("dgst %s -verify t/pubkey.der -keyform DER -signature t/data.sig t/data.txt" % mdarg)

        with open("t/privkey.pem","wb") as e: e.write(sk.to_pem()) # 2
        run_openssl("dgst %s -sign t/privkey.pem -out t/data.sig2 t/data.txt" % mdarg)
        run_openssl("dgst %s -verify t/pubkey.pem -signature t/data.sig2 t/data.txt" % mdarg)

class DER(unittest.TestCase):
    def test_oids(self):
        oid_ecPublicKey = der.encode_oid(1, 2, 840, 10045, 2, 1)
        self.assertEqual(hexlify(oid_ecPublicKey), b("06072a8648ce3d0201"))
        self.assertEqual(hexlify(NIST224p.encoded_oid), b("06052b81040021"))
        self.assertEqual(hexlify(NIST256p.encoded_oid),
                             b("06082a8648ce3d030107"))
        x = oid_ecPublicKey + b("more")
        x1, rest = der.remove_object(x)
        self.assertEqual(x1, (1, 2, 840, 10045, 2, 1))
        self.assertEqual(rest, b("more"))

    def test_integer(self):
        self.assertEqual(der.encode_integer(0), b("\x02\x01\x00"))
        self.assertEqual(der.encode_integer(1), b("\x02\x01\x01"))
        self.assertEqual(der.encode_integer(127), b("\x02\x01\x7f"))
        self.assertEqual(der.encode_integer(128), b("\x02\x02\x00\x80"))
        self.assertEqual(der.encode_integer(256), b("\x02\x02\x01\x00"))
        #self.assertEqual(der.encode_integer(-1), b("\x02\x01\xff"))

        def s(n): return der.remove_integer(der.encode_integer(n) + b("junk"))
        self.assertEqual(s(0), (0, b("junk")))
        self.assertEqual(s(1), (1, b("junk")))
        self.assertEqual(s(127), (127, b("junk")))
        self.assertEqual(s(128), (128, b("junk")))
        self.assertEqual(s(256), (256, b("junk")))
        self.assertEqual(s(1234567890123456789012345678901234567890),
                             (1234567890123456789012345678901234567890,b("junk")))

    def test_number(self):
        self.assertEqual(der.encode_number(0), b("\x00"))
        self.assertEqual(der.encode_number(127), b("\x7f"))
        self.assertEqual(der.encode_number(128), b("\x81\x00"))
        self.assertEqual(der.encode_number(3*128+7), b("\x83\x07"))
        #self.assertEqual(der.read_number("\x81\x9b"+"more"), (155, 2))
        #self.assertEqual(der.encode_number(155), b("\x81\x9b"))
        for n in (0, 1, 2, 127, 128, 3*128+7, 840, 10045): #, 155):
            x = der.encode_number(n) + b("more")
            n1, llen = der.read_number(x)
            self.assertEqual(n1, n)
            self.assertEqual(x[llen:], b("more"))

    def test_length(self):
        self.assertEqual(der.encode_length(0), b("\x00"))
        self.assertEqual(der.encode_length(127), b("\x7f"))
        self.assertEqual(der.encode_length(128), b("\x81\x80"))
        self.assertEqual(der.encode_length(255), b("\x81\xff"))
        self.assertEqual(der.encode_length(256), b("\x82\x01\x00"))
        self.assertEqual(der.encode_length(3*256+7), b("\x82\x03\x07"))
        self.assertEqual(der.read_length(b("\x81\x9b")+b("more")), (155, 2))
        self.assertEqual(der.encode_length(155), b("\x81\x9b"))
        for n in (0, 1, 2, 127, 128, 255, 256, 3*256+7, 155):
            x = der.encode_length(n) + b("more")
            n1, llen = der.read_length(x)
            self.assertEqual(n1, n)
            self.assertEqual(x[llen:], b("more"))

    def test_sequence(self):
        x = der.encode_sequence(b("ABC"), b("DEF")) + b("GHI")
        self.assertEqual(x, b("\x30\x06ABCDEFGHI"))
        x1, rest = der.remove_sequence(x)
        self.assertEqual(x1, b("ABCDEF"))
        self.assertEqual(rest, b("GHI"))

    def test_constructed(self):
        x = der.encode_constructed(0, NIST224p.encoded_oid)
        self.assertEqual(hexlify(x), b("a007") + b("06052b81040021"))
        x = der.encode_constructed(1, unhexlify(b("0102030a0b0c")))
        self.assertEqual(hexlify(x), b("a106") + b("0102030a0b0c"))

class Util(unittest.TestCase):
    def test_trytryagain(self):
        tta = util.randrange_from_seed__trytryagain
        for i in range(1000):
            seed = "seed-%d" % i
            for order in (2**8-2, 2**8-1, 2**8, 2**8+1, 2**8+2,
                          2**16-1, 2**16+1):
                n = tta(seed, order)
                self.assertTrue(1 <= n < order, (1, n, order))
        # this trytryagain *does* provide long-term stability
        self.assertEqual(("%x"%(tta("seed", NIST224p.order))).encode(),
                             b("6fa59d73bf0446ae8743cf748fc5ac11d5585a90356417e97155c3bc"))

    def test_randrange(self):
        # util.randrange does not provide long-term stability: we might
        # change the algorithm in the future.
        for i in range(1000):
            entropy = util.PRNG("seed-%d" % i)
            for order in (2**8-2, 2**8-1, 2**8,
                          2**16-1, 2**16+1,
                          ):
                # that oddball 2**16+1 takes half our runtime
                n = util.randrange(order, entropy=entropy)
                self.assertTrue(1 <= n < order, (1, n, order))

    def OFF_test_prove_uniformity(self):
        order = 2**8-2
        counts = dict([(i, 0) for i in range(1, order)])
        assert 0 not in counts
        assert order not in counts
        for i in range(1000000):
            seed = "seed-%d" % i
            n = util.randrange_from_seed__trytryagain(seed, order)
            counts[n] += 1
        # this technique should use the full range
        self.assertTrue(counts[order-1])
        for i in range(1, order):
            print_("%3d: %s" % (i, "*"*(counts[i]//100)))
            

def __main__():
    unittest.main()
if __name__ == "__main__":
    __main__()
