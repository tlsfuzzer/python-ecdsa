import os
import binascii

import ecdsa
import der
from curves import NIST192p, find_curve
from util import string_to_number_fixedlen, number_to_string, \
     string_to_randrange_trytryagain
#from util import string_to_randrange_overshoot_modulo
from util import sig_to_string, infunc_string
from util import oid_ecPublicKey, encoded_oid_ecPublicKey

default_string_to_range = string_to_randrange_trytryagain

class BadSignatureError(Exception):
    pass
class VerifyingKey:
    @classmethod
    def from_public_point(klass, point, curve=NIST192p):
        self = klass()
        self.curve = curve
        self.pubkey = ecdsa.Public_key(curve.generator, point)
        self.pubkey.order = curve.order
        return self

    @classmethod
    def from_string(klass, string, curve=NIST192p):
        order = curve.order
        assert len(string) == curve.verifying_key_length, \
               (len(string), curve.verifying_key_length)
        xs = string[:curve.baselen]
        ys = string[curve.baselen:]
        x = string_to_number_fixedlen(xs, order)
        y = string_to_number_fixedlen(ys, order)
        assert ecdsa.point_is_valid(curve.generator, x, y)
        import ellipticcurve
        point = ellipticcurve.Point(curve.curve, x, y, order)
        return klass.from_public_point(point, curve)

    @classmethod
    def from_pem(klass, string):
        return klass.from_der(der.unpem(string))

    @classmethod
    def from_der(klass, string):
        # [[oid_ecPublicKey,oid_curve], point_str_bitstring]
        s1,empty = der.remove_sequence(string)
        if empty != "":
            raise der.UnexpectedDER("trailing junk after DER pubkey: %s" %
                                    binascii.hexlify(empty))
        s2,point_str_bitstring = der.remove_sequence(s1)
        # s2 = oid_ecPublicKey,oid_curve
        oid_pk, rest = der.remove_object(s2)
        oid_curve, empty = der.remove_object(rest)
        if empty != "":
            raise der.UnexpectedDER("trailing junk after DER pubkey objects: %s" %
                                    binascii.hexlify(empty))
        assert oid_pk == oid_ecPublicKey, (oid_pk, oid_ecPublicKey)
        curve = find_curve(oid_curve)
        point_str, empty = der.remove_bitstring(point_str_bitstring)
        if empty != "":
            raise der.UnexpectedDER("trailing junk after pubkey pointstring: %s" %
                                    binascii.hexlify(empty))
        assert point_str.startswith("\x00\x04")
        return klass.from_string(point_str[2:], curve)

    def to_string(self):
        # VerifyingKey.from_string(vk.to_string()) == vk as long as the
        # curves are the same: the curve itself is not included in the
        # serialized form
        order = self.pubkey.order
        x_str = number_to_string(self.pubkey.point.x(), order)
        y_str = number_to_string(self.pubkey.point.y(), order)
        return x_str + y_str

    def to_pem(self):
        return der.topem(self.to_der(), "PUBLIC KEY")

    def to_der(self):
        order = self.pubkey.order
        x_str = number_to_string(self.pubkey.point.x(), order)
        y_str = number_to_string(self.pubkey.point.y(), order)
        point_str = "\x00\x04" + x_str + y_str
        return der.encode_sequence(der.encode_sequence(encoded_oid_ecPublicKey,
                                                       self.curve.encoded_oid),
                                   der.encode_bitstring(point_str))

    def verify(self, signature, data,
               hashfunc=default_string_to_range, infunc=infunc_string):
        r, s = infunc(signature, self.pubkey.order)
        sig = ecdsa.Signature(r, s)
        number = hashfunc(data, self.pubkey.order)
        if self.pubkey.verifies(number, sig):
            return True
        raise BadSignatureError

class SigningKey:
    @classmethod
    def generate(klass, curve=NIST192p, entropy=None):
        if entropy is None:
            entropy = os.urandom
        seed = entropy(curve.baselen)
        return klass.from_seed(seed, curve)

    @classmethod
    def from_seed(klass, seed, curve=NIST192p):
        n = curve.order
        secexp = default_string_to_range(seed, n)
        return klass.from_secret_exponent(secexp, curve)

    @classmethod
    def from_secret_exponent(klass, secexp, curve=NIST192p):
        self = klass()
        self.curve = curve
        self.baselen = curve.baselen
        n = curve.order
        assert 1 <= secexp < n
        pubkey_point = curve.generator*secexp
        pubkey = ecdsa.Public_key(curve.generator, pubkey_point)
        pubkey.order = n
        self.verifying_key = VerifyingKey.from_public_point(pubkey_point, curve)
        self.privkey = ecdsa.Private_key(pubkey, secexp)
        self.privkey.order = n
        return self

    @classmethod
    def from_string(klass, string, curve=NIST192p):
        secexp = string_to_number_fixedlen(string, curve.order)
        return klass.from_secret_exponent(secexp, curve)

    @classmethod
    def from_pem(klass, string):
        # the privkey pem file has two sections: "EC PARAMETERS" and "EC
        # PRIVATE KEY". The first is redundant.
        privkey_pem = string[string.index("-----BEGIN EC PRIVATE KEY-----"):]
        return klass.from_der(der.unpem(privkey_pem))
    @classmethod
    def from_der(klass, string):
        # SEQ([int(1), octetstring(privkey),cont[0], oid(secp224r1),cont[1],bitstring])
        s, empty = der.remove_sequence(string)
        if empty != "":
            raise der.UnexpectedDER("trailing junk after DER privkey: %s" %
                                    binascii.hexlify(empty))
        one, s = der.remove_integer(s)
        if one != 1:
            raise der.UnexpectedDER("expected '1' at start of DER privkey, got %d"
                                    % one)
        privkey_str, s = der.remove_octet_string(s)
        tag, curve_oid_str, s = der.remove_constructed(s)
        if tag != 0:
            raise der.UnexpectedDER("expected tag 0 in DER privkey, got %d" % tag)
        curve_oid, empty = der.remove_object(curve_oid_str)
        if empty != "":
            raise der.UnexpectedDER("trailing junk after DER privkey curve_oid: %s"
                                    % binascii.hexlify(empty))
        curve = find_curve(curve_oid)

        # we don't actually care about the following fields
        #
        #tag, pubkey_bitstring, s = der.remove_constructed(s)
        #if tag != 1:
        #    raise der.UnexpectedDER("expected tag 1 in DER privkey, got %d"
        #                            % tag)
        #pubkey_str = der.remove_bitstring(pubkey_bitstring)
        #if empty != "":
        #    raise der.UnexpectedDER("trailing junk after DER privkey "
        #                            "pubkeystr: %s" % binascii.hexlify(empty))

        # our from_string method likes fixed-length privkey strings
        if len(privkey_str) < curve.baselen:
            privkey_str = "\x00"*(curve.baselen-len(privkey_str)) + privkey_str
        return klass.from_string(privkey_str, curve)

    def to_string(self):
        secexp = self.privkey.secret_multiplier
        s = number_to_string(secexp, self.privkey.order)
        return s

    def to_pem(self):
        # TODO: "BEGIN ECPARAMETERS"
        return der.topem(self.to_der(), "EC PRIVATE KEY")

    def to_der(self):
        # SEQ([int(1), octetstring(privkey),cont[0], oid(secp224r1),cont[1],bitstring])
        encoded_vk = "\x00\x04" + self.get_verifying_key().to_string()
        return der.encode_sequence(der.encode_integer(1),
                                   der.encode_octet_string(self.to_string()),
                                   der.encode_constructed(0, self.curve.encoded_oid),
                                   der.encode_constructed(1, der.encode_bitstring(encoded_vk)),
                                   )

    # to serialize this, just remember the secret= you passed in.

    def get_verifying_key(self):
        return self.verifying_key

    def sign(self, data, entropy=None,
             hashfunc=default_string_to_range, outfunc=sig_to_string):
        """
        Use hashfunc=hashfunc_truncate(sha1) to match openssl's
        -ecdsa-with-SHA1 mode."""

        number = hashfunc(data, self.privkey.order)
        r, s = self.sign_number(number, entropy)
        return outfunc(r, s, self.privkey.order)

    def sign_number(self, number, entropy=None):
        # returns a pair of numbers
        order = self.privkey.order
        if entropy is None:
            entropy = os.urandom
        dont_try_forever = 1000
        while dont_try_forever > 0:
            dont_try_forever -= 1
            # the chance that we'll loop at all is like 2**-224, because most
            # of the NIST orders are close-to-but-lower-than a power of two
            k = default_string_to_range(entropy(self.baselen), order)
            assert 1 <= k < self.privkey.order
            try:
                sig = self.privkey.sign(number, k)
            except RuntimeError:
                # try again
                continue
            break
        return sig.r, sig.s
