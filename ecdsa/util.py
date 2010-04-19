
import math
import binascii
from hashlib import sha256, sha512
import der
from curves import orderlen

# RFC5480:
#   The "unrestricted" algorithm identifier is:
#     id-ecPublicKey OBJECT IDENTIFIER ::= {
#       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }

oid_ecPublicKey = (1, 2, 840, 10045, 2, 1)
encoded_oid_ecPublicKey = der.encode_oid(*oid_ecPublicKey)

class PRNG:
    # this returns a callable which, when invoked with an integer N, will
    # return N pseudorandom bytes.
    def __init__(self, seed):
        self.generator = self.block_generator(seed)

    def __call__(self, numbytes):
        return "".join([self.generator.next() for i in range(numbytes)])

    def block_generator(self, seed):
        counter = 0
        while True:
            for byte in sha256("prng-%d-%s" % (counter, seed)).digest():
                yield byte
            counter += 1

def string_to_randrange_overshoot_modulo(seed, order):
    # hash the data, then turn the digest into a number in [1,order).
    #
    # We use David-Sarah Hopwood's suggestion: turn it into a number that's
    # sufficiently larger than the group order, then modulo it down to fit.
    # This should give adequate (but not perfect) uniformity, and simple
    # code. There are other choices: try-try-again is the main one.
    base = PRNG(seed)(2*orderlen(order))
    number = (int(binascii.hexlify(base), 16) % (order-1)) + 1
    assert 1 <= number < order, (1, number, order)
    return number

def lsb_of_ones(numbits):
    return (1 << numbits) - 1

def string_to_randrange_truncate_bytes(data, order, hashmod=sha256):
    # hash the data, then turn the digest into a number in [1,order), but
    # don't worry about trying to uniformly fill the range. This will lose,
    # on average, half a byte of entropy.
    bits = int(math.log(order-1, 2)+1)
    bytes = bits // 8
    base = hashmod(data).digest()[:bytes]
    base = "\x00"*(bytes-len(base)) + base
    number = 1+int(binascii.hexlify(base), 16)
    assert 1 <= number < order
    return number

def string_to_randrange_truncate_bits(data, order, hashmod=sha256):
    # like string_to_randrange_truncate_bytes, but only lose an average of
    # half a bit
    bits = int(math.log(order-1, 2)+1)
    maxbytes = (bits+7) // 8
    base = hashmod(data).digest()[:maxbytes]
    base = "\x00"*(maxbytes-len(base)) + base
    topbits = 8*maxbytes - bits
    if topbits:
        base = chr(ord(base[0]) & lsb_of_ones(topbits)) + base[1:]
    number = 1+int(binascii.hexlify(base), 16)
    assert 1 <= number < order
    return number

def string_to_randrange_trytryagain(data, order):
    base = PRNG(data)
    # figure out exactly how many bits we need (rounded up to the nearest
    # bit), so we can reduce the chance of looping to less than 0.5 . This is
    # specified to feed from a byte-oriented PRNG, and discards the
    # high-order bits of the first byte as necessary to get the right number
    # of bits.
    bits = int(math.log(order, 2)+1)
    bytes = bits // 8
    extrabits = bits - 8*bytes
    while True:
        extrabyte = ""
        if extrabits:
            extrabyte = chr(ord(base(1)) & lsb_of_ones(extrabits))
        guess = string_to_number(extrabyte + base(bytes))
        if 1 <= guess < order:
            return guess

def OLDstring_to_randrange_truncate(data, order):
    # hash the data, then turn the digest into a number in [1,order), but
    # don't worry about trying to uniformly fill the range
    h = 4*sha512(data).hexdigest()
    olen = len("%x" % order)
    assert len(h) > 2*olen, (len(h), olen)
    number = (int(h, 16) % (order-1)) + 1
    assert 1 <= number < order, (1, number, order)
    return number

def number_to_string(num, order):
    l = orderlen(order)
    fmt_str = "%0" + str(2*l) + "x"
    string = binascii.unhexlify(fmt_str % num)
    assert len(string) == l, (len(string), l)
    return string

def hashfunc_truncate(hashclass):
    def hashfunc(string, order):
        h = hashclass(string).digest()
        h = "\x00"*(orderlen(order)-len(h)) + h # pad to size
        number = string_to_number_fixedlen(h, order)
        return number
    return hashfunc

def string_to_number(string):
    return int(binascii.hexlify(string), 16)

def string_to_number_fixedlen(string, order):
    l = orderlen(order)
    assert len(string) == l, (len(string), l)
    return int(binascii.hexlify(string), 16)

def sig_to_strings(r, s, order):
    r_str = number_to_string(r, order)
    s_str = number_to_string(s, order)
    return (r_str, s_str)

def sig_to_string(r, s, order):
    # for any given curve, the size of the signature numbers is
    # fixed, so just use simple concatenation
    r_str, s_str = sig_to_strings(r, s, order)
    return r_str + s_str

def sig_to_der(r, s, order):
    return der.encode_sequence(der.encode_integer(r), der.encode_integer(s))


def infunc_string(signature, order):
    l = orderlen(order)
    assert len(signature) == 2*l, (len(signature), 2*l)
    r = string_to_number_fixedlen(signature[:l], order)
    s = string_to_number_fixedlen(signature[l:], order)
    return r, s

def infunc_strings((r_str, s_str), order):
    l = orderlen(order)
    assert len(r_str) == l, (len(r_str), l)
    assert len(s_str) == l, (len(s_str), l)
    r = string_to_number_fixedlen(r_str, order)
    s = string_to_number_fixedlen(s_str, order)
    return r, s

def infunc_der(sig_der, order):
    #return der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
    rs_strings, empty = der.remove_sequence(sig_der)
    if empty != "":
        raise der.UnexpectedDER("trailing junk after DER sig: %s" %
                                binascii.hexlify(empty))
    r, rest = der.remove_integer(rs_strings)
    s, empty = der.remove_integer(rest)
    if empty != "":
        raise der.UnexpectedDER("trailing junk after DER numbers: %s" %
                                binascii.hexlify(empty))
    return r, s

