'''
           
RFC 6979:
    Deterministic Usage of the Digital Signature Algorithm (DSA) and
    Elliptic Curve Digital Signature Algorithm (ECDSA)

    http://tools.ietf.org/html/rfc6979
    
Many thanks to Coda Hale for his implementation in Go language:
    https://github.com/codahale/rfc6979

'''

import hmac
from binascii import hexlify
from util import number_to_string, number_to_string_crop

def bit_length(num):
    # http://docs.python.org/dev/library/stdtypes.html#int.bit_length
    s = bin(num)  # binary representation:  bin(-37) --> '-0b100101'
    s = s.lstrip('-0b')  # remove leading zeros and minus sign
    return len(s)  # len('100101') --> 6

def bits2int(data, qlen):
    x = int(hexlify(data), 16)
    l = len(data) * 8
    
    if l > qlen:
        return x >> (l-qlen)
    return x    

def bits2octets(data, order):
    z1 = bits2int(data, bit_length(order))
    z2 = z1 - order
    
    if z2 < 0:
        z2 = z1
        
    return number_to_string_crop(z2, order)
    
# https://tools.ietf.org/html/rfc6979#section-3.2
def generate_k(generator, secexp, hash_func, data):
    '''
        generator - ECDSA generator used in the signature
        secexp - secure exponent (private key) in numeric form
        hash_func - reference to the same hash function used for generating hash
        data - hash in binary form of the signing data 
    '''
    
    qlen = bit_length(generator.order())
    holen = hash_func().digestsize
    rolen = (qlen + 7) / 8
    bx = number_to_string(secexp, generator.order()) + bits2octets(data, generator.order())
    
    # Step B
    v = '\x01' * holen

    # Step C
    k = '\x00' * holen

    # Step D

    k = hmac.new(k, v+'\x00'+bx, hash_func).digest() 

    # Step E
    v = hmac.new(k, v, hash_func).digest()
    
    # Step F
    k = hmac.new(k, v+'\x01'+bx, hash_func).digest()

    # Step G
    v = hmac.new(k, v, hash_func).digest()

    # Step H
    while True:
        # Step H1
        t = ''

        # Step H2
        while len(t) < rolen:
            v = hmac.new(k, v, hash_func).digest()
            t += v

        # Step H3
        secret = bits2int(t, qlen)

        if secret >= 1 and secret < generator.order():
            return secret

        k = hmac.new(k, v+'\x00', hash_func).digest()
        v = hmac.new(k, v, hash_func).digest()
