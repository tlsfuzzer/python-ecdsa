import six
import timeit

def do(setup_statements, statement):
    # extracted from timeit.py
    t = timeit.Timer(stmt=statement,
                     setup="\n".join(setup_statements))
    # determine number so that 0.2 <= total time < 2.0
    for i in range(1, 10):
        number = 10**i
        x = t.timeit(number)
        if x >= 0.2:
            break
    return x / number

for curve in ["NIST192p", "NIST224p", "NIST256p", "SECP256k1",
              "NIST384p", "NIST521p"]:
    S1 = "import six; from ecdsa import SigningKey, %s" % curve
    S2 = "sk = SigningKey.generate(%s)" % curve
    S3 = "msg = six.b('msg')"
    S4 = "sig = sk.sign(msg)"
    S5 = "vk = sk.get_verifying_key()"
    S6 = "vk.verify(sig, msg)"
    # We happen to know that .generate() also calculates the
    # verifying key, which is the time-consuming part. If the code
    # were changed to lazily calculate vk, we'd need to change this
    # benchmark to loop over S5 instead of S2
    keygen = do([S1], S2)
    sign = do([S1,S2,S3], S4)
    verf = do([S1,S2,S3,S4,S5], S6)
    import ecdsa
    c = getattr(ecdsa, curve)
    sig = ecdsa.SigningKey.generate(c).sign(six.b("msg"))
    print("%9s: siglen=%3d, keygen=%.3fs, sign=%.3fs, verify=%.3fs" \
          % (curve, len(sig), keygen, sign, verf))
