import timeit
from ecdsa.curves import curves


UNIQUE_KEYS = 100


def do(setup_statements, statement):
    # extracted from timeit.py
    t = timeit.Timer(stmt=statement, setup="\n".join(setup_statements))
    # determine number so that 0.2 <= total time < 2.0
    for i in range(1, 10):
        number = 10 ** i
        x = t.timeit(number)
        if x >= 0.2:
            break
    return x / number / UNIQUE_KEYS


prnt_form = (
    "{name:>16}{sep:1} {siglen:>6} {keygen:>9{form}}{unit:1} "
    "{keygen_inv:>9{form_inv}} {sign:>9{form}}{unit:1} "
    "{sign_inv:>9{form_inv}} {verify:>9{form}}{unit:1} "
    "{verify_inv:>9{form_inv}} {verify_single:>13{form}}{unit:1} "
    "{verify_single_inv:>14{form_inv}}"
)

print(
    prnt_form.format(
        siglen="siglen",
        keygen="keygen",
        keygen_inv="keygen/s",
        sign="sign",
        sign_inv="sign/s",
        verify="verify",
        verify_inv="verify/s",
        verify_single="no PC verify",
        verify_single_inv="no PC verify/s",
        name="",
        sep="",
        unit="",
        form="",
        form_inv="",
    )
)

for curve in [i.name for i in curves]:
    S1 = "from ecdsa import SigningKey, %s" % curve
    S1 += "; from ecdsa.util import PRNG"
    # as the code is very much data dependant, use the same 100 keys
    # to sign the same 100 messages over and over to make the
    # benchmarking stable
    S2 = (
        "sk = ["
        "SigningKey.generate({0}, entropy=PRNG(i)) "
        "for i in range({1})]"
    ).format(curve, UNIQUE_KEYS)
    S3 = "msg = b'msg'"
    S4 = "sig = [k.sign(msg, entropy=PRNG(b'A')) for k in sk]"
    S5 = "vk = [k.get_verifying_key() for k in sk]"
    S6 = "[k.precompute() for k in vk]"
    S7 = "[k.verify(s, msg) for k, s in zip(vk, sig)]"
    # We happen to know that .generate() also calculates the
    # verifying key, which is the time-consuming part. If the code
    # were changed to lazily calculate vk, we'd need to change this
    # benchmark to loop over S5 instead of S2
    keygen = do([S1], S2)
    sign = do([S1, S2, S3], S4)
    verf = do([S1, S2, S3, S4, S5, S6], S7)
    verf_single = do([S1, S2, S3, S4, S5], S7)
    import ecdsa

    c = getattr(ecdsa, curve)
    sig = ecdsa.SigningKey.generate(c).sign(b"msg")
    print(
        prnt_form.format(
            name=curve,
            sep=":",
            siglen=len(sig),
            unit="s",
            keygen=keygen,
            keygen_inv=1.0 / keygen,
            sign=sign,
            sign_inv=1.0 / sign,
            verify=verf,
            verify_inv=1.0 / verf,
            verify_single=verf_single,
            verify_single_inv=1.0 / verf_single,
            form=".5f",
            form_inv=".2f",
        )
    )

print("")

ecdh_form = "{name:>16}{sep:1} {ecdh:>9{form}}{unit:1} {ecdh_inv:>9{form_inv}}"

print(
    ecdh_form.format(
        ecdh="ecdh",
        ecdh_inv="ecdh/s",
        name="",
        sep="",
        unit="",
        form="",
        form_inv="",
    )
)

for curve in [i.name for i in curves]:
    if curve == "Ed25519" or curve == "Ed448":
        continue
    S1 = "from ecdsa import SigningKey, ECDH, {0}".format(curve)
    S1 += "; from ecdsa.util import PRNG"
    # as with signatures, calculate shared secrets for the same
    # set of keys over and over
    S2 = (
        "our = ["
        "SigningKey.generate({0}, entropy=PRNG(i)) "
        "for i in range({1})]"
    ).format(curve, UNIQUE_KEYS)
    S3 = (
        "remote = ["
        "SigningKey.generate({0}, entropy=PRNG(i+10)).verifying_key "
        "for i in range({1})]"
    ).format(curve, UNIQUE_KEYS)
    S4 = (
        "ecdh = ["
        "ECDH(private_key=o, public_key=r) "
        "for o, r in zip(our, remote)]"
    )
    S5 = "[e.generate_sharedsecret_bytes() for e in ecdh]"
    ecdh = do([S1, S2, S3, S4], S5)
    print(
        ecdh_form.format(
            name=curve,
            sep=":",
            unit="s",
            form=".5f",
            form_inv=".2f",
            ecdh=ecdh,
            ecdh_inv=1.0 / ecdh,
        )
    )
