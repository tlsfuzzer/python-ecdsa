#!/usr/bin/env python
try:
    # try setuptools, so devs can run bdist_wheel
    from setuptools import setup, Command
except ImportError:
    # but most users really don't require it
    from distutils.core import setup, Command
import timeit

import versioneer
versioneer.versionfile_source = "ecdsa/_version.py"
versioneer.versionfile_build = versioneer.versionfile_source
versioneer.tag_prefix = "python-ecdsa-"
versioneer.parentdir_prefix = "ecdsa-"
versioneer.VCS = "git"

commands = versioneer.get_cmdclass().copy()

class Test(Command):
    description = "run unit tests"
    user_options = []
    boolean_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        from ecdsa import numbertheory
        numbertheory.__main__()
        from ecdsa import ellipticcurve
        ellipticcurve.__main__()
        from ecdsa import ecdsa
        ecdsa.__main__()
        from ecdsa import test_pyecdsa
        test_pyecdsa.unittest.main(module=test_pyecdsa, argv=["dummy"])
        # all tests os.exit(1) upon failure
commands["test"] = Test

class Speed(Test):
    description = "run benchmark suite"
    def run(self):
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
            S1 = "from ecdsa import six, SigningKey, %s" % curve
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
            sig = ecdsa.SigningKey.generate(c).sign(ecdsa.six.b("msg"))
            print("%9s: siglen=%3d, keygen=%.3fs, sign=%.3fs, verify=%.3fs" \
                  % (curve, len(sig), keygen, sign, verf))

commands["speed"] = Speed


setup(name="ecdsa",
      version=versioneer.get_version(),
      description="ECDSA cryptographic signature library (pure python)",
      author="Brian Warner",
      author_email="warner-pyecdsa@lothar.com",
      url="http://github.com/warner/python-ecdsa",
      packages=["ecdsa"],
      license="MIT",
      cmdclass=commands,
      classifiers=[
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.2",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
      ],
)
