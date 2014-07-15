#!/usr/bin/env python
try:
    # try setuptools, so devs can run bdist_wheel
    from setuptools import setup, Command
except ImportError:
    # but most users really don't require it
    from distutils.core import setup, Command

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
      ],
)
