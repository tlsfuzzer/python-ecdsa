#!/usr/bin/env python

from distutils.core import setup

# to run unit tests, do this:
#  python ecdsa/ecdsa.py  # look for *** failures messages
#  python ecdsa/test_pyecdsa.py   # look for "Failure:" messages

setup(name="ecdsa",
      version="0.5",
      description="ECDSA cryptographic signature library (pure python)",
      author="Brian Warner",
      author_email="warner-pyecdsa@lothar.com",
      url="http://github.com/warner/python-ecdsa",
      packages=["ecdsa"],
      license="MIT",
      cmdclass={ "test": test },
      )
