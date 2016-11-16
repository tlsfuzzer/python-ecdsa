#!/usr/bin/env python
try:
    # try setuptools, so devs can run bdist_wheel
    from setuptools import setup, Command
except ImportError:
    # but most users really don't require it
    from distutils.core import setup, Command
import versioneer

commands = versioneer.get_cmdclass().copy()

setup(name="ecdsa",
      version=versioneer.get_version(),
      description="ECDSA cryptographic signature library (pure python)",
      author="Brian Warner",
      author_email="warner@lothar.com",
      url="http://github.com/warner/python-ecdsa",
      packages=["ecdsa"],
      package_dir={"": "src"},
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
