#!/usr/bin/env python

from setuptools import setup
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
      python_requires=">=2.6, !=3.0.*, !=3.1.*, !=3.2.*",
      classifiers=[
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
      ],
      install_requires=['six'],
      )
