#!/usr/bin/env python

import re, sys, subprocess
from distutils.core import setup, Command
from distutils.command.sdist import sdist as _sdist

VERSION_PY = """
# This file is originally generated from Git information by running 'setup.py
# version'. Distribution tarballs contain a pre-generated copy of this file.

__version__ = '%s'
"""

def update_version_py():
    try:
        ver = subprocess.Popen(["git", "describe", "--dirty", "--always"],
                               stdout=subprocess.PIPE,
                               ).communicate()[0]
        # we use tags like "python-ecdsa-0.5", so strip the prefix
        assert ver.startswith("python-ecdsa-")
        ver = ver[len("python-ecdsa-"):].strip()
        f = open("ecdsa/_version.py", "w")
        f.write(VERSION_PY % ver)
        f.close()
        print "set ecdsa/_version.py to '%s'" % ver
    except IndexError:
        print "unable to run git, leaving ecdsa/_version.py alone"

def get_version():
    try:
        f = open("ecdsa/_version.py")
    except EnvironmentError:
        return None
    for line in f.readlines():
        mo = re.match("__version__ = '([^']+)'", line)
        if mo:
            ver = mo.group(1)
            return ver
    return None

class Version(Command):
    description = "update _version.py from Git repo"
    user_options = []
    boolean_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        update_version_py()

class sdist(_sdist):
    def run(self):
        update_version_py()
        return _sdist.run(self)

setup(name="ecdsa",
      version=get_version(),
      description="ECDSA cryptographic signature library (pure python)",
      author="Brian Warner",
      author_email="warner-pyecdsa@lothar.com",
      url="http://github.com/warner/python-ecdsa",
      packages=["ecdsa"],
      license="MIT",
      cmdclass={ "version": Version, "sdist": sdist },
      )
