#!/usr/bin/env python

import glob, os, sys, unittest
from distutils.core import setup, Command

class test(Command):
    description =" Run the test suite"
    user_options = []

    def initialize_options(self):
        self.test_dirs = None
    def finalize_options(self):
        if self.test_dirs is None:
            self.test_dirs = ["pyecdsa"]

    def run(self):
        testsRun = errors = failures = 0
        for dir in self.test_dirs:
            for filename in glob.glob(os.path.join(dir, "test_*.py")):
                self.announce("running test from " + filename)
                info = self._run_test(filename)
                errors = errors + info[0]
                failures = failures + info[1]
                testsRun = testsRun + info[2]
        if errors or failures:
            print "%d errors and %d failures, %d tests run" % \
                  (errors, failures, testsRun)
            sys.exit(1)
        else:
            print "All %d tests passed" % testsRun

    def _run_test(self, filename):
        # make sure the file's directory is on sys.path so we can import.
        dirname, basename = os.path.split(filename)
        sys.path.insert(0, dirname)
        try:
            modname = os.path.splitext(basename)[0]
            mod = __import__(modname)
            suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
            runner = unittest.TextTestRunner(stream=open("/dev/null", 'w'))
            results = runner.run(suite)
            return len(results.errors), len(results.failures), results.testsRun
        finally:
            if sys.path[0] == dirname:
                del sys.path[0]
        

setup(name="pyecdsa",
      version="x",
      description="ECDSA cryptographic signature library (pure python)",
      author="Brian Warner",
      author_email="warner-pyecdsa@lothar.com",
      url="http://github.com/warner/pyecdsa",
      packages=["pyecdsa"],
      license="MIT",
      cmdclass={ "test": test },
      )
