"""
Common functions for providing cross-python version compatibility.
"""
import sys


if sys.version_info < (3, 0):
    def normalise_bytes(buffer_object):
        """Cast the input into array of bytes."""
        return buffer(buffer_object)


else:
    def normalise_bytes(buffer_object):
        """Cast the input into array of bytes."""
        return memoryview(buffer_object).cast('B')
