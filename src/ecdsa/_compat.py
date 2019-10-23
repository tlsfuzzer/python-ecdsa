"""
Common functions for providing cross-python version compatibility.
"""
import sys
from six import integer_types


def str_idx_as_int(string, index):
    """Take index'th byte from string, return as integer"""
    val = string[index]
    if isinstance(val, integer_types):
        return val
    return ord(val)


if sys.version_info < (3, 0):
    def normalise_bytes(buffer_object):
        """Cast the input into array of bytes."""
        return buffer(buffer_object)


else:
    def normalise_bytes(buffer_object):
        """Cast the input into array of bytes."""
        return memoryview(buffer_object).cast('B')
