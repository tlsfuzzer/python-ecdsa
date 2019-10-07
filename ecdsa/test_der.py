
# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from .der import remove_integer, UnexpectedDER, read_length
from .six import b

class TestRemoveInteger(unittest.TestCase):
    # DER requires the integers to be 0-padded only if they would be
    # interpreted as negative, check if those errors are detected
    def test_non_minimal_encoding(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b('\x02\x02\x00\x01'))

    def test_negative_with_high_bit_set(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b('\x02\x01\x80'))

    def test_two_zero_bytes_with_high_bit_set(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b('\x02\x03\x00\x00\xff'))

    def test_zero_length_integer(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b('\x02\x00'))

    def test_empty_string(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b(''))

    def test_encoding_of_zero(self):
        val, rem = remove_integer(b('\x02\x01\x00'))

        self.assertEqual(val, 0)
        self.assertFalse(rem)

    def test_encoding_of_127(self):
        val, rem = remove_integer(b('\x02\x01\x7f'))

        self.assertEqual(val, 127)
        self.assertFalse(rem)

    def test_encoding_of_128(self):
        val, rem = remove_integer(b('\x02\x02\x00\x80'))

        self.assertEqual(val, 128)
        self.assertFalse(rem)


class TestReadLength(unittest.TestCase):
    # DER requires the lengths between 0 and 127 to be encoded using the short
    # form and lengths above that encoded with minimal number of bytes
    # necessary
    def test_zero_length(self):
        self.assertEqual((0, 1), read_length(b('\x00')))

    def test_two_byte_zero_length(self):
        with self.assertRaises(UnexpectedDER):
            read_length(b('\x81\x00'))

    def test_two_byte_small_length(self):
        with self.assertRaises(UnexpectedDER):
            read_length(b('\x81\x7f'))

    def test_long_form_with_zero_length(self):
        with self.assertRaises(UnexpectedDER):
            read_length(b('\x80'))

    def test_smallest_two_byte_length(self):
        self.assertEqual((128, 2), read_length(b('\x81\x80')))

    def test_zero_padded_length(self):
        with self.assertRaises(UnexpectedDER):
            read_length(b('\x82\x00\x80'))

    def test_two_three_byte_length(self):
        self.assertEqual((256, 3), read_length(b'\x82\x01\x00'))

    def test_empty_string(self):
        with self.assertRaises(UnexpectedDER):
            read_length(b(''))

    def test_length_overflow(self):
        with self.assertRaises(UnexpectedDER):
            read_length(b('\x83\x01\x00'))
