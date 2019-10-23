
# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from .der import remove_integer, UnexpectedDER, read_length, encode_bitstring,\
        remove_bitstring
from six import b
import pytest
import warnings
from ._compat import str_idx_as_int


class TestRemoveInteger(unittest.TestCase):
    # DER requires the integers to be 0-padded only if they would be
    # interpreted as negative, check if those errors are detected
    def test_non_minimal_encoding(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b('\x02\x02\x00\x01'))

    def test_negative_with_high_bit_set(self):
        with self.assertRaises(UnexpectedDER):
            remove_integer(b('\x02\x01\x80'))

    def test_minimal_with_high_bit_set(self):
        val, rem = remove_integer(b('\x02\x02\x00\x80'))

        self.assertEqual(val, 0x80)
        self.assertFalse(rem)

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


class TestEncodeBitstring(unittest.TestCase):
    # DER requires BIT STRINGS to include a number of padding bits in the
    # encoded byte string, that padding must be between 0 and 7

    def test_old_call_convention(self):
        """This is the old way to use the function."""
        warnings.simplefilter('always')
        with pytest.warns(DeprecationWarning) as warns:
            der = encode_bitstring(b'\x00\xff')

        self.assertEqual(len(warns), 1)
        self.assertIn("unused= needs to be specified",
            warns[0].message.args[0])

        self.assertEqual(der, b'\x03\x02\x00\xff')

    def test_new_call_convention(self):
        """This is how it should be called now."""
        warnings.simplefilter('always')
        with pytest.warns(None) as warns:
            der = encode_bitstring(b'\xff', 0)

        # verify that new call convention doesn't raise Warnings
        self.assertEqual(len(warns), 0)

        self.assertEqual(der, b'\x03\x02\x00\xff')

    def test_implicit_unused_bits(self):
        """
        Writing bit string with already included the number of unused bits.
        """
        warnings.simplefilter('always')
        with pytest.warns(None) as warns:
            der = encode_bitstring(b'\x00\xff', None)

        # verify that new call convention doesn't raise Warnings
        self.assertEqual(len(warns), 0)

        self.assertEqual(der, b'\x03\x02\x00\xff')

    def test_explicit_unused_bits(self):
        der = encode_bitstring(b'\xff\xf0', 4)

        self.assertEqual(der, b'\x03\x03\x04\xff\xf0')

    def test_empty_string(self):
        self.assertEqual(encode_bitstring(b'', 0), b'\x03\x01\x00')

    def test_invalid_unused_count(self):
        with self.assertRaises(ValueError):
            encode_bitstring(b'\xff\x00', 8)

    def test_invalid_unused_with_empty_string(self):
        with self.assertRaises(ValueError):
            encode_bitstring(b'', 1)

    def test_non_zero_padding_bits(self):
        with self.assertRaises(ValueError):
            encode_bitstring(b'\xff', 2)


class TestRemoveBitstring(unittest.TestCase):
    def test_old_call_convention(self):
        """This is the old way to call the function."""
        warnings.simplefilter('always')
        with pytest.warns(DeprecationWarning) as warns:
            bits, rest = remove_bitstring(b'\x03\x02\x00\xff')

        self.assertEqual(len(warns), 1)
        self.assertIn("expect_unused= needs to be specified",
                      warns[0].message.args[0])

        self.assertEqual(bits, b'\x00\xff')
        self.assertEqual(rest, b'')

    def test_new_call_convention(self):
        warnings.simplefilter('always')
        with pytest.warns(None) as warns:
            bits, rest = remove_bitstring(b'\x03\x02\x00\xff', 0)

        self.assertEqual(len(warns), 0)

        self.assertEqual(bits, b'\xff')
        self.assertEqual(rest, b'')

    def test_implicit_unexpected_unused(self):
        warnings.simplefilter('always')
        with pytest.warns(None) as warns:
            bits, rest = remove_bitstring(b'\x03\x02\x00\xff', None)

        self.assertEqual(len(warns), 0)

        self.assertEqual(bits, (b'\xff', 0))
        self.assertEqual(rest, b'')

    def test_with_padding(self):
        ret, rest = remove_bitstring(b'\x03\x02\x04\xf0', None)

        self.assertEqual(ret, (b'\xf0', 4))
        self.assertEqual(rest, b'')

    def test_not_a_bitstring(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x02\x02\x00\xff', None)

    def test_empty_encoding(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x03\x00', None)

    def test_empty_string(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'', None)

    def test_no_length(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x03', None)

    def test_unexpected_number_of_unused_bits(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x03\x02\x00\xff', 1)

    def test_invalid_encoding_of_unused_bits(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x03\x03\x08\xff\x00', None)

    def test_invalid_encoding_of_empty_string(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x03\x01\x01', None)

    def test_invalid_padding_bits(self):
        with self.assertRaises(UnexpectedDER):
            remove_bitstring(b'\x03\x02\x01\xff', None)


class TestStrIdxAsInt(unittest.TestCase):
    def test_str(self):
        self.assertEqual(115, str_idx_as_int('str', 0))

    def test_bytes(self):
        self.assertEqual(115, str_idx_as_int(b'str', 0))

    def test_bytearray(self):
        self.assertEqual(115, str_idx_as_int(bytearray(b'str'), 0))
