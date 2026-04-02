# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
from binascii import hexlify

try:
    import unittest2 as unittest
except ImportError:
    import unittest
import sys
import hypothesis.strategies as st
from hypothesis import given, settings
from ._compat import str_idx_as_int
from .curves import NIST256p, NIST224p
from .ber import (
    UnexpectedBER,
    encode_tag,
    decode_tag,
    encode_length,
    encode_indefinite_length,
    encode_end_of_contents,
    read_length,
    encode_constructed,
    encode_constructed_indefinite,
    encode_implicit,
    encode_integer,
    encode_sequence,
    encode_sequence_indefinite,
    encode_number,
    is_sequence,
    remove_constructed,
    remove_implicit,
    remove_sequence,
    remove_integer,
    remove_tlv,
    END_OF_CONTENTS,
)
from .util import sigencode_ber_indefinite, sigdecode_ber_indefinite


class TestEncodeTag(unittest.TestCase):
    def test_low_tag_universal_primitive(self):
        # Tag 2 (INTEGER), universal, primitive
        # 0b00000010
        result = encode_tag(2, constructed=False, cls="universal")
        self.assertEqual(result, b"\x02")

    def test_low_tag_universal_constructed(self):
        # Tag 16 (SEQUENCE), universal, constructed
        result = encode_tag(16, constructed=True, cls="universal")
        # 0b00110000
        self.assertEqual(result, b"\x30")

    def test_low_tag_context_specific_primitive(self):
        # Tag 0, context-specific, primitive
        # 0b10000000
        result = encode_tag(0, constructed=False, cls="context-specific")
        self.assertEqual(result, b"\x80")

    def test_low_tag_context_specific_constructed(self):
        # Tag 1, context-specific, constructed
        # 0b10100001
        result = encode_tag(1, constructed=True, cls="context-specific")
        self.assertEqual(result, b"\xa1")

    def test_low_tag_application(self):
        result = encode_tag(5, constructed=False, cls="application")
        # 0b01000101
        self.assertEqual(result, b"\x45")

    def test_low_tag_private(self):
        result = encode_tag(10, constructed=False, cls="private")
        # 0b11001010
        self.assertEqual(result, b"\xca")

    def test_tag_30_is_low_form(self):
        result = encode_tag(30, constructed=False, cls="universal")
        self.assertEqual(result, b"\x1e")

    def test_high_tag_31(self):
        # Tag 31 uses high-tag-number form
        result = encode_tag(31, constructed=False, cls="universal")
        self.assertEqual(result, b"\x1f\x1f")

    def test_high_tag_127(self):
        result = encode_tag(127, constructed=False, cls="universal")
        self.assertEqual(result, b"\x1f\x7f")

    def test_high_tag_128(self):
        # 128 = 0x80 in base 128: 0x81 0x00
        result = encode_tag(128, constructed=False, cls="universal")
        self.assertEqual(result, b"\x1f\x81\x00")

    def test_high_tag_context_specific_constructed(self):
        result = encode_tag(31, constructed=True, cls="context-specific")
        # First octet: 0xA0 | 0x1F = 0xBF
        self.assertEqual(result, b"\xbf\x1f")

    def test_negative_tag_raises(self):
        with self.assertRaises(ValueError):
            encode_tag(-1)

    def test_invalid_class_raises(self):
        with self.assertRaises(ValueError):
            encode_tag(0, cls="foobar")


class TestDecodeTag(unittest.TestCase):
    def test_low_tag_universal_primitive(self):
        tag, constructed, cls, length = decode_tag(b"\x02")
        self.assertEqual(tag, 2)
        self.assertFalse(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(length, 1)

    def test_low_tag_universal_constructed(self):
        tag, constructed, cls, length = decode_tag(b"\x30")
        self.assertEqual(tag, 16)
        self.assertTrue(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(length, 1)

    def test_low_tag_context_specific(self):
        tag, constructed, cls, length = decode_tag(b"\x80")
        self.assertEqual(tag, 0)
        self.assertFalse(constructed)
        self.assertEqual(cls, "context-specific")
        self.assertEqual(length, 1)

    def test_low_tag_application(self):
        tag, constructed, cls, length = decode_tag(b"\x45")
        self.assertEqual(tag, 5)
        self.assertFalse(constructed)
        self.assertEqual(cls, "application")
        self.assertEqual(length, 1)

    def test_low_tag_private(self):
        tag, constructed, cls, length = decode_tag(b"\xca")
        self.assertEqual(tag, 10)
        self.assertFalse(constructed)
        self.assertEqual(cls, "private")
        self.assertEqual(length, 1)

    def test_high_tag_31(self):
        tag, constructed, cls, length = decode_tag(b"\x1f\x1f")
        self.assertEqual(tag, 31)
        self.assertFalse(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(length, 2)

    def test_high_tag_128(self):
        tag, constructed, cls, length = decode_tag(b"\x1f\x81\x00")
        self.assertEqual(tag, 128)
        self.assertFalse(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(length, 3)

    def test_empty_string(self):
        with self.assertRaises(UnexpectedBER):
            decode_tag(b"")

    def test_truncated_high_tag(self):
        with self.assertRaises(UnexpectedBER):
            decode_tag(b"\x1f")

    def test_non_minimal_high_tag(self):
        # First subsequent octet is 0x80 (non-minimal)
        with self.assertRaises(UnexpectedBER):
            decode_tag(b"\x1f\x80\x01")

    def test_high_form_for_small_tag(self):
        # Tag 15 encoded in high-tag form (should be low form)
        with self.assertRaises(UnexpectedBER):
            decode_tag(b"\x1f\x0f")

    def test_roundtrip_low_tag(self):
        for tag_num in range(0, 31):
            encoded = encode_tag(tag_num, constructed=False, cls="universal")
            decoded_tag, constructed, cls, _ = decode_tag(encoded)
            self.assertEqual(decoded_tag, tag_num)
            self.assertFalse(constructed)
            self.assertEqual(cls, "universal")

    def test_roundtrip_high_tag(self):
        for tag_num in [31, 50, 127, 128, 255, 16383]:
            encoded = encode_tag(
                tag_num, constructed=True, cls="context-specific"
            )
            decoded_tag, constructed, cls, _ = decode_tag(encoded)
            self.assertEqual(decoded_tag, tag_num)
            self.assertTrue(constructed)
            self.assertEqual(cls, "context-specific")


class TestEncodeLength(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(encode_length(0), b"\x00")

    def test_short_form_max(self):
        self.assertEqual(encode_length(127), b"\x7f")

    def test_long_form_128(self):
        self.assertEqual(encode_length(128), b"\x81\x80")

    def test_long_form_256(self):
        self.assertEqual(encode_length(256), b"\x82\x01\x00")


class TestReadLength(unittest.TestCase):
    def test_zero_length(self):
        self.assertEqual((0, 1), read_length(b"\x00"))

    def test_short_form_127(self):
        self.assertEqual((127, 1), read_length(b"\x7f"))

    def test_long_form_128(self):
        self.assertEqual((128, 2), read_length(b"\x81\x80"))

    def test_long_form_256(self):
        self.assertEqual((256, 3), read_length(b"\x82\x01\x00"))

    def test_indefinite_length(self):
        # BER supports indefinite length (0x80)
        length, consumed = read_length(b"\x80")
        self.assertIsNone(length)
        self.assertEqual(consumed, 1)

    def test_non_minimal_two_byte_zero(self):
        # BER accepts non-minimal length encoding (unlike DER)
        length, consumed = read_length(b"\x81\x00")
        self.assertEqual(length, 0)
        self.assertEqual(consumed, 2)

    def test_non_minimal_two_byte_small(self):
        # BER accepts a two-byte encoding for values < 128
        length, consumed = read_length(b"\x81\x7f")
        self.assertEqual(length, 127)
        self.assertEqual(consumed, 2)

    def test_non_minimal_zero_padded(self):
        # BER accepts zero-padded length encoding
        length, consumed = read_length(b"\x82\x00\x80")
        self.assertEqual(length, 128)
        self.assertEqual(consumed, 3)

    def test_empty_string(self):
        with self.assertRaises(UnexpectedBER):
            read_length(b"")

    def test_length_overflow(self):
        with self.assertRaises(UnexpectedBER):
            read_length(b"\x83\x01\x00")


class TestIndefiniteLength(unittest.TestCase):
    def test_encode_indefinite_length(self):
        self.assertEqual(encode_indefinite_length(), b"\x80")

    def test_encode_end_of_contents(self):
        self.assertEqual(encode_end_of_contents(), b"\x00\x00")

    def test_end_of_contents_constant(self):
        self.assertEqual(END_OF_CONTENTS, b"\x00\x00")


class TestRemoveInteger(unittest.TestCase):
    def test_encoding_of_zero(self):
        val, rem = remove_integer(b"\x02\x01\x00")
        self.assertEqual(val, 0)
        self.assertEqual(rem, b"")

    def test_encoding_of_127(self):
        val, rem = remove_integer(b"\x02\x01\x7f")
        self.assertEqual(val, 127)
        self.assertEqual(rem, b"")

    def test_encoding_of_128(self):
        val, rem = remove_integer(b"\x02\x02\x00\x80")
        self.assertEqual(val, 128)
        self.assertEqual(rem, b"")

    def test_negative_with_high_bit_set(self):
        with self.assertRaises(UnexpectedBER):
            remove_integer(b"\x02\x01\x80")

    def test_minimal_with_high_bit_set(self):
        val, rem = remove_integer(b"\x02\x02\x00\x80")
        self.assertEqual(val, 0x80)
        self.assertEqual(rem, b"")

    def test_non_minimal_encoding_accepted(self):
        # BER accepts non-minimal integer encodings (extra zero padding)
        # This would raise UnexpectedDER in DER mode
        val, rem = remove_integer(b"\x02\x02\x00\x01")
        self.assertEqual(val, 1)
        self.assertEqual(rem, b"")

    def test_non_minimal_multiple_zero_padding(self):
        # Multiple leading zeros accepted in BER
        val, rem = remove_integer(b"\x02\x03\x00\x00\x7f")
        self.assertEqual(val, 127)
        self.assertEqual(rem, b"")

    def test_zero_length_integer(self):
        with self.assertRaises(UnexpectedBER):
            remove_integer(b"\x02\x00")

    def test_empty_string(self):
        with self.assertRaises(UnexpectedBER):
            remove_integer(b"")

    def test_wrong_tag(self):
        with self.assertRaises(UnexpectedBER) as e:
            remove_integer(b"\x01\x02\x00\x80")
        self.assertIn("wanted type 'integer'", str(e.exception))

    def test_wrong_length(self):
        with self.assertRaises(UnexpectedBER) as e:
            remove_integer(b"\x02\x03\x00\x80")
        self.assertIn("Length longer", str(e.exception))

    def test_with_remaining_bytes(self):
        val, rem = remove_integer(b"\x02\x01\x05\xff\xaa")
        self.assertEqual(val, 5)
        self.assertEqual(rem, b"\xff\xaa")


class TestEncodeInteger(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(encode_integer(0), b"\x02\x01\x00")

    def test_127(self):
        self.assertEqual(encode_integer(127), b"\x02\x01\x7f")

    def test_128(self):
        self.assertEqual(encode_integer(128), b"\x02\x02\x00\x80")

    def test_256(self):
        self.assertEqual(encode_integer(256), b"\x02\x02\x01\x00")

    def test_roundtrip(self):
        for value in [0, 1, 127, 128, 255, 256, 65535, 2**32]:
            encoded = encode_integer(value)
            decoded, rest = remove_integer(encoded)
            self.assertEqual(decoded, value)
            self.assertEqual(rest, b"")


class TestEncodeSequence(unittest.TestCase):
    def test_simple(self):
        inner = encode_integer(42)
        seq = encode_sequence(inner)
        self.assertEqual(seq[:1], b"\x30")
        body, rest = remove_sequence(seq)
        self.assertEqual(rest, b"")
        val, _ = remove_integer(body)
        self.assertEqual(val, 42)

    def test_multiple_elements(self):
        a = encode_integer(1)
        b = encode_integer(2)
        seq = encode_sequence(a, b)
        body, rest = remove_sequence(seq)
        self.assertEqual(rest, b"")
        v1, remaining = remove_integer(body)
        v2, remaining = remove_integer(remaining)
        self.assertEqual(v1, 1)
        self.assertEqual(v2, 2)
        self.assertEqual(remaining, b"")

    def test_empty_sequence(self):
        seq = encode_sequence()
        self.assertEqual(seq, b"\x30\x00")


class TestRemoveSequence(unittest.TestCase):
    def test_simple(self):
        data = b"\x30\x02\xff\xaa"
        body, rest = remove_sequence(data)
        self.assertEqual(body, b"\xff\xaa")
        self.assertEqual(rest, b"")

    def test_with_empty_string(self):
        with self.assertRaises(UnexpectedBER) as e:
            remove_sequence(b"")
        self.assertIn("Empty string", str(e.exception))

    def test_with_wrong_tag(self):
        data = b"\x20\x02\xff\xaa"
        with self.assertRaises(UnexpectedBER) as e:
            remove_sequence(data)
        self.assertIn("wanted type 'sequence'", str(e.exception))

    def test_with_wrong_length(self):
        data = b"\x30\x03\xff\xaa"
        with self.assertRaises(UnexpectedBER) as e:
            remove_sequence(data)
        self.assertIn("Length longer", str(e.exception))

    def test_indefinite_length(self):
        # SEQUENCE with indefinite length: 0x30 0x80 <contents> 0x00 0x00
        inner = encode_integer(5)
        data = b"\x30\x80" + inner + b"\x00\x00"
        body, rest = remove_sequence(data)
        self.assertEqual(rest, b"")
        val, _ = remove_integer(body)
        self.assertEqual(val, 5)

    def test_indefinite_length_with_remaining(self):
        inner = encode_integer(10)
        data = b"\x30\x80" + inner + b"\x00\x00" + b"\xde\xad"
        body, rest = remove_sequence(data)
        self.assertEqual(rest, b"\xde\xad")
        val, _ = remove_integer(body)
        self.assertEqual(val, 10)

    def test_indefinite_length_multiple_elements(self):
        a = encode_integer(1)
        b_val = encode_integer(2)
        data = b"\x30\x80" + a + b_val + b"\x00\x00"
        body, rest = remove_sequence(data)
        self.assertEqual(rest, b"")
        v1, remaining = remove_integer(body)
        v2, remaining = remove_integer(remaining)
        self.assertEqual(v1, 1)
        self.assertEqual(v2, 2)
        self.assertEqual(remaining, b"")


class TestEncodeSequenceIndefinite(unittest.TestCase):
    def test_simple(self):
        inner = encode_integer(42)
        seq = encode_sequence_indefinite(inner)
        # Should start with 0x30 0x80 and end with 0x00 0x00
        self.assertEqual(seq[:2], b"\x30\x80")
        self.assertEqual(seq[-2:], b"\x00\x00")

    def test_roundtrip(self):
        inner = encode_integer(99)
        seq = encode_sequence_indefinite(inner)
        body, rest = remove_sequence(seq)
        self.assertEqual(rest, b"")
        val, _ = remove_integer(body)
        self.assertEqual(val, 99)

    def test_empty(self):
        seq = encode_sequence_indefinite()
        self.assertEqual(seq, b"\x30\x80\x00\x00")
        body, rest = remove_sequence(seq)
        self.assertEqual(body, b"")
        self.assertEqual(rest, b"")


class TestRemoveConstructed(unittest.TestCase):
    def test_simple(self):
        data = b"\xa1\x02\xff\xaa"
        tag, body, rest = remove_constructed(data)
        self.assertEqual(tag, 0x01)
        self.assertEqual(body, b"\xff\xaa")
        self.assertEqual(rest, b"")

    def test_with_malformed_tag(self):
        data = b"\x01\x02\xff\xaa"
        with self.assertRaises(UnexpectedBER) as e:
            remove_constructed(data)
        self.assertIn("constructed tag", str(e.exception))

    def test_indefinite_length(self):
        inner = encode_integer(7)
        data = b"\xa0\x80" + inner + b"\x00\x00"
        tag, body, rest = remove_constructed(data)
        self.assertEqual(tag, 0)
        val, _ = remove_integer(body)
        self.assertEqual(val, 7)
        self.assertEqual(rest, b"")

    def test_indefinite_length_with_remaining(self):
        inner = encode_integer(3)
        data = b"\xa1\x80" + inner + b"\x00\x00" + b"\xbe\xef"
        tag, body, rest = remove_constructed(data)
        self.assertEqual(tag, 1)
        val, _ = remove_integer(body)
        self.assertEqual(val, 3)
        self.assertEqual(rest, b"\xbe\xef")

    def test_truncated_length(self):
        bad = b"\xa0\x82\x10\x00" + b"ABC"
        with self.assertRaises(UnexpectedBER) as e:
            remove_constructed(bad)
        self.assertIn("Length longer", str(e.exception))


class TestEncodeConstructedIndefinite(unittest.TestCase):
    def test_simple(self):
        inner = encode_integer(5)
        result = encode_constructed_indefinite(0, inner)
        self.assertEqual(result[:2], b"\xa0\x80")
        self.assertEqual(result[-2:], b"\x00\x00")

    def test_roundtrip(self):
        inner = encode_integer(77)
        result = encode_constructed_indefinite(3, inner)
        tag, body, rest = remove_constructed(result)
        self.assertEqual(tag, 3)
        self.assertEqual(rest, b"")
        val, _ = remove_integer(body)
        self.assertEqual(val, 77)


class TestEncodeImplicit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = b"\x0a\x0b"
        cls.data_application = b"\x46\x02\x0a\x0b"
        cls.data_context_specific = b"\x86\x02\x0a\x0b"
        cls.data_private = b"\xc6\x02\x0a\x0b"

    def test_encode_with_default_class(self):
        ret = encode_implicit(6, self.data)
        self.assertEqual(ret, self.data_context_specific)

    def test_encode_with_application_class(self):
        ret = encode_implicit(6, self.data, "application")
        self.assertEqual(ret, self.data_application)

    def test_encode_with_context_specific_class(self):
        ret = encode_implicit(6, self.data, "context-specific")
        self.assertEqual(ret, self.data_context_specific)

    def test_encode_with_private_class(self):
        ret = encode_implicit(6, self.data, "private")
        self.assertEqual(ret, self.data_private)

    def test_encode_with_invalid_class(self):
        with self.assertRaises(ValueError) as e:
            encode_implicit(6, self.data, "foobar")
        self.assertIn("invalid tag class", str(e.exception))

    def test_encode_high_tag(self):
        # BER supports high tag numbers (>30), unlike DER
        result = encode_implicit(31, b"\x0a\x0b")
        # High tag form for context-specific: 0x9F 0x1F
        self.assertEqual(result[:2], b"\x9f\x1f")

    def test_encode_constructed_flag(self):
        result = encode_implicit(6, self.data, constructed=True)
        first_byte = str_idx_as_int(result, 0)
        # Constructed bit (bit 6) should be set
        self.assertTrue(first_byte & 0x20)


class TestRemoveImplicit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exp_tag = 6
        cls.exp_data = b"\x0a\x0b"
        cls.data_application = b"\x46\x02\x0a\x0b"
        cls.data_context_specific = b"\x86\x02\x0a\x0b"
        cls.data_private = b"\xc6\x02\x0a\x0b"

    def test_simple(self):
        tag, body, rest = remove_implicit(self.data_context_specific)
        self.assertEqual(tag, self.exp_tag)
        self.assertEqual(body, self.exp_data)
        self.assertEqual(rest, b"")

    def test_wrong_expected_class(self):
        with self.assertRaises(ValueError) as e:
            remove_implicit(self.data_context_specific, "foobar")
        self.assertIn("invalid `exp_class` value", str(e.exception))

    def test_with_wrong_class(self):
        with self.assertRaises(UnexpectedBER) as e:
            remove_implicit(self.data_application)
        self.assertIn("wanted class context-specific", str(e.exception))

    def test_with_application_class(self):
        tag, body, rest = remove_implicit(self.data_application, "application")
        self.assertEqual(tag, self.exp_tag)
        self.assertEqual(body, self.exp_data)
        self.assertEqual(rest, b"")

    def test_with_private_class(self):
        tag, body, rest = remove_implicit(self.data_private, "private")
        self.assertEqual(tag, self.exp_tag)
        self.assertEqual(body, self.exp_data)
        self.assertEqual(rest, b"")

    def test_with_data_following(self):
        extra_data = b"\x00\x01"
        tag, body, rest = remove_implicit(
            self.data_context_specific + extra_data
        )
        self.assertEqual(tag, self.exp_tag)
        self.assertEqual(body, self.exp_data)
        self.assertEqual(rest, extra_data)

    def test_with_constructed(self):
        data = b"\xa6\x02\x0a\x0b"
        with self.assertRaises(UnexpectedBER) as e:
            remove_implicit(data)
        self.assertIn("wanted type primitive", str(e.exception))

    def test_encode_decode(self):
        data = b"some longish string"
        tag, body, rest = remove_implicit(
            encode_implicit(6, data, "application"), "application"
        )
        self.assertEqual(tag, 6)
        self.assertEqual(body, data)
        self.assertEqual(rest, b"")

    def test_high_tag_encode_decode(self):
        data = b"high tag data"
        encoded = encode_implicit(50, data, "context-specific")
        tag, body, rest = remove_implicit(encoded)
        self.assertEqual(tag, 50)
        self.assertEqual(body, data)
        self.assertEqual(rest, b"")

    def test_truncated_length(self):
        bad = b"\x80\x82\x10\x00" + b"ABC"
        with self.assertRaises(UnexpectedBER) as e:
            remove_implicit(bad)
        self.assertIn("Length longer", str(e.exception))


class TestIsSequence(unittest.TestCase):
    def test_true(self):
        self.assertTrue(is_sequence(b"\x30\x00"))

    def test_false(self):
        self.assertFalse(is_sequence(b"\x31\x00"))

    def test_empty(self):
        self.assertFalse(is_sequence(b""))


class TestRemoveTlv(unittest.TestCase):
    def test_integer(self):
        data = encode_integer(42)
        tag, constructed, cls, body, rest = remove_tlv(data)
        self.assertEqual(tag, 2)
        self.assertFalse(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(rest, b"")

    def test_sequence(self):
        inner = encode_integer(1)
        data = encode_sequence(inner)
        tag, constructed, cls, body, rest = remove_tlv(data)
        self.assertEqual(tag, 16)
        self.assertTrue(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(rest, b"")
        val, _ = remove_integer(body)
        self.assertEqual(val, 1)

    def test_indefinite_length_constructed(self):
        inner = encode_integer(5)
        data = b"\x30\x80" + inner + b"\x00\x00"
        tag, constructed, cls, body, rest = remove_tlv(data)
        self.assertEqual(tag, 16)
        self.assertTrue(constructed)
        self.assertEqual(cls, "universal")
        self.assertEqual(rest, b"")
        val, _ = remove_integer(body)
        self.assertEqual(val, 5)

    def test_indefinite_length_primitive_rejects(self):
        # Indefinite length is not allowed for primitive types
        data = b"\x02\x80\x01\x05\x00\x00"
        with self.assertRaises(UnexpectedBER) as e:
            remove_tlv(data)
        self.assertIn("Indefinite length not allowed", str(e.exception))

    def test_empty_string(self):
        with self.assertRaises(UnexpectedBER):
            remove_tlv(b"")

    def test_with_remaining_bytes(self):
        data = encode_integer(10) + b"\xde\xad"
        tag, constructed, cls, body, rest = remove_tlv(data)
        self.assertEqual(tag, 2)
        self.assertEqual(rest, b"\xde\xad")

    def test_truncated_body(self):
        bad = b"\x02\x05\x01"  # claims length 5 but only 1 byte
        with self.assertRaises(UnexpectedBER) as e:
            remove_tlv(bad)
        self.assertIn("Length longer", str(e.exception))


class TestEncodeNumber(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(encode_number(0), b"\x00")

    def test_127(self):
        self.assertEqual(encode_number(127), b"\x7f")

    def test_128(self):
        self.assertEqual(encode_number(128), b"\x81\x00")

    def test_16384(self):
        # 16384 = 0x4000 -> base 128: 0x81 0x80 0x00
        self.assertEqual(encode_number(16384), b"\x81\x80\x00")


class TestSigencodeIndefinite(unittest.TestCase):
    def test_simple_encode(self):
        r, s, order = 42, 99, 2**256
        sig = sigencode_ber_indefinite(r, s, order)
        # Should start with SEQUENCE indefinite: 0x30 0x80
        self.assertEqual(sig[:2], b"\x30\x80")
        # Should end with end-of-contents: 0x00 0x00
        self.assertEqual(sig[-2:], b"\x00\x00")

    def test_roundtrip(self):
        r, s, order = 12345, 67890, 2**256
        sig = sigencode_ber_indefinite(r, s, order)
        r_dec, s_dec = sigdecode_ber_indefinite(sig, order)
        self.assertEqual(r_dec, r)
        self.assertEqual(s_dec, s)

    def test_large_values(self):
        order = 2**256
        r = order - 1
        s = order - 2
        sig = sigencode_ber_indefinite(r, s, order)
        r_dec, s_dec = sigdecode_ber_indefinite(sig, order)
        self.assertEqual(r_dec, r)
        self.assertEqual(s_dec, s)

    def test_small_values(self):
        r, s, order = 1, 1, 2**256
        sig = sigencode_ber_indefinite(r, s, order)
        r_dec, s_dec = sigdecode_ber_indefinite(sig, order)
        self.assertEqual(r_dec, 1)
        self.assertEqual(s_dec, 1)


class TestSigdecodeIndefinite(unittest.TestCase):
    def test_trailing_junk_after_sequence(self):
        r, s, order = 42, 99, 2**256
        sig = sigencode_ber_indefinite(r, s, order) + b"\xff"
        with self.assertRaises(UnexpectedBER) as e:
            sigdecode_ber_indefinite(sig, order)
        self.assertIn("trailing junk after BER sig", str(e.exception))

    def test_trailing_junk_after_integers(self):
        # Manually build: SEQUENCE indefinite with r, s, and extra data
        extra = encode_integer(999)
        inner = encode_integer(42) + encode_integer(99) + extra
        sig = b"\x30\x80" + inner + b"\x00\x00"
        with self.assertRaises(UnexpectedBER) as e:
            sigdecode_ber_indefinite(sig, 2**256)
        self.assertIn("trailing junk after BER numbers", str(e.exception))

    def test_empty_string(self):
        with self.assertRaises(UnexpectedBER):
            sigdecode_ber_indefinite(b"", 2**256)

    def test_wrong_tag(self):
        with self.assertRaises(UnexpectedBER):
            sigdecode_ber_indefinite(b"\x31\x80\x00\x00", 2**256)


HYP_SETTINGS = {}

if "--fast" in sys.argv:  # pragma: no cover
    HYP_SETTINGS["max_examples"] = 2


@settings(**HYP_SETTINGS)
@given(st.integers(min_value=0, max_value=2**256))
def test_integer_roundtrip(value):
    encoded = encode_integer(value)
    decoded, rest = remove_integer(encoded)
    assert rest == b""
    assert decoded == value


@settings(**HYP_SETTINGS)
@given(st.integers(min_value=0, max_value=500))
def test_tag_roundtrip(tag_num):
    for cls in ("universal", "application", "context-specific", "private"):
        for constructed in (True, False):
            encoded = encode_tag(tag_num, constructed=constructed, cls=cls)
            decoded_tag, dec_constructed, dec_cls, consumed = decode_tag(
                encoded
            )
            assert decoded_tag == tag_num
            assert dec_constructed == constructed
            assert dec_cls == cls
            assert consumed == len(encoded)


@settings(**HYP_SETTINGS)
@given(st.integers(min_value=0, max_value=2**32))
def test_length_roundtrip(length):
    encoded = encode_length(length)
    decoded, consumed = read_length(encoded)
    assert decoded == length
    assert consumed == len(encoded)


@settings(**HYP_SETTINGS)
@given(
    st.integers(min_value=1, max_value=2**256 - 1),
    st.integers(min_value=1, max_value=2**256 - 1),
)
def test_sigencode_sigdecode_ber_indefinite_roundtrip(r, s):
    order = 2**256
    sig = sigencode_ber_indefinite(r, s, order)
    r_dec, s_dec = sigdecode_ber_indefinite(sig, order)
    assert r_dec == r
    assert s_dec == s
