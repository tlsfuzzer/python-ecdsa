from __future__ import division

import binascii
from . import der
from six import int2byte
from ._compat import str_idx_as_int


# Tag class values (bits 8 and 7 of the identifier octet)
TAG_CLASS_UNIVERSAL = 0b00000000
TAG_CLASS_APPLICATION = 0b01000000
TAG_CLASS_CONTEXT_SPECIFIC = 0b10000000
TAG_CLASS_PRIVATE = 0b11000000

# Bit 6: 0 = primitive, 1 = constructed
TAG_PRIMITIVE = 0b00000000
TAG_CONSTRUCTED = 0b00100000

# Indefinite length marker
INDEFINITE_LENGTH = 0x80

# End-of-contents octets
END_OF_CONTENTS = b"\x00\x00"


class UnexpectedBER(Exception):
    pass


def _tag_class_from_name(cls):
    """Convert a tag class name to its numeric value."""
    if cls == "universal":
        return TAG_CLASS_UNIVERSAL
    elif cls == "application":
        return TAG_CLASS_APPLICATION
    elif cls == "context-specific":
        return TAG_CLASS_CONTEXT_SPECIFIC
    elif cls == "private":
        return TAG_CLASS_PRIVATE
    else:
        raise ValueError(
            "invalid tag class: {0}, must be one of 'universal', "
            "'application', 'context-specific', 'private'".format(cls)
        )


def encode_tag(tag, constructed=False, cls="universal"):
    """
    Encode a BER identifier (tag) octet(s).

    Supports both low tag numbers (0-30, single octet) and high tag numbers
    (31+, multi-octet).

    :param int tag: the tag number to encode
    :param bool constructed: if True, set the constructed bit (bit 6);
        otherwise use primitive encoding
    :param str cls: the class of the tag: "universal", "application",
        "context-specific", or "private"
    :rtype: bytes
    """
    tag_class = _tag_class_from_name(cls)
    method_bit = TAG_CONSTRUCTED if constructed else TAG_PRIMITIVE

    if tag < 0:
        raise ValueError("Tag number must be non-negative")

    if tag <= 30:
        # Low-tag-number form: single octet
        return int2byte(tag_class | method_bit | tag)
    else:
        # High-tag-number form: first octet has bits 5-1 all set to 1,
        # followed by tag number in base-128
        first_octet = tag_class | method_bit | 0x1F
        tag_bytes = encode_number(tag)
        return int2byte(first_octet) + tag_bytes


def decode_tag(string):
    """
    Decode a BER identifier (tag) from the beginning of `string`.

    Returns the tag number, whether it is constructed, the tag class name,
    and the number of octets consumed.

    :param bytes string: the byte string to decode from
    :return: tuple of (tag_number, constructed, class_name, octets_consumed)
    :rtype: tuple(int, bool, str, int)
    """
    if not string:
        raise UnexpectedBER("Empty string does not encode a tag")

    first = str_idx_as_int(string, 0)

    # Decode class (bits 8-7)
    class_bits = first & 0b11000000
    if class_bits == TAG_CLASS_UNIVERSAL:
        cls = "universal"
    elif class_bits == TAG_CLASS_APPLICATION:
        cls = "application"
    elif class_bits == TAG_CLASS_CONTEXT_SPECIFIC:
        cls = "context-specific"
    else:
        cls = "private"

    # Decode constructed/primitive (bit 6)
    constructed = bool(first & TAG_CONSTRUCTED)

    # Decode tag number (bits 5-1)
    tag_bits = first & 0x1F

    if tag_bits < 0x1F:
        # Low-tag-number form
        return tag_bits, constructed, cls, 1

    # High-tag-number form: read base-128 encoded tag number
    if len(string) < 2:
        raise UnexpectedBER("Truncated high-tag-number encoding")
    # First subsequent octet must not be 0x80 (non-minimal)
    if str_idx_as_int(string, 1) == 0x80:
        raise UnexpectedBER("Non-minimal encoding of high tag number")
    tag_number, num_len = read_number(string[1:])
    if tag_number <= 30:
        raise UnexpectedBER(
            "Tag number {0} should use low-tag-number form".format(tag_number)
        )
    return tag_number, constructed, cls, 1 + num_len


def encode_length(length):
    """
    :param int length: the length to encode, must be non-negative
    :rtype: bytes
    """
    return der.encode_length(length)


def encode_indefinite_length():
    """
    Encode the BER indefinite-length marker.

    Returns a single octet 0x80, used for constructed indefinite-length
    encodings.

    :rtype: bytes
    """
    return b"\x80"


def encode_end_of_contents():
    """
    Encode the BER end-of-contents octets.

    Returns two octets 0x00 0x00, which terminate a constructed
    indefinite-length encoding. This is the primitive, definite-length
    encoding of a value with universal class, tag number 0, and length 0.

    :rtype: bytes
    """
    return END_OF_CONTENTS


def read_length(string):
    """
    Read a BER length value from the beginning of `string`.

    Supports short form, long definite form, and indefinite form.

    For definite lengths, returns (length, number_of_octets_consumed).
    For indefinite length, returns (None, 1).

    Unlike DER, BER does not require minimal length encoding, so
    non-minimal encodings are accepted.

    :param bytes string: the byte string to read from
    :return: tuple of (length_or_None, octets_consumed)
    :rtype: tuple(int or None, int)
    """
    if not string:
        raise UnexpectedBER("Empty string can't encode valid length value")
    num = str_idx_as_int(string, 0)

    if not (num & 0x80):
        # Short form: single octet, bit 8 = 0, bits 7-1 give the length
        return (num & 0x7F), 1

    llen = num & 0x7F
    if llen == 0:
        # Indefinite form: octet 0x80
        return None, 1

    # Long definite form: llen additional octets encode the length
    if llen > len(string) - 1:
        raise UnexpectedBER("Length of length longer than provided buffer")
    # BER does not require minimal encoding, so we accept any valid encoding
    return int(binascii.hexlify(string[1 : 1 + llen]), 16), 1 + llen


def _read_indefinite_contents(string):
    """
    Read contents from an indefinite-length encoding.

    Scans `string` for end-of-contents octets (0x00 0x00) and returns
    the contents and remaining bytes.

    :param bytes string: the byte string to scan
    :return: tuple of (contents_bytes, remaining_bytes)
    :rtype: tuple(bytes, bytes)
    """
    # We need to scan through properly-formed TLV structures until we
    # find the end-of-contents octets (tag=0x00, length=0x00)
    offset = 0
    while True:
        if offset >= len(string):
            raise UnexpectedBER(
                "Indefinite-length encoding missing end-of-contents octets"
            )
        if offset + 1 < len(string):
            if (
                str_idx_as_int(string, offset) == 0x00
                and str_idx_as_int(string, offset + 1) == 0x00
            ):
                # Found end-of-contents
                return string[:offset], string[offset + 2 :]

        # Read past this TLV element
        _, _, _, tag_len = decode_tag(string[offset:])
        if offset + tag_len >= len(string):
            raise UnexpectedBER(
                "Truncated element in indefinite-length contents"
            )
        length, llen = read_length(string[offset + tag_len :])
        if length is None:
            # Nested indefinite-length encoding
            inner_contents, _ = _read_indefinite_contents(
                string[offset + tag_len + llen :]
            )
            # Calculate how far we advanced: tag + length_marker + contents
            # + end-of-contents
            element_len = (
                tag_len
                + llen
                + len(inner_contents)
                + 2  # end-of-contents octets
            )
            offset += element_len
        else:
            offset += tag_len + llen + length


def encode_constructed(tag, value):
    """
    Encode a context-specific, constructed value using BER
    definite-length encoding.

    :param int tag: the tag number (0-30)
    :param bytes value: the already-encoded contents
    :rtype: bytes
    """
    return der.encode_constructed(tag, value)


def encode_constructed_indefinite(tag, value):
    """
    Encode a context-specific, constructed value using BER
    indefinite-length encoding.

    :param int tag: the tag number (0-30)
    :param bytes value: the already-encoded contents
    :rtype: bytes
    """
    return (
        int2byte(0xA0 + tag)
        + encode_indefinite_length()
        + value
        + encode_end_of_contents()
    )


def encode_implicit(tag, value, cls="context-specific", constructed=False):
    """
    Encode an IMPLICIT value using BER.

    Supports high tag numbers (>30) via multi-byte tag encoding.

    :param int tag: the tag value to encode
    :param bytes value: the data to encode
    :param str cls: the class of the tag: "application", "context-specific",
        or "private"
    :param bool constructed: if True, set the constructed bit
    :rtype: bytes
    """
    if cls not in ("application", "context-specific", "private"):
        raise ValueError("invalid tag class")

    return (
        encode_tag(tag, constructed=constructed, cls=cls)
        + encode_length(len(value))
        + value
    )


def encode_integer(r):
    """
    Encode a non-negative integer using BER.

    :param int r: the integer to encode, must be >= 0
    :rtype: bytes
    """
    return der.encode_integer(r)


def encode_sequence(*encoded_pieces):
    """
    Encode a SEQUENCE using BER definite-length encoding.

    :param encoded_pieces: already-encoded elements of the sequence
    :rtype: bytes
    """
    return der.encode_sequence(*encoded_pieces)


def encode_sequence_indefinite(*encoded_pieces):
    """
    Encode a SEQUENCE using BER indefinite-length encoding.

    The resulting encoding uses the constructed, indefinite-length method
    with end-of-contents octets (0x00 0x00) to mark the end.

    :param encoded_pieces: already-encoded elements of the sequence
    :rtype: bytes
    """
    return (
        b"\x30"
        + encode_indefinite_length()
        + b"".join(encoded_pieces)
        + encode_end_of_contents()
    )


def encode_number(n):
    """
    Encode a number in base-128 big-endian form (for OID sub-identifiers
    and high tag numbers).

    :param int n: the number to encode
    :rtype: bytes
    """
    return der.encode_number(n)


def is_sequence(string):
    """Check if `string` starts with a SEQUENCE tag."""
    return der.is_sequence(string)


def remove_constructed(string):
    """
    Remove a context-specific constructed value from `string`.

    Supports both definite-length and indefinite-length encodings.

    :param bytes string: byte string to decode
    :return: tuple of (tag, body, rest)
    :rtype: tuple(int, bytes, bytes)
    """
    s0 = str_idx_as_int(string, 0)
    if (s0 & 0xE0) != 0xA0:
        raise UnexpectedBER(
            "wanted type 'constructed tag' (0xa0-0xbf), got 0x{0:02x}".format(
                s0
            )
        )
    tag = s0 & 0x1F
    length, llen = read_length(string[1:])

    if length is None:
        # Indefinite-length encoding
        body, rest = _read_indefinite_contents(string[1 + llen :])
        return tag, body, rest

    if length > len(string) - 1 - llen:
        raise UnexpectedBER("Length longer than the provided buffer")
    body = string[1 + llen : 1 + llen + length]
    rest = string[1 + llen + length :]
    return tag, body, rest


def remove_implicit(string, exp_class="context-specific"):
    """
    Remove an IMPLICIT tagged value from `string` following BER.

    Supports high tag numbers (>30) via multi-byte tag decoding.

    :param bytes string: byte string to decode
    :param str exp_class: expected tag class: "context-specific",
        "application", or "private"
    :return: tuple of (tag, body, rest)
    :rtype: tuple(int, bytes, bytes)
    """
    if exp_class not in ("context-specific", "application", "private"):
        raise ValueError("invalid `exp_class` value")

    tag_number, constructed, cls, tag_len = decode_tag(string)

    if cls != exp_class:
        raise UnexpectedBER(
            "wanted class {0}, got class {1}".format(exp_class, cls)
        )
    if constructed:
        raise UnexpectedBER("wanted type primitive, got constructed tag")

    length, llen = read_length(string[tag_len:])
    if length is None:
        raise UnexpectedBER(
            "Indefinite length not allowed for primitive encoding"
        )
    if length > len(string) - tag_len - llen:
        raise UnexpectedBER("Length longer than the provided buffer")
    body = string[tag_len + llen : tag_len + llen + length]
    rest = string[tag_len + llen + length :]
    return tag_number, body, rest


def remove_sequence(string):
    """
    Remove a SEQUENCE from `string` following BER.

    Supports both definite-length and indefinite-length encodings.

    :param bytes string: byte string to decode
    :return: tuple of (sequence_body, rest)
    :rtype: tuple(bytes, bytes)
    """
    if not string:
        raise UnexpectedBER("Empty string does not encode a sequence")
    if string[:1] != b"\x30":
        n = str_idx_as_int(string, 0)
        raise UnexpectedBER(
            "wanted type 'sequence' (0x30), got 0x{0:02x}".format(n)
        )
    length, lengthlength = read_length(string[1:])

    if length is None:
        # Indefinite-length encoding
        body, rest = _read_indefinite_contents(string[1 + lengthlength :])
        return body, rest

    if length > len(string) - 1 - lengthlength:
        raise UnexpectedBER("Length longer than the provided buffer")
    endseq = 1 + lengthlength + length
    return string[1 + lengthlength : endseq], string[endseq:]


def remove_integer(string):
    """
    Remove an INTEGER from `string` following BER.

    Unlike DER, BER does not require minimal encoding of integers,
    so extra leading zero bytes are accepted.

    :param bytes string: byte string to decode
    :return: tuple of (integer_value, rest)
    :rtype: tuple(int, bytes)
    """
    if not string:
        raise UnexpectedBER(
            "Empty string is an invalid encoding of an integer"
        )
    if string[:1] != b"\x02":
        n = str_idx_as_int(string, 0)
        raise UnexpectedBER(
            "wanted type 'integer' (0x02), got 0x{0:02x}".format(n)
        )
    length, llen = read_length(string[1:])
    if length is None:
        raise UnexpectedBER("Indefinite length not valid for INTEGER")
    if length > len(string) - 1 - llen:
        raise UnexpectedBER("Length longer than provided buffer")
    if length == 0:
        raise UnexpectedBER("0-byte long encoding of integer")
    numberbytes = string[1 + llen : 1 + llen + length]
    rest = string[1 + llen + length :]
    msb = str_idx_as_int(numberbytes, 0)
    if not msb < 0x80:
        raise UnexpectedBER("Negative integers are not supported")
    # BER does not require minimal encoding, so we accept non-minimal
    # integer encodings (extra leading zero bytes)
    return int(binascii.hexlify(numberbytes), 16), rest


def read_number(string):
    """
    Read a base-128 encoded number from `string`.

    Used for OID sub-identifiers and high tag numbers.

    :param bytes string: byte string to read from
    :return: tuple of (number, octets_consumed)
    :rtype: tuple(int, int)
    """
    try:
        number, llen = der.read_number(string)
    except der.UnexpectedDER as e:
        raise UnexpectedBER(str(e))
    return number, llen


def remove_tlv(string):
    """
    Remove a single BER TLV (Tag-Length-Value) element from `string`.

    This is a generic function that can decode any BER-encoded element
    without knowledge of its specific type.

    :param bytes string: byte string to decode
    :return: tuple of (tag_number, constructed, class_name, body, rest)
    :rtype: tuple(int, bool, str, bytes, bytes)
    """
    if not string:
        raise UnexpectedBER("Empty string does not encode a TLV")

    tag_number, constructed, cls, tag_len = decode_tag(string)
    length, llen = read_length(string[tag_len:])

    if length is None:
        if not constructed:
            raise UnexpectedBER(
                "Indefinite length not allowed for primitive encoding"
            )
        body, rest = _read_indefinite_contents(string[tag_len + llen :])
        return tag_number, constructed, cls, body, rest

    total_header = tag_len + llen
    if length > len(string) - total_header:
        raise UnexpectedBER("Length longer than the provided buffer")
    body = string[total_header : total_header + length]
    rest = string[total_header + length :]
    return tag_number, constructed, cls, body, rest
