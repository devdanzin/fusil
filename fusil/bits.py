"""
Convert bytes string to integer, and integer to bytes string.
"""

from struct import calcsize, unpack, error as struct_error
from itertools import chain, repeat

BIG_ENDIAN = "ABCD"
LITTLE_ENDIAN = "DCBA"

def uint2bytes(value, endian, size=None):
    r"""
    Convert an unsigned integer to a bytes string in the specified endian.
    If size is given, add nul bytes to fill to size bytes.

    >>> uint2bytes(0x1219, BIG_ENDIAN)
    '\x12\x19'
    >>> uint2bytes(0x1219, BIG_ENDIAN, 4)   # 32 bits
    '\x00\x00\x12\x19'
    >>> uint2bytes(0x1219, LITTLE_ENDIAN, 4)   # 32 bits
    '\x19\x12\x00\x00'
    """
    assert (not size and 0 < value) or (0 <= value)
    assert endian in (LITTLE_ENDIAN, BIG_ENDIAN)
    text = []
    while (value != 0 or text == ""):
        byte = value % 256
        text.append( chr(byte) )
        value >>= 8
    if size:
        need = max(size - len(text), 0)
    else:
        need = 0
    if need:
        if endian is BIG_ENDIAN:
            text = chain(repeat("\0", need), reversed(text))
        else:
            text = chain(text, repeat("\0", need))
    else:
        if endian is BIG_ENDIAN:
            text = reversed(text)
    return "".join(text)

def _createStructFormat():
    """
    Create a dictionnary (endian, size_byte) => struct format used
    by bytes2uint() to convert raw data to positive integer.
    """
    format = {
        BIG_ENDIAN:    {},
        LITTLE_ENDIAN: {},
    }
    for struct_format in "BHILQ":
        try:
            size = calcsize(struct_format)
            format[BIG_ENDIAN][size] = '>%s' % struct_format
            format[LITTLE_ENDIAN][size] = '<%s' % struct_format
        except struct_error:
            pass
    return format
_struct_format = _createStructFormat()

def bytes2uint(data, endian):
    r"""
    Convert a bytes string into an unsigned integer.

    >>> chr(bytes2uint('*', BIG_ENDIAN))
    '*'
    >>> bytes2uint("\x00\x01\x02\x03", BIG_ENDIAN) == 0x10203
    True
    >>> bytes2uint("\x2a\x10", LITTLE_ENDIAN) == 0x102a
    True
    >>> bytes2uint("\xff\x14\x2a\x10", BIG_ENDIAN) == 0xff142a10
    True
    >>> bytes2uint("\x00\x01\x02\x03", LITTLE_ENDIAN) == 0x3020100
    True
    >>> bytes2uint("\xff\x14\x2a\x10\xab\x00\xd9\x0e", BIG_ENDIAN) == 0xff142a10ab00d90e
    True
    >>> bytes2uint("\xff\xff\xff\xff\xff\xff\xff\xff", BIG_ENDIAN) == (2**64-1)
    True
    """
    assert 1 <= len(data) <= 32   # arbitrary limit: 256 bits
    try:
        return unpack(_struct_format[endian][len(data)], data)[0]
    except KeyError:
        pass

    assert endian in (BIG_ENDIAN, LITTLE_ENDIAN)
    shift = 0
    value = 0
    if endian is BIG_ENDIAN:
        data = reversed(data)
    for character in data:
        byte = ord(character)
        value += (byte << shift)
        shift += 8
    return value

