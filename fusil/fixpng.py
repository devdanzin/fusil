"""
Functions to recompute (fix) CRC32 checksums of an PNG picture.
"""

from array import array
try:
    from io import StringIO
except ImportError:
    # Python 2
    from StringIO import StringIO
from fusil.bits import bytes2uint, BIG_ENDIAN, uint2bytes
from zlib import crc32
from logging import info

def pngCRC32(data):
    """
    Compute the CRC32 of specified data (str) as an unsigned integer.
    """
    return crc32(data) & 0xFFFFFFFF

def fixPNG(data):
    """
    Fix a mangled PNG picture:
     - Rewrite PNG header (first 8 bytes)
     - Recompute CRC32 of each PNG chunk

    Stop if a chunk length is invalid.
    """
    # array -> str
    data = data.tostring()

    origdata = data
    datalen = len(data)
    data = StringIO(data)

    data.seek(0)
    data.write("\x89PNG\r\n\x1a\n")

    index = 8
    while index < (datalen-4):
        data.seek(index)
        size = bytes2uint(data.read(4), BIG_ENDIAN)
        chunksize = size+12
        if datalen < (index+chunksize):
            info("fixPNG: Skip invalid chunk at %s" % index)
            break

        data.seek(index+4)
        crcdata = data.read(chunksize-8)
        newcrc = uint2bytes(pngCRC32(crcdata), BIG_ENDIAN, 4)

        data.seek(index+chunksize-4)
        data.write(newcrc)

        index += chunksize

    data.seek(0,0)
    data = data.read()
    assert len(data) == len(origdata)

    # str -> array
    data = array('B', data)
    return data

