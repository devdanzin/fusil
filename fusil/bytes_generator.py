r"""
Bytes generators:
 - BytesGenerator
 - LengthGenerator

Byte sets:
 - ASCII8: 0..255
 - ASCII0: 1..255
 - ASCII7: 0..127
 - PRINTABLE_ASCII: 32..126
 - UPPER_LETTERS: 'A'..'Z'
 - LOWER_LETTERS: 'a'..'z'
 - LETTERS: UPPER_LETTERS | LOWER_LETTERS
 - DECIMAL_DIGITS: "0".."9"
 - HEXADECIMAL_DIGITS: DECIMAL_DIGITS | 'a'..'f' | 'A'..'F'
 - PUNCTUATION: --> .,-;?!:(){}[]<>'"/\<--
"""

from random import choice, randint

from ptrace.os_tools import RUNNING_PYTHON3

from fusil.six import b


def createBytesSet(start, stop):
    if RUNNING_PYTHON3:
        return set(range(start, stop + 1))
    else:
        return set(chr(code) for code in xrange(start, stop + 1))


# ASCII codes 0..255
ASCII8 = createBytesSet(0, 255)

# ASCII codes 1..255
ASCII0 = createBytesSet(1, 255)

# ASCII codes 0..127
ASCII7 = createBytesSet(0, 127)

# ASCII codes 32..126
PRINTABLE_ASCII = createBytesSet(32, 126)

# Letters and digits
UPPER_LETTERS = set(b("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
LOWER_LETTERS = set(b("abcdefghijklmnopqrstuvwxyz"))
LETTERS = UPPER_LETTERS | LOWER_LETTERS
DECIMAL_DIGITS = set(b("0123456789"))
HEXADECIMAL_DIGITS = DECIMAL_DIGITS | set(b("abcdefABCDEF"))
PUNCTUATION = set(b(" .,-;?!:(){}[]<>'\"/\\"))


class Generator:
    def __init__(self, min_length, max_length):
        self.min_length = min_length
        self.max_length = max_length

    def createLength(self):
        return randint(self.min_length, self.max_length)

    def _createValue(self, length):
        raise NotImplementedError()

    def createValue(self, length=None):
        if length is None:
            length = self.createLength()
        return self._createValue(length)


class BytesGenerator(Generator):
    def __init__(self, min_length, max_length, bytes_set=ASCII8):
        Generator.__init__(self, min_length, max_length)
        self.bytes_set = bytes_set

    def _createValue(self, length):
        bytes_list = list(self.bytes_set)
        if len(bytes_list) != 1:
            if RUNNING_PYTHON3:
                return bytes(choice(bytes_list) for index in range(length))
            else:
                return "".join(choice(bytes_list) for index in xrange(length))
        else:
            value = bytes_list[0]
            if RUNNING_PYTHON3:
                value = bytes((value,))
            return value * length


class LengthGenerator(BytesGenerator):
    def __init__(self, min_length, max_length):
        BytesGenerator.__init__(self, min_length, max_length, set(b("A")))
