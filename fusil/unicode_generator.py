from fusil.bytes_generator import Generator
from fusil.six import text_type, unichr
from fusil.six.moves import range as xrange
from random import choice, randint

def createCharset(start, stop):
    return set(u''.join( unichr(code) for code in xrange(start, stop+1) ))

# ASCII codes 0..255
ASCII8 = createCharset(0, 255)

# ASCII codes 1..255
ASCII0 = createCharset(1, 255)

# ASCII codes 0..127
ASCII7 = createCharset(0, 127)

# ASCII codes 32..126
PRINTABLE_ASCII = createCharset(32, 126)

# Unicode: codes 0..65535
UNICODE_65535 = createCharset(0, 65535)

# Letters and digits
UPPER_LETTERS = set(u'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
LOWER_LETTERS = set(u'abcdefghijklmnopqrstuvwxyz')
LETTERS = UPPER_LETTERS | LOWER_LETTERS
DECIMAL_DIGITS = set(u'0123456789')
HEXADECIMAL_DIGITS = DECIMAL_DIGITS | set(u'abcdefABCDEF')
PUNCTUATION = set(u' .,-;?!:(){}[]<>\'"/\\')

class UnicodeGenerator(Generator):
    def __init__(self, min_length, max_length, charset=ASCII8):
        Generator.__init__(self, min_length, max_length)
        self.charset = list(charset)

    def _createValue(self, length):
        if 1 < len(self.charset):
            return u''.join( choice(self.charset)
                for index in xrange(length) )
        else:
            return self.charset[0] * length

class UnsignedGenerator(UnicodeGenerator):
    """Unsigned integer"""
    def __init__(self, max_length=20, charset=DECIMAL_DIGITS, min_length=1):
        # 2^32 length in decimal: 10 digits
        # 2^64 length in decimal: 20 digits
        # 2^128 length in decimal: 39 digits
        UnicodeGenerator.__init__(self, min_length, max_length, charset)
        # First digit charset
        self.first_digit = list(charset - set('0'))

    def _createValue(self, length):
        if 2 <= length:
            return choice(self.first_digit) \
                + UnicodeGenerator._createValue(self, length - 1)
        else:
            return UnicodeGenerator._createValue(self, length)

class IntegerGenerator(UnsignedGenerator):
    """Signed integer"""
    def __init__(self, max_length=21, charset=DECIMAL_DIGITS):
        # 2^32 length in decimal: 10 digits + sign = 11
        # 2^64 length in decimal: 20 digits + sign = 21
        # 2^128 length in decimal: 39 digits + sign = 40
        UnsignedGenerator.__init__(self, max_length, charset=charset, min_length=2)

    def _createValue(self, length):
        value = UnsignedGenerator._createValue(self, length-1)
        if randint(0, 1) == 1:
            value = u"-" + value
        return value

class IntegerRangeGenerator(Generator):
    """
    Random signed integer in the specified range.
    """
    def __init__(self, min, max):
        Generator.__init__(self, 1, 1)
        self.min = min
        self.max = max

    def createValue(self):
        value = randint(self.min, self.max)
        return text_type(value)

class UnixPathGenerator(UnicodeGenerator):
    def __init__(self, max_length=None, absolute=False, charset=None):
        if not max_length:
            max_length = 5000
        UnicodeGenerator.__init__(self, 1, max_length)
        if not charset:
            charset = UPPER_LETTERS | LOWER_LETTERS | DECIMAL_DIGITS | set('-_.')
        self.filename_length = 100
        self.filename_generator = UnicodeGenerator(1, 1, charset)
        self.change_dir = (".", "..")
        self.absolute = absolute

    def _createValue(self, length):
        path = []
        path_len = 0
        while path_len < length:
            if not path:
                # Absolute path? (25%)
                use_slash = self.absolute or (randint(0, 4) == 0)
            elif path[-1] == u'/':
                # Add double slash, eg. /a/b// ? (10%)
                use_slash = (randint(0, 9) == 0)
            else:
                use_slash = True

            if use_slash:
                part = u'/'
            else:
                filelen = min(randint(1, length - path_len), self.filename_length)
                if randint(0, 9) != 0:
                    # Filename
                    part = self.filename_generator.createValue(length=filelen)
                else:
                    # "." or ".."
                    part = choice(self.change_dir)
            path.append(part)
            path_len += len(part)
        return u''.join(path)

