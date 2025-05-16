"""
Functions and constants to prepare Unicode strings.
"""

ESCAPE_CHARACTERS = "'" + '"' + "\\"


def formatCharacter(char):
    if char in ESCAPE_CHARACTERS:
        # >\"<
        return "\\" + char
    code = ord(char)
    if 32 <= code <= 126:
        # >a<
        return char
    elif code <= 255:
        # >\xEF<
        return "\\x%02X" % code
    elif code <= 65535:
        # >\u0101<
        return "\\u%04X" % code
    else:
        # >\U00010FA3<
        return "\\U%08X" % code


def escapeUnicode(text):
    return "".join(formatCharacter(char) for char in text)
