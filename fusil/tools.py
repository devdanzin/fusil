import re

from fusil.six import text_type
from fusil.six.moves import zip as izip


def minmax(min_value, value, max_value):
    """
    Restrict value to [min_value; max_value]

    >>> minmax(-2, -3, 10)
    -2
    >>> minmax(-2, 27, 10)
    10
    >>> minmax(-2, 0, 10)
    0
    """
    return min(max(min_value, value), max_value)


def listDiff(old, new):
    """
    Difference of two lists item by item.

    >>> listDiff([4, 0, 3], [10, 0, 50])
    [6, 0, 47]
    """
    return [item[1] - item[0] for item in izip(old, new)]


def timedeltaSeconds(delta):
    """
    Convert a datetime.timedelta() objet to a number of second
    (floatting point number).

    >>> from datetime import timedelta
    >>> timedeltaSeconds(timedelta(seconds=2, microseconds=40000))
    2.04
    >>> timedeltaSeconds(timedelta(minutes=1, milliseconds=250))
    60.25
    """
    return delta.microseconds / 1000000.0 + delta.seconds + delta.days * 3600 * 24


def makeUnicode(text):
    if isinstance(text, text_type):
        return text
    try:
        return text_type(text, "utf8")
    except UnicodeError:
        pass
    return text_type(text, "ISO-8859-1")


def makeFilename(text):
    """
    >>> makeFilename('Fatal error!')
    'fatal_error'
    """
    if isinstance(text, text_type):
        text = text.lower()
        text = re.sub("[^a-z_-]", "_", text)
        text = re.sub("_{2,}", "_", text)
        text = re.sub("_$", "", text)
    else:
        # byte string
        text = text.lower()
        text = re.sub(b"[^a-z_-]", b"_", text)
        text = re.sub(b"_{2,}", b"_", text)
        text = re.sub(b"_$", b"", text)
    return text
