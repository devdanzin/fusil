from ptrace.six import b

def generateSpecialValues():
    values = (
        # Special values in big endian
        # SPECIAL_VALUES will contains value in big endian and little endian
        b("\x00"),
        b("\x00\x00"),
        b("\x01"),
        b("\x00\x01"),
        b("\x7f"),
        b("\x7f\xff"),
        b("\x7f\xff\xff\xff"),
        b("\x80"),
        b("\x80\x00"),
        b("\x80\x00\x00\x00"),
        b("\xfe"),
        b("\xfe\xff"),
        b("\xfe\xff\xff\xff"),
        b("\xff"),
        b("\xff\xff"),
        b("\xff\xff\xff\xff"),
    )
    result = []
    for item in values:
        result.append(item)
        itemb = item[::-1]
        if item != itemb:
            result.append(itemb)
    return result

SPECIAL_VALUES = generateSpecialValues()

MAX_INCR = 8

