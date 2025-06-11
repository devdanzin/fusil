SURROGATES = (
    '"\\x00"',
    '"\\x00"',
    '"\\x00"',
    '"\\x00"',
    '"\\uDC80"',
    '"\\uDC80"',
    '"\\U0010FFFF"',
    '"\\U0010FFFF"',
    '"\\udbff\\udfff"',
)
BUFFER_OBJECTS = (
    'bytearray(b"abc\\xe9\\xff")',
    'bytearray(b"test")',
    'memoryview(b"abc\\xe9\\xff")',
    'memoryview(bytearray(b"abc\\xe9\\xff"))',
)
INTERESTING = (
    "0",
    # Large integer boundaries
    "sys.maxsize",  # Maximum integer size for current platform
    "sys.maxsize - 1",  # One below maximum integer size
    "sys.maxsize + 1",  # One above maximum integer size (overflow test)
    "-sys.maxsize",  # Negative maximum integer boundary
    "2 ** 63 - 1",  # 64-bit integer boundary (signed max for 64-bit)
    "-2 ** 63",  # 64-bit integer boundary (signed min for 64-bit)
    "2 ** 31 - 1",  # 32-bit integer boundary (signed max for 32-bit)
    "-2 ** 31",  # 32-bit integer boundary (signed min for 32-bit)
    # Large powers and exponential values
    "10 ** (sys.int_info.default_max_str_digits + 1)",  # Overflow of typical max digit handling
    "10 ** 100",  # Extremely large integer to test overflow and precision
    "-10 ** (sys.int_info.default_max_str_digits)",  # Large negative integer boundary
    "10 ** (sys.int_info.default_max_str_digits + 2)",  # Further max digit overflow test
    # Floating-point boundaries and edge cases
    'float("nan")',  # NaN, tests handling of undefined floats
    'float("inf")',  # Positive infinity
    'float("-inf")',  # Negative infinity
    "sys.float_info.epsilon",  # Smallest positive float greater than zero
    "sys.float_info.max",  # Maximum representable float
    "sys.float_info.min",  # Minimum positive float
    "-sys.float_info.max",  # Negative maximum float
    "-sys.float_info.epsilon",  # Negative epsilon (smallest magnitude negative float)
    "sys.float_info.min / 2",  # Value close to underflow boundary
    "-sys.float_info.min / 2",  # Negative value close to underflow boundary
    'float("0.0000001")',  # Very small float, near zero
    '-float("0.0000001")',  # Very small negative float, near zero
    # Complex numbers with extreme values
    "complex(sys.maxsize, sys.maxsize)",  # Large complex number with large real and imaginary parts
    'complex(float("inf"), float("nan"))',  # Complex with infinity and NaN
    "complex(sys.float_info.max, sys.float_info.epsilon)",  # Mix of large and tiny parts in complex
    "1j",  # Small complex number with imaginary unit
    "-1j",  # Negative small complex number with imaginary unit
    # Unicode and string boundary tests
    "chr(0)",  # Null character
    "chr(127)",  # Edge of ASCII range
    "chr(255)",  # Edge of extended ASCII range
    "chr(0x10FFFF)",  # Maximum Unicode code point
    r'"\uDC80"',  # Unpaired surrogate, tests encoding robustness
    '"𝒜"',  # Surrogate pair in UTF-16
    r'"\x00" * 10',  # Null byte sequence
    '"A" * (2 ** 16)',  # Large string boundary (typical buffer size)
    '"💻" * 2**10',  # Large string with multibyte Unicode characters
    # Boolean and None values
    "True",  # Basic boolean value
    "False",  # Basic boolean value
    "None",  # None, tests for null handling
    # Pathological data structures
    "[]",  # Empty list
    "[[]]",  # Nested empty list
    "[[[]]]",  # Deeply nested empty list
    "{0: {0: {0: {}}}}",  # Deeply nested dictionary
    '[(None, 1, "a") for _ in range(2**10)]',  # Large list with mixed types
    "[[1] * 10] * 10",  # Nested lists with shared references
    'bytearray(b"")',  # Empty byte array
    'bytearray(b"A" * 2**10)',  # Moderately large byte array
    # Bytes and encoded data
    "bytes(10 ** 5)",  # Large empty bytes sequence
    "bytes(range(256))",  # Full byte range, all possible byte values
    r'b"\x00" * (2**16)',  # Maximum byte array handling with null bytes
    'memoryview(b"A" * 2**8)',  # Memory view around a moderately large byte array
    # Regular expressions and raw strings
    'r"^(?:a|aa)*$"',  # Complex regex pattern
    r'r"\A[\w-]+\Z"',  # Simple regex pattern
    r'r"\d{1,100}"',  # Large quantifier regex pattern
    # Lambda and object instances
    "lambda: None",  # Simple lambda function (tests function call handling)
    "(lambda x: sys.maxsize)",  # Lambda with boundary value as output
    "object()",  # Base object with minimal attributes
    "frozenset({sys.maxsize, -sys.maxsize})",  # Immutable set with boundary values
    # Other encoding and integer tests
    '"A" * (2**10)',  # Large simple string
    "complex(-10 ** 10, 10 ** 10)",  # Complex number with extreme real and imaginary values
    "(sys.maxunicode + 1,)",  # Beyond max Unicode
)
