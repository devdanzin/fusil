import unittest
import sys
import os

# --- Test Setup: Path Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    from fusil.python.unicode import escapeUnicode
    UNICODE_AVAILABLE = True
except ImportError as e:
    print(f"Could not import unicode module, skipping tests: {e}", file=sys.stderr)
    escapeUnicode = None
    UNICODE_AVAILABLE = False


@unittest.skipIf(not UNICODE_AVAILABLE, "Could not import unicode module, skipping tests.")
class TestUnicode(unittest.TestCase):
    """
    Test suite for the unicode.py module.

    Verifies the escapeUnicode function.
    """

    def test_escape_unicode_function(self):
        """
        Tests the escapeUnicode helper function with various inputs.
        """
        self.assertEqual(escapeUnicode("hello"), "hello")
        self.assertEqual(escapeUnicode('hello"world'), 'hello\\"world')
        self.assertEqual(escapeUnicode("\x07"), "\\x07")
        self.assertEqual(escapeUnicode("¢"), "\\xA2")
        self.assertEqual(escapeUnicode("😀"), "\\U0001F600")


if __name__ == '__main__':
    unittest.main()
