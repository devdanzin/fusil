"""Unit tests for fusil.directory.Directory.uniqueFilename / isEmpty.

uniqueFilename names crash artifacts, so collisions must never overwrite. Uses a real
temp dir; runtime-free.
"""

import os
import tempfile
import unittest

from fusil.directory import Directory


class TestUniqueFilename(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.d = Directory(self.tmp)

    def test_first_use_has_no_suffix(self):
        self.assertEqual(os.path.basename(self.d.uniqueFilename("a.txt")), "a.txt")

    def test_collision_gets_numeric_suffix(self):
        first = self.d.uniqueFilename("a.txt")
        second = self.d.uniqueFilename("a.txt")
        self.assertNotEqual(first, second)
        self.assertEqual(os.path.basename(second), "a-2.txt")

    def test_extensionless_collision(self):
        self.d.uniqueFilename("foo")
        self.assertEqual(os.path.basename(self.d.uniqueFilename("foo")), "foo-2")

    def test_collision_with_existing_file_on_disk(self):
        # A name already present on disk (not via the registry) still collides.
        open(os.path.join(self.tmp, "x.log"), "w").close()
        self.assertEqual(os.path.basename(self.d.uniqueFilename("x.log")), "x-2.log")

    def test_save_false_does_not_register(self):
        self.d.uniqueFilename("b.txt", save=False)
        # Not registered => the next call reuses the bare name.
        self.assertEqual(os.path.basename(self.d.uniqueFilename("b.txt", save=False)), "b.txt")

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            self.d.uniqueFilename("")


class TestIsEmpty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_empty_dir(self):
        self.assertTrue(Directory(self.tmp).isEmpty())

    def test_non_empty_dir(self):
        open(os.path.join(self.tmp, "f"), "w").close()
        self.assertFalse(Directory(self.tmp).isEmpty())


if __name__ == "__main__":
    unittest.main()
