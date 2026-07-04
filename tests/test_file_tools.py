"""Unit tests for fusil.file_tools — the two path helpers.

``filenameExtension`` returns the dotted extension of the *basename* (or None), and
``relativePath`` strips a leading working-directory prefix. Both are tiny, pure, and
dependency-free, so these tests exercise the real functions directly and only mock
``os.getcwd`` for the default-cwd path of ``relativePath``.
"""

import unittest
from unittest import mock

from fusil.file_tools import filenameExtension, relativePath


class TestFilenameExtension(unittest.TestCase):
    def test_simple_extension(self):
        self.assertEqual(filenameExtension("/a/b/file.txt"), ".txt")

    def test_bare_filename(self):
        self.assertEqual(filenameExtension("file.txt"), ".txt")

    def test_multiple_dots_returns_last(self):
        self.assertEqual(filenameExtension("/a/b/archive.tar.gz"), ".gz")

    def test_no_extension_returns_none(self):
        self.assertIsNone(filenameExtension("/a/b/noext"))

    def test_bare_name_without_dot_returns_none(self):
        self.assertIsNone(filenameExtension("README"))

    def test_only_directory_component_has_dot(self):
        # The dot is in a directory component, not the basename -> no extension.
        self.assertIsNone(filenameExtension("/path.with.dot/file"))

    def test_dotfile_treated_as_extension(self):
        # basename ".bashrc" contains a dot, so rsplit yields "bashrc".
        self.assertEqual(filenameExtension("/home/user/.bashrc"), ".bashrc")

    def test_trailing_dot_yields_bare_dot(self):
        self.assertEqual(filenameExtension("file."), ".")


class TestRelativePath(unittest.TestCase):
    def test_strips_explicit_cwd_prefix(self):
        self.assertEqual(
            relativePath("/home/user/proj/sub/file.py", "/home/user/proj"),
            "sub/file.py",
        )

    def test_path_not_under_cwd_is_unchanged(self):
        self.assertEqual(
            relativePath("/etc/passwd", "/home/user/proj"),
            "/etc/passwd",
        )

    def test_path_equal_to_cwd_becomes_empty(self):
        # path[len(cwd) + 1:] strips the (nonexistent) trailing separator too.
        self.assertEqual(relativePath("/home/user/proj", "/home/user/proj"), "")

    def test_default_cwd_uses_getcwd(self):
        with mock.patch("fusil.file_tools.getcwd", return_value="/work/dir"):
            self.assertEqual(relativePath("/work/dir/a/b.py"), "a/b.py")

    def test_default_cwd_not_matching_is_unchanged(self):
        with mock.patch("fusil.file_tools.getcwd", return_value="/work/dir"):
            self.assertEqual(relativePath("/elsewhere/a.py"), "/elsewhere/a.py")

    def test_empty_cwd_falls_back_to_getcwd(self):
        # A falsy cwd argument triggers the getcwd() default.
        with mock.patch("fusil.file_tools.getcwd", return_value="/work") as g:
            self.assertEqual(relativePath("/work/x", cwd=""), "x")
            g.assert_called_once()


if __name__ == "__main__":
    unittest.main()
