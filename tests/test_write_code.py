"""Tests for the WriteCode base (the code-generation primitives)."""

import io
import unittest

from fusil.write_code import WriteCode


class TestIndentedContextManager(unittest.TestCase):
    """`with self.indented():` -- the enabling change for the generator refactor."""

    def _writer(self):
        writer = WriteCode()
        writer.useStream(io.StringIO())
        return writer

    def test_indents_body_and_restores_level(self):
        writer = self._writer()
        writer.write(0, "a")
        with writer.indented():
            writer.write(0, "b")
        writer.write(0, "c")
        self.assertEqual(writer.output.getvalue(), "a\n    b\nc\n")
        self.assertEqual(writer.base_level, 0)

    def test_restores_level_on_exception(self):
        writer = self._writer()
        with self.assertRaises(ValueError):
            with writer.indented():
                self.assertEqual(writer.base_level, 1)
                raise ValueError("boom")
        self.assertEqual(writer.base_level, 0)

    def test_nesting(self):
        writer = self._writer()
        with writer.indented():
            with writer.indented():
                writer.write(0, "deep")
        self.assertEqual(writer.output.getvalue(), "        deep\n")
        self.assertEqual(writer.base_level, 0)

    def test_delta(self):
        writer = self._writer()
        with writer.indented(2):
            writer.write(0, "x")
        self.assertEqual(writer.output.getvalue(), "        x\n")

    def test_equivalent_to_manual_addlevel_restorelevel(self):
        """The context manager must emit exactly what the manual dance emitted."""
        manual = WriteCode()
        manual.useStream(io.StringIO())
        manual.write(0, "head")
        saved = manual.addLevel(1)
        manual.write(0, "body")
        manual.restoreLevel(saved)
        manual.write(0, "tail")

        cm = WriteCode()
        cm.useStream(io.StringIO())
        cm.write(0, "head")
        with cm.indented():
            cm.write(0, "body")
        cm.write(0, "tail")

        self.assertEqual(cm.output.getvalue(), manual.output.getvalue())


if __name__ == "__main__":
    unittest.main()
