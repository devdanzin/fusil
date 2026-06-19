"""Unit tests for the in-loop OOM crash deduper (fusil.python.oom_dedup).

Pure-Python: exercises classification, snapshot matching, and the keep/prune decision
without the python-ptrace runtime stack, so it runs in the dev venv.
"""
import os
import tempfile
import unittest

from fusil.python import oom_dedup

SNAPSHOT = "\n".join([
    "# oom_id\tkind\tkeytype\tkey",
    "OOM-0003\tabort\tfunc\tObjects/codeobject.c:code_dealloc",
    "OOM-0003\tabort\tline\tObjects/codeobject.c:2440",
    "OOM-0027\tabort\tassert\tPython/generated_cases.c.h:PyStackRef_BoolCheck(cond)",
    "OOM-0027\tabort\tfunc\tPython/generated_cases.c.h:_PyEval_EvalFrameDefault",
    "OOM-0022\tfatal\tmsg\t_Py_CheckSlotResult: Slot __delitem__ of type dict succeeded",
    "OOM-0004\tabort\tline\tObjects/object.c:909",
])

ABORT_0003 = "python: Objects/codeobject.c:2440: void code_dealloc(PyObject *): Assertion `co != NULL' failed."
ABORT_0027 = ("python: Python/generated_cases.c.h:11120: PyObject *_PyEval_EvalFrameDefault"
              "(PyThreadState *, _PyInterpreterFrame *, int): Assertion `PyStackRef_BoolCheck(cond)' failed.")
ABORT_NEAR = "python: Objects/object.c:915: void clear_freelist(void): Assertion `x' failed."  # within 12 of 909
FATAL_0022 = "Fatal Python error: _Py_CheckSlotResult: Slot __delitem__ of type dict succeeded with an exception"
GENERIC_FATAL = "Fatal Python error: _PyObject_AssertFailed: _PyObject_AssertFailed"
SEGV = "Fatal Python error: Segmentation fault\nCurrent thread's C stack trace ..."
ABORT_NEW = "python: Objects/brandnew.c:5: void totally_new(void): Assertion `nope' failed."


class TestClassify(unittest.TestCase):
    def test_abort_extracts_file_line_func_expr(self):
        c = oom_dedup.classify(ABORT_0003)
        self.assertEqual(c["kind"], "abort")
        self.assertEqual(c["file"], "Objects/codeobject.c")
        self.assertEqual(c["line"], 2440)
        self.assertEqual(c["func"], "code_dealloc")
        self.assertEqual(c["assert_expr"], "co != NULL")

    def test_specific_fatal(self):
        c = oom_dedup.classify(FATAL_0022)
        self.assertEqual(c["kind"], "fatal")
        self.assertTrue(c["fatal_msg"].startswith("_Py_CheckSlotResult"))

    def test_generic_assert_fatal_routes_to_segv(self):
        # carries no real site -> must not be trusted as a known fatal
        self.assertEqual(oom_dedup.classify(GENERIC_FATAL)["kind"], "segv")

    def test_segv_and_import_and_clean(self):
        self.assertEqual(oom_dedup.classify(SEGV)["kind"], "segv")
        self.assertEqual(oom_dedup.classify("ModuleNotFoundError: no mod")["kind"], "import")
        self.assertEqual(oom_dedup.classify("hello world, no crash")["kind"], "clean")


class TestMatch(unittest.TestCase):
    def setUp(self):
        self.snap = oom_dedup.load_snapshot(SNAPSHOT.splitlines())

    def _match(self, text):
        return oom_dedup.match(oom_dedup.classify(text), self.snap)

    def test_match_by_func(self):
        ids, how = self._match(ABORT_0003)
        self.assertEqual(ids, {"OOM-0003"})

    def test_assert_beats_func(self):
        ids, how = self._match(ABORT_0027)
        self.assertEqual(ids, {"OOM-0027"})
        self.assertEqual(how, "assert")

    def test_match_by_msg(self):
        ids, _ = self._match(FATAL_0022)
        self.assertEqual(ids, {"OOM-0022"})

    def test_near_line(self):
        ids, how = self._match(ABORT_NEAR)
        self.assertEqual(ids, {"OOM-0004"})
        self.assertEqual(how, "near")

    def test_unknown_is_new(self):
        ids, how = self._match(ABORT_NEW)
        self.assertEqual(ids, set())
        self.assertEqual(how, "NEW")


class TestDeduper(unittest.TestCase):
    def _deduper(self, keep=5, prune=False):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        return oom_dedup.Deduper(path, keep=keep, prune=prune)

    def test_known_kept_and_labeled(self):
        d = self._deduper()
        keep, label = d.decide(ABORT_0003)
        self.assertTrue(keep)
        self.assertEqual(label, "OOM-0003")

    def test_prune_over_cap(self):
        d = self._deduper(keep=2, prune=True)
        self.assertEqual([d.decide(ABORT_0003)[0] for _ in range(4)], [True, True, False, False])
        self.assertEqual(d.kept["OOM-0003"], 2)
        self.assertEqual(d.seen["OOM-0003"], 4)

    def test_new_never_pruned(self):
        d = self._deduper(keep=1, prune=True)
        for _ in range(3):
            keep, label = d.decide(ABORT_NEW)
            self.assertTrue(keep)
            self.assertEqual(label, "oomNEW")

    def test_segv_never_pruned(self):
        d = self._deduper(keep=1, prune=True)
        for _ in range(3):
            keep, label = d.decide(SEGV)
            self.assertTrue(keep)
            self.assertEqual(label, "oomSEGV")

    def test_prune_disabled_keeps_all(self):
        d = self._deduper(keep=1, prune=False)
        self.assertTrue(all(d.decide(ABORT_0003)[0] for _ in range(5)))


if __name__ == "__main__":
    unittest.main()
