"""Tests for the handle_abort crash-diagnostics path.

`augment_asan_options` ensures the target prints a symbolized ASan backtrace on abort
(handle_abort) while still exiting via SIGABRT (abort_on_error), so the in-loop OOM dedup can
resolve an abort's crash site straight from stdout -- no gdb re-run. Pure-Python.
"""
import os
import tempfile
import unittest

from fusil.process.env import augment_asan_options
from fusil.python import oom_dedup


class TestAugmentAsanOptions(unittest.TestCase):
    def _keys(self, s):
        return {p.split("=", 1)[0] for p in s.split(":") if p}

    def test_empty_gets_both_defaults(self):
        self.assertEqual(augment_asan_options(None), "handle_abort=1:abort_on_error=1")
        self.assertEqual(augment_asan_options(""), "handle_abort=1:abort_on_error=1")

    def test_existing_options_preserved_and_extended(self):
        out = augment_asan_options("detect_leaks=0")
        self.assertTrue(out.startswith("detect_leaks=0:"))
        self.assertEqual(self._keys(out), {"detect_leaks", "handle_abort", "abort_on_error"})

    def test_explicit_keys_not_overridden(self):
        # A caller who set handle_abort=0 on purpose keeps it; only the missing key is added.
        out = augment_asan_options("handle_abort=0")
        self.assertIn("handle_abort=0", out)
        self.assertNotIn("handle_abort=1", out)
        self.assertIn("abort_on_error=1", out)

    def test_idempotent(self):
        once = augment_asan_options("detect_leaks=0")
        self.assertEqual(augment_asan_options(once), once)


# A negrefcount abort the way the target prints it with handle_abort=1: the faulthandler
# fatal + object dump, then ASan's symbolized C backtrace (stderr merged into stdout). The
# innermost real frame after the _PyObject_AssertFailed/_Py_NegativeRefcount detector plumbing
# is the dealloc cascade -- here tuple_dealloc, the discriminating site.
ABORT_STDOUT = """\
./Include/refcount.h:520: _Py_NegativeRefcount: Assertion failed: object has negative ref count
Fatal Python error: _PyObject_AssertFailed: _PyObject_AssertFailed
object type name: MemoryError
AddressSanitizer:DEADLYSIGNAL
==123==ERROR: AddressSanitizer: ABRT on unknown address 0x000000000000
    #8 0x55 in _PyObject_AssertFailed /src/Objects/object.c:3278:5
    #9 0x55 in _Py_NegativeRefcount /src/Objects/object.c:275:5
    #12 0x55 in tuple_dealloc /src/Objects/tupleobject.c:277:9
    #13 0x55 in subtype_dealloc /src/Objects/typeobject.c:2876:5
    #14 0x55 in _Py_Dealloc /src/Objects/object.c:3319:5
    #17 0x55 in list_dealloc /src/Objects/listobject.c:567:13
"""

SNAPSHOT = "\n".join([
    "# oom_id\tkind\tkeytype\tkey",
    "OOM-9001\tabort\tfunc\tObjects/tupleobject.c:tuple_dealloc",
    "OOM-9001\tabort\tline\tObjects/tupleobject.c:277",
])


class TestDeduperResolvesAbortFromStdout(unittest.TestCase):
    def test_extract_native_sites_skips_detector_plumbing(self):
        sites = oom_dedup.extract_native_sites(ABORT_STDOUT)
        # _PyObject_AssertFailed and _Py_NegativeRefcount are detector plumbing -> skipped,
        # so the innermost reported frame is the real dealloc-cascade site.
        self.assertEqual(sites[0], "tuple_dealloc@Objects/tupleobject.c:277")

    def test_decide_resolves_abort_without_gdb(self):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        os.write(fd, SNAPSHOT.encode())
        os.close(fd)
        try:
            # resolve_segv=False and no resolver: the only way this resolves is the native
            # backtrace in stdout -- exactly what handle_abort=1 provides for aborts.
            d = oom_dedup.Deduper(path, resolve_segv=False)
            keep, label = d.decide(ABORT_STDOUT, source_path=None)
            self.assertTrue(keep)
            self.assertEqual(label, "OOM-9001")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
