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
    "OOM-0006\tabort\tfunc\tObjects/dictobject.c:dictiter_dealloc",
])

# a gdb backtrace whose real crash site is masked by fatal/refcount plumbing
BT = "\n".join([
    "#0  fatal_error_exit at Python/pylifecycle.c:3517",
    "#5  _Py_NegativeRefcount at Objects/object.c:275",
    "#8  0x55 in dictiter_dealloc (op=...) at Objects/dictobject.c:5532",
    "#9  _Py_Dealloc (op=...) at Objects/object.c:3319",
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


class TestHardening(unittest.TestCase):
    """Match ALL of a crash's signals (every assertion + every gdb-chain frame), incl.
    CPython's double-quote Assertion form -- so a known bug behind a secondary frame /
    later assertion isn't mislabeled oomNEW (the OOM-0017/0020 fleet false positives)."""
    def _deduper(self, resolver=None):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT + "\nOOM-0099\tabort\tline\tPython/gc_free_threading.c:1116\n")
        self.addCleanup(os.unlink, path)
        return oom_dedup.Deduper(path, resolve_segv=resolver is not None, segv_resolver=resolver)

    def test_double_quote_assertion_parsed(self):
        a = oom_dedup.all_asserts(
            'Python/gc_free_threading.c:1116: validate_gc_objects: Assertion "gc_get_refs(op) >= 0" failed: x')
        self.assertEqual(a[0][0], "Python/gc_free_threading.c")
        self.assertEqual(a[0][1], 1116)
        self.assertEqual(a[0][2], "validate_gc_objects")

    def test_secondary_assertion_matches_known(self):
        # primary (gdb-caught) assert is unknown, but an earlier listed assert is known.
        stdout = ('Python/gc_free_threading.c:1116: validate_gc_objects: Assertion "gc_get_refs(op) >= 0" failed\n'
                  'Python/ceval.h:148: check_invalid_reentrancy: Assertion `!x\' failed.\n'
                  'Fatal Python error: Aborted')
        keep, label = self._deduper().decide(stdout)
        self.assertTrue(keep)
        self.assertEqual(label, "OOM-0099")

    def test_resolved_site_frame_matches_known(self):
        # the resolved SITE (chain[0], after the plumbing skip) is what we match.
        d = self._deduper(resolver=lambda sp: ["dictiter_dealloc@Objects/dictobject.c:5532",
                                               "subtype_dealloc@Objects/typeobject.c:2876"])
        self.assertEqual(d.decide(SEGV, source_path="s"), (True, "OOM-0006"))

    def test_deeper_chain_frame_not_matched(self):
        # a NEW site frame stays oomNEW even if a deeper (generic) frame would match --
        # avoids over-matching shared deallocator plumbing.
        d = self._deduper(resolver=lambda sp: ["brand_new@Objects/zzz.c:9",
                                               "dictiter_dealloc@Objects/dictobject.c:5532"])
        self.assertEqual(d.decide(SEGV, source_path="s")[1], "oomNEW")


# A real ASan SEGV backtrace as captured in a session's stdout (stderr is merged in).
# The leading nptl/libc frames carry no CPython path; the real site is frame #5.
ASAN_SEGV = "\n".join([
    "Fatal Python error: Segmentation fault",
    "==910653==ERROR: AddressSanitizer: SEGV on unknown address 0x03e8000de53d",
    "    #0 0x75087fea648c in __pthread_kill_implementation nptl/pthread_kill.c:44:76",
    "    #3 0x75087fe45b7d in raise signal/../sysdeps/posix/raise.c:26:13",
    "    #4 0x75087fe45caf  (/usr/lib/x86_64-linux-gnu/libc.so.6+0x45caf)",
    "    #5 0x579b5f3bf58c in dictiter_dealloc "
    "/home/danzin/projects/3.16_ft_debug_asan_cpython/Objects/dictobject.c:5532:12",
    "    #6 0x579b5f3bf58c in _PyXI_excinfo_clear "
    "/home/danzin/projects/3.16_ft_debug_asan_cpython/Python/crossinterp.c:1374:5",
    "    #7 0x579b5f038dba in cfunction_vectorcall_FASTCALL_KEYWORDS "
    "/home/danzin/projects/3.16_ft_debug_asan_cpython/Objects/methodobject.c:465:24",
    "SUMMARY: AddressSanitizer: SEGV nptl/pthread_kill.c:44:76",
])


class TestNativeBacktrace(unittest.TestCase):
    """The fix: resolve a SEGV from the native backtrace ALREADY in stdout (ASan debug
    build), with no gdb re-run -- so a crash whose source.py would not reproduce under a
    fresh hash seed / thread timing is still labelled, not dumped as oomSEGV."""

    def _deduper(self, resolver=None):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        # resolve_segv stays False: prove dedup works from stdout WITHOUT gdb.
        return oom_dedup.Deduper(path, resolve_segv=resolver is not None, segv_resolver=resolver)

    def test_extract_native_skips_libc_returns_real_site(self):
        sites = oom_dedup.extract_native_sites(ASAN_SEGV)
        self.assertEqual(sites[0], "dictiter_dealloc@Objects/dictobject.c:5532")

    def test_asan_segv_matches_known_without_gdb(self):
        # OOM-0006 is keyed on dictiter_dealloc in the snapshot; no resolver provided.
        keep, label = self._deduper().decide(ASAN_SEGV, source_path=None)
        self.assertTrue(keep)
        self.assertEqual(label, "OOM-0006")

    def test_asan_segv_unknown_site_is_new_not_segv(self):
        stdout = ASAN_SEGV.replace("dictiter_dealloc", "brand_new_func").replace(
            "Objects/dictobject.c:5532", "Objects/zzz.c:9")
        keep, label = self._deduper().decide(stdout, source_path=None)
        self.assertTrue(keep)
        self.assertEqual(label, "oomNEW")

    def test_native_backtrace_preferred_over_gdb_rerun(self):
        # stdout has a usable native frame -> the (would-be-wrong) resolver is never called.
        called = []
        d = self._deduper(resolver=lambda sp: called.append(sp) or ["x@Objects/other.c:1"])
        self.assertEqual(d.decide(ASAN_SEGV, source_path="s")[1], "OOM-0006")
        self.assertEqual(called, [])

    def test_bare_segv_no_native_no_resolver_stays_segv(self):
        # non-ASan / no captured backtrace and resolution disabled -> oomSEGV (fallback kept).
        self.assertEqual(self._deduper().decide(SEGV, source_path="s"), (True, "oomSEGV"))

    def test_inlined_decref_atomic_header_frames_skipped(self):
        # A "DECREF a freed object" segv: innermost frames are the inlined atomic/Py_DECREF
        # helpers in headers -> the site must be the real .c caller (code_dealloc), not the
        # shared header line that would mask dozens of distinct bugs as one.
        bt = "\n".join([
            "==1==ERROR: AddressSanitizer: SEGV on unknown address",
            "    #4 0x0 in _Py_atomic_load_uint32_relaxed "
            "/p/./Include/cpython/pyatomic_gcc.h:367:10",
            "    #5 0x0 in Py_DECREF /p/./Include/refcount.h:345:22",
            "    #6 0x0 in code_dealloc /p/Objects/codeobject.c:2440:9",
        ])
        sites = oom_dedup.extract_native_sites(bt)
        self.assertEqual(sites[0], "code_dealloc@Objects/codeobject.c:2440")
        # and it matches the catalog bug keyed on that .c line, not labelled oomNEW.
        self.assertEqual(self._deduper().decide(bt, source_path=None), (True, "OOM-0003"))


class TestExtractSite(unittest.TestCase):
    def test_skips_plumbing_returns_real_site(self):
        self.assertEqual(oom_dedup.extract_site_from_bt(BT),
                         "dictiter_dealloc@Objects/dictobject.c:5532")

    def test_no_cpython_frame_returns_none(self):
        self.assertIsNone(oom_dedup.extract_site_from_bt(
            "#0 __pthread_kill at nptl/pthread_kill.c:44\n#1 raise at sysdeps/raise.c:26"))


class TestSegvResolution(unittest.TestCase):
    def _deduper(self, resolver, keep=5, prune=False):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        return oom_dedup.Deduper(path, keep=keep, prune=prune,
                                 resolve_segv=True, segv_resolver=resolver)

    def test_resolved_segv_matches_known(self):
        d = self._deduper(lambda sp: "dictiter_dealloc@Objects/dictobject.c:5532")
        self.assertEqual(d.decide(SEGV, source_path="s"), (True, "OOM-0006"))

    def test_resolved_segv_unknown_is_new(self):
        d = self._deduper(lambda sp: "brand_new@Objects/xyz.c:1")
        keep, label = d.decide(SEGV, source_path="s")
        self.assertTrue(keep)
        self.assertEqual(label, "oomNEW")
        self.assertTrue(any(k.startswith("NEW:") for k in d.seen))

    def test_unresolvable_segv_kept_as_segv(self):
        d = self._deduper(lambda sp: None)
        self.assertEqual(d.decide(SEGV, source_path="s"), (True, "oomSEGV"))

    def test_resolved_known_segv_prunes_over_cap(self):
        d = self._deduper(lambda sp: "dictiter_dealloc@Objects/dictobject.c:5532",
                          keep=1, prune=True)
        self.assertTrue(d.decide(SEGV, source_path="s")[0])
        self.assertFalse(d.decide(SEGV, source_path="s")[0])

    def test_resolve_disabled_never_calls_resolver(self):
        called = []
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        d = oom_dedup.Deduper(path, resolve_segv=False,
                              segv_resolver=lambda sp: called.append(sp))
        self.assertEqual(d.decide(SEGV, source_path="s"), (True, "oomSEGV"))
        self.assertEqual(called, [])


class TestGdbResolveDropsPrivileges(unittest.TestCase):
    """gdb_crash_site re-runs the *fuzzed* source.py, so it must never do so with more
    privilege than the fuzzing children had: drop to the configured user when root, and
    confine cwd to the session dir (not the root-owned run-dir root)."""

    SRC = "/run/inst-01/python-2/session-9/source.py"
    SESSION_DIR = "/run/inst-01/python-2/session-9"

    def _capture(self, *, uid, drop_uid=None, drop_gid=None):
        """Stub subprocess.run + os.getuid; return the kwargs gdb_crash_site passed to run."""
        captured = {}

        class _Result:
            stdout = ""  # no frames -> extract_sites_from_bt returns []

        def fake_run(cmd, **kwargs):
            captured["kwargs"] = kwargs
            return _Result()

        orig_run, orig_getuid = oom_dedup.subprocess.run, oom_dedup.os.getuid
        oom_dedup.subprocess.run = fake_run
        oom_dedup.os.getuid = lambda: uid
        try:
            oom_dedup.gdb_crash_site("/bin/python", self.SRC,
                                     drop_uid=drop_uid, drop_gid=drop_gid)
        finally:
            oom_dedup.subprocess.run = orig_run
            oom_dedup.os.getuid = orig_getuid
        return captured["kwargs"]

    def test_drops_to_user_and_confines_cwd_when_root(self):
        kw = self._capture(uid=0, drop_uid=1001, drop_gid=1001)
        self.assertEqual(kw["user"], 1001)
        self.assertEqual(kw["group"], 1001)
        self.assertEqual(kw["extra_groups"], [1001])  # root's supplementary groups dropped
        self.assertEqual(kw["cwd"], self.SESSION_DIR)

    def test_no_drop_when_already_unprivileged(self):
        # A non-root caller is already unprivileged (and setgroups() would fail for it).
        kw = self._capture(uid=1001, drop_uid=1001, drop_gid=1001)
        self.assertNotIn("user", kw)
        self.assertNotIn("group", kw)
        self.assertNotIn("extra_groups", kw)
        self.assertEqual(kw["cwd"], self.SESSION_DIR)  # cwd confinement still applies

    def test_no_drop_target_runs_as_is_even_as_root(self):
        # --unsafe (no process user) configures no drop target: behaviour unchanged.
        kw = self._capture(uid=0)
        self.assertNotIn("user", kw)
        self.assertNotIn("group", kw)
        self.assertEqual(kw["cwd"], self.SESSION_DIR)


if __name__ == "__main__":
    unittest.main()
