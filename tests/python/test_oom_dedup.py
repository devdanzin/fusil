"""Unit tests for the in-loop OOM crash deduper (fusil.python.oom_dedup).

Pure-Python: exercises classification, snapshot matching, and the keep/prune decision
without the python-ptrace runtime stack, so it runs in the dev venv.
"""

import os
import tempfile
import unittest

from fusil.python import oom_dedup

SNAPSHOT = "\n".join(
    [
        "# oom_id\tkind\tkeytype\tkey",
        "OOM-0003\tabort\tfunc\tObjects/codeobject.c:code_dealloc",
        "OOM-0003\tabort\tline\tObjects/codeobject.c:2440",
        "OOM-0027\tabort\tassert\tPython/generated_cases.c.h:PyStackRef_BoolCheck(cond)",
        "OOM-0027\tabort\tfunc\tPython/generated_cases.c.h:_PyEval_EvalFrameDefault",
        "OOM-0022\tfatal\tmsg\t_Py_CheckSlotResult: Slot __delitem__ of type dict succeeded",
        "OOM-0004\tabort\tline\tObjects/object.c:909",
        "OOM-0006\tabort\tfunc\tObjects/dictobject.c:dictiter_dealloc",
    ]
)

# a gdb backtrace whose real crash site is masked by fatal/refcount plumbing
BT = "\n".join(
    [
        "#0  fatal_error_exit at Python/pylifecycle.c:3517",
        "#5  _Py_NegativeRefcount at Objects/object.c:275",
        "#8  0x55 in dictiter_dealloc (op=...) at Objects/dictobject.c:5532",
        "#9  _Py_Dealloc (op=...) at Objects/object.c:3319",
    ]
)

ABORT_0003 = "python: Objects/codeobject.c:2440: void code_dealloc(PyObject *): Assertion `co != NULL' failed."
ABORT_0027 = (
    "python: Python/generated_cases.c.h:11120: PyObject *_PyEval_EvalFrameDefault"
    "(PyThreadState *, _PyInterpreterFrame *, int): Assertion `PyStackRef_BoolCheck(cond)' failed."
)
ABORT_NEAR = "python: Objects/object.c:915: void clear_freelist(void): Assertion `x' failed."  # within 12 of 909
FATAL_0022 = "Fatal Python error: _Py_CheckSlotResult: Slot __delitem__ of type dict succeeded with an exception"
GENERIC_FATAL = "Fatal Python error: _PyObject_AssertFailed: _PyObject_AssertFailed"
SEGV = "Fatal Python error: Segmentation fault\nCurrent thread's C stack trace ..."
ABORT_NEW = "python: Objects/brandnew.c:5: void totally_new(void): Assertion `nope' failed."
# The generic over-decref/UAF DETECTOR assert: Py_DECREF_MORTAL's !_Py_IsStaticImmortal(op)
# fires on a freed object whose refcount word reads back as static-immortal. Carries no real
# site (like _Py_NegativeRefcount) -> must NOT become a discriminating oomNEW key. The
# faulthandler C stack's innermost real frames are themselves generic teardown detectors.
ABORT_IMMORTAL = "\n".join(
    [
        "python: ./Include/internal/pycore_object.h:414: void Py_DECREF_MORTAL"
        "(const char *, int, PyObject *): Assertion `!_Py_IsStaticImmortal(op)' failed.",
        "Fatal Python error: Aborted",
        "Current thread's C stack trace (most recent call first):",
        '  Binary file "/build/python", at _Py_DumpStack+0x32 [0x1]',
        '  Binary file "/lib/libc.so.6", at abort+0x27 [0x2]',
        '  Binary file "/build/python", at _PyFrame_ClearLocals+0x142 [0x3]',
        '  Binary file "/build/python", at _PyFrame_ClearExceptCode+0x50e [0x4]',
        '  Binary file "/build/python", at _PyEval_EvalFrameDefault+0x39124 [0x5]',
    ]
)
# The dict-freelist corruption DETECTOR assert: new_dict's `mp == NULL || Py_IS_TYPE(mp,
# &PyDict_Type)` fires when a block popped from the dicts freelist isn't a dict (rr-confirmed
# an OOM-0036 face -- a list.append double-free victim dict decrements its freelist next-pointer).
# Generic -> must NOT become a discriminating oomNEW key.
ABORT_DICT_FREELIST = "\n".join(
    [
        "python: Objects/dictobject.c:961: PyObject *new_dict(PyDictKeysObject *, PyDictValues *, "
        "Py_ssize_t, int): Assertion `mp == NULL || Py_IS_TYPE(mp, &PyDict_Type)' failed.",
        "Fatal Python error: Aborted",
        "Current thread's C stack trace (most recent call first):",
        '  Binary file "/build/python", at _Py_DumpStack+0x32 [0x1]',
        '  Binary file "/lib/libc.so.6", at abort+0x27 [0x2]',
        '  Binary file "/build/python", at _PyEvalFramePushAndInit+0x200 [0x3]',
        '  Binary file "/build/python", at _PyEval_EvalFrameDefault+0xc4ac [0x4]',
    ]
)
# The tuple-freelist analog: tuple_alloc's `PyTuple_Check(op)` fires when a block popped from the
# tuple freelist isn't a tuple -- the debug-abort form of the documented OOM-0036 "tuple_alloc
# freelist SEGV" face. Generic -> must NOT become a discriminating oomNEW key.
ABORT_TUPLE_FREELIST = "\n".join(
    [
        "python: Objects/tupleobject.c:48: PyTupleObject *tuple_alloc(Py_ssize_t): "
        "Assertion `PyTuple_Check(op)' failed.",
        "Fatal Python error: Aborted",
        "Current thread's C stack trace (most recent call first):",
        '  Binary file "/build/python", at _Py_DumpStack+0x32 [0x1]',
        '  Binary file "/lib/libc.so.6", at abort+0x27 [0x2]',
        '  Binary file "/build/python", at _PyTuple_FromStackRefStealOnSuccess+0x29 [0x3]',
        '  Binary file "/build/python", at _PyEval_EvalFrameDefault+0x8513 [0x4]',
    ]
)
# The GC-list-invariant DETECTOR assert: validate_list's `(gc->_gc_next & NEXT_MASK_UNREACHABLE)
# == next_value` fires at collection/shutdown when a PyGC_Head is corrupted -- another OOM-0036
# face (the freed double-free victim's slot is reused by a GC-tracked object whose _gc_next the
# stale-stackref second decref decrements). Generic -> must NOT become a discriminating oomNEW key.
ABORT_VALIDATE_LIST = "\n".join(
    [
        "python: Python/gc.c:380: void validate_list(PyGC_Head *, enum flagstates): "
        "Assertion `(gc->_gc_next & NEXT_MASK_UNREACHABLE) == next_value' failed.",
        "Fatal Python error: Aborted",
        "Current thread's C stack trace (most recent call first):",
        '  Binary file "/build/python", at _Py_DumpStack+0x32 [0x1]',
        '  Binary file "/lib/libc.so.6", at abort+0x27 [0x2]',
        '  Binary file "/build/python", at gc_collect_main+0x9ab [0x3]',
        '  Binary file "/build/python", at _PyGC_Collect+0x41 [0x4]',
    ]
)
# The negative-refcount DETECTOR assert (`_Py_NegativeRefcount: ... object has negative ref count`)
# has TWO shapes. DEFERRED: the over-decref'd object is detected during unrelated frame/exception
# teardown (the OOM-0036 stackref family), so the ASan backtrace is the dealloc-detection cascade and
# every real frame under the refcount plumbing (PyStackRef_XCLOSE, frame_dealloc, tb_dealloc, ...) is a
# bystander -- the producer already returned. Must fold to needs-resolution (oomSEGV), never a distinct
# oomNEW keyed on the useless negref assert expr or a bystander dealloc frame.
ABORT_NEGREF_DEFERRED = "\n".join(
    [
        "./Include/internal/pycore_stackref.h:726: _Py_NegativeRefcount: "
        "Assertion failed: object has negative ref count",
        "Fatal Python error: _PyObject_AssertFailed: _PyObject_AssertFailed",
        "    #8 0x5b61fdfbb838 in _PyObject_AssertFailed Objects/object.c:3278",
        "    #9 0x5b61fdfbbb22 in _Py_NegativeRefcount Objects/object.c:275",
        "    #10 0x5b61fdf34272 in Py_DECREF Include/refcount.h:354",
        "    #11 0x5b61fdf34b93 in PyStackRef_XCLOSE Include/internal/pycore_stackref.h:726",
        "    #12 0x5b61fdf3ad42 in frame_dealloc Objects/frameobject.c:1949",
        "    #13 0x5b61fdfba573 in _Py_Dealloc Objects/object.c:3319",
        "    #14 0x5b61fe33a297 in tb_dealloc Python/traceback.c:246",
    ]
)
# INLINE: the producer over-decref's in place and the very next decref trips the negref assert, so the
# producer frame sits right under the refcount plumbing (this is OOM-0019 = a double `Py_XDECREF` inside
# `_PyPegen_raise_error_known_location`). decide() must still resolve past the detectors and FOLD it to
# the known bug -- NOT swallow it as an unresolved oomSEGV. Here the inline producer is `code_dealloc`
# (an OOM-0003 catalog site) to reuse the base snapshot.
ABORT_NEGREF_INLINE = "\n".join(
    [
        "./Include/refcount.h:520: _Py_NegativeRefcount: "
        "Assertion failed: object has negative ref count",
        "Fatal Python error: _PyObject_AssertFailed: _PyObject_AssertFailed",
        "    #8 0x5b61fdfbb838 in _PyObject_AssertFailed Objects/object.c:3278",
        "    #9 0x5b61fdfbbb22 in _Py_NegativeRefcount Objects/object.c:275",
        "    #10 0x5b61fdf34272 in Py_DECREF Include/refcount.h:354",
        "    #11 0x5b61fdf34b93 in Py_XDECREF Include/refcount.h:520",
        "    #12 0x5b61fdf3ad42 in code_dealloc Objects/codeobject.c:2440",
        "    #13 0x5b61fdfba573 in _PyEval_EvalFrameDefault Python/ceval.c:1000",
    ]
)


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

    def test_generic_detector_assert_routes_to_segv(self):
        # Py_DECREF_MORTAL/!_Py_IsStaticImmortal is a generic UAF detector -> no real site,
        # classify past it like a generic fatal (kind=segv), never a trusted abort site.
        c = oom_dedup.classify(ABORT_IMMORTAL)
        self.assertEqual(c["kind"], "segv")
        self.assertIsNone(c["assert_expr"])
        # but a REAL assert alongside the detector still wins (its site is the discriminator).
        real = ABORT_IMMORTAL + "\n" + ABORT_0003
        self.assertEqual(oom_dedup.classify(real)["kind"], "abort")
        self.assertEqual(oom_dedup.classify(real)["func"], "code_dealloc")

    def test_dict_freelist_detector_assert_routes_to_segv(self):
        # new_dict's `mp == NULL || Py_IS_TYPE(mp, &PyDict_Type)` is a generic dict-freelist
        # corruption detector (an OOM-0036 face) -> no real site, classify past it (kind=segv).
        c = oom_dedup.classify(ABORT_DICT_FREELIST)
        self.assertEqual(c["kind"], "segv")
        self.assertIsNone(c["assert_expr"])

    def test_tuple_freelist_detector_assert_routes_to_segv(self):
        # tuple_alloc's `PyTuple_Check(op)` is the tuple-freelist analog (an OOM-0036 face) ->
        # no real site, classify past it (kind=segv).
        c = oom_dedup.classify(ABORT_TUPLE_FREELIST)
        self.assertEqual(c["kind"], "segv")
        self.assertIsNone(c["assert_expr"])

    def test_validate_list_detector_assert_routes_to_segv(self):
        # validate_list@gc.c:380 is a generic GC_Head-corruption detector (an OOM-0036 face) ->
        # no real site, classify past it (kind=segv).
        c = oom_dedup.classify(ABORT_VALIDATE_LIST)
        self.assertEqual(c["kind"], "segv")
        self.assertIsNone(c["assert_expr"])

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

    def test_msg_match_distinguishes_by_type(self):
        # Two type-specific "Deallocator of type 'X'" msg keys must not be conflated by their
        # shared prefix: each known type maps to its own bug, and a NEW type matches neither
        # (a too-short prefix slice used to ignore the type and collide the whole family).
        snap = oom_dedup.load_snapshot(
            [
                "OOM-0007\tfatal\tmsg\t"
                "_Py_Dealloc: Deallocator of type 'Context' cleared the curre",
                "OOM-0023\tfatal\tmsg\t"
                "_Py_Dealloc: Deallocator of type '_StoreAction' cleared the ",
            ]
        )

        def decide_type(t):
            text = (
                "Fatal Python error: _Py_Dealloc: Deallocator of type '%s' "
                "cleared the current exception" % t
            )
            return oom_dedup.match(oom_dedup.classify(text), snap)[0]

        self.assertEqual(decide_type("Context"), {"OOM-0007"})
        self.assertEqual(decide_type("_StoreAction"), {"OOM-0023"})
        self.assertEqual(decide_type("collections.deque"), set())  # new type -> no match

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


class TestGenericDetectorAssert(unittest.TestCase):
    """Py_DECREF_MORTAL/!_Py_IsStaticImmortal is the assert() face of the over-decref/UAF
    family (like _Py_NegativeRefcount): a generic detector, never a real site. It must fold
    to needs-resolution (oomSEGV), NOT flood ./fleet finds as a discriminating oomNEW."""

    def _deduper(self, resolver=None, keep=5, prune=False):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        return oom_dedup.Deduper(
            path, keep=keep, prune=prune, resolve_segv=resolver is not None, segv_resolver=resolver
        )

    def test_unresolved_immortal_assert_is_segv_not_new(self):
        # No ASan frames, no resolver, and the faulthandler C stack's real frames are
        # themselves teardown detectors -> can't resolve a producer -> needs-resolution.
        keep, label = self._deduper().decide(ABORT_IMMORTAL, source_path=None)
        self.assertTrue(keep)
        self.assertEqual(label, "oomSEGV")

    def test_immortal_assert_never_pruned(self):
        # never a discriminating new/known site -> always kept even with prune on.
        d = self._deduper(keep=1, prune=True)
        for _ in range(3):
            self.assertEqual(d.decide(ABORT_IMMORTAL)[0], True)

    def test_immortal_assert_does_not_trigger_gdb_resolution(self):
        # A pure detector assert must NOT run the (slow, per-crash) gdb re-run: its producer
        # already returned, so resolution only yields frame-teardown / bystander frames. Even
        # with resolve_segv on and a resolver that WOULD match a bug, the resolver is never
        # called and it stays oomSEGV -- the producer is pinned offline via rr, not in-loop.
        called = []
        d = self._deduper(
            resolver=lambda sp: called.append(sp) or ["dictiter_dealloc@Objects/dictobject.c:5532"]
        )
        self.assertEqual(d.decide(ABORT_IMMORTAL, source_path="s"), (True, "oomSEGV"))
        self.assertEqual(called, [])

    def test_immortal_assert_never_keys_pycore_object_site(self):
        # regression: the raw assert site must never appear as an oomNEW key.
        d = self._deduper()
        d.decide(ABORT_IMMORTAL, source_path=None)
        self.assertFalse(any("_Py_IsStaticImmortal" in k for k in d.seen))
        self.assertFalse(any("pycore_object.h" in k for k in d.seen))

    def test_dict_freelist_assert_is_segv_not_new(self):
        # new_dict's dict-freelist corruption assert (an OOM-0036 face) is a generic detector ->
        # needs-resolution, never a distinct oomNEW keyed on dictobject.c:961 / new_dict.
        d = self._deduper()
        keep, label = d.decide(ABORT_DICT_FREELIST, source_path=None)
        self.assertEqual((keep, label), (True, "oomSEGV"))
        self.assertFalse(any("PyDict_Type" in k or "new_dict" in k for k in d.seen))

    def test_tuple_freelist_assert_is_segv_not_new(self):
        # tuple_alloc's tuple-freelist corruption assert (an OOM-0036 face) -> needs-resolution,
        # never a distinct oomNEW keyed on tupleobject.c:48 / tuple_alloc.
        d = self._deduper()
        keep, label = d.decide(ABORT_TUPLE_FREELIST, source_path=None)
        self.assertEqual((keep, label), (True, "oomSEGV"))
        self.assertFalse(any("PyTuple_Check" in k or "tuple_alloc" in k for k in d.seen))

    def test_validate_list_assert_is_segv_not_new(self):
        # validate_list@gc.c:380's GC_Head-corruption assert (an OOM-0036 face) -> needs-resolution,
        # never a distinct oomNEW keyed on gc.c:380 / validate_list.
        d = self._deduper()
        keep, label = d.decide(ABORT_VALIDATE_LIST, source_path=None)
        self.assertEqual((keep, label), (True, "oomSEGV"))
        self.assertFalse(any("validate_list" in k or "gc.c:380" in k for k in d.seen))


class TestNegrefDetectorAssert(unittest.TestCase):
    """`_Py_NegativeRefcount`'s `object has negative ref count` assert is the negref DETECTOR face
    of the over-decref family. Its DEFERRED shape (producer already returned; the OOM-0036 stackref
    family) must fold to needs-resolution (oomSEGV), while its INLINE shape (OOM-0019: producer right
    under the refcount plumbing) must STILL resolve past the detectors and fold to the known bug."""

    def _deduper(self, keep=5, prune=False):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        return oom_dedup.Deduper(path, keep=keep, prune=prune)

    def test_deferred_negref_is_segv_not_new(self):
        # A full ASan dealloc-detection cascade whose only real frames under the refcount plumbing are
        # bystanders (frame_dealloc/tb_dealloc) -> the producer returned -> oomSEGV, never oomNEW.
        d = self._deduper()
        keep, label = d.decide(ABORT_NEGREF_DEFERRED, source_path=None)
        self.assertEqual((keep, label), (True, "oomSEGV"))
        # never keyed on the useless negref assert expr nor a bystander teardown frame.
        self.assertFalse(any("negative ref count" in k for k in d.seen))
        self.assertFalse(any("frame_dealloc" in k or "pycore_stackref" in k for k in d.seen))

    def test_deferred_negref_never_pruned(self):
        d = self._deduper(keep=1, prune=True)
        for _ in range(3):
            self.assertEqual(d.decide(ABORT_NEGREF_DEFERRED)[0], True)

    def test_inline_negref_folds_to_known_producer(self):
        # regression guard for OOM-0019: the negref assert is generic, but its chain resolves to the
        # inline producer (code_dealloc = an OOM-0003 site) -> must fold there, NOT be swallowed as
        # an unresolved oomSEGV.
        d = self._deduper()
        keep, label = d.decide(ABORT_NEGREF_INLINE, source_path=None)
        self.assertEqual((keep, label), (True, "OOM-0003"))


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
            'Python/gc_free_threading.c:1116: validate_gc_objects: Assertion "gc_get_refs(op) >= 0" failed: x'
        )
        self.assertEqual(a[0][0], "Python/gc_free_threading.c")
        self.assertEqual(a[0][1], 1116)
        self.assertEqual(a[0][2], "validate_gc_objects")

    def test_secondary_assertion_matches_known(self):
        # primary (gdb-caught) assert is unknown, but an earlier listed assert is known.
        stdout = (
            'Python/gc_free_threading.c:1116: validate_gc_objects: Assertion "gc_get_refs(op) >= 0" failed\n'
            "Python/ceval.h:148: check_invalid_reentrancy: Assertion `!x' failed.\n"
            "Fatal Python error: Aborted"
        )
        keep, label = self._deduper().decide(stdout)
        self.assertTrue(keep)
        self.assertEqual(label, "OOM-0099")

    def test_resolved_site_frame_matches_known(self):
        # the resolved SITE (chain[0], after the plumbing skip) is what we match.
        d = self._deduper(
            resolver=lambda sp: [
                "dictiter_dealloc@Objects/dictobject.c:5532",
                "subtype_dealloc@Objects/typeobject.c:2876",
            ]
        )
        self.assertEqual(d.decide(SEGV, source_path="s"), (True, "OOM-0006"))

    def test_deeper_chain_frame_not_matched(self):
        # a NEW site frame stays oomNEW even if a deeper (generic) frame would match --
        # avoids over-matching shared deallocator plumbing.
        d = self._deduper(
            resolver=lambda sp: [
                "brand_new@Objects/zzz.c:9",
                "dictiter_dealloc@Objects/dictobject.c:5532",
            ]
        )
        self.assertEqual(d.decide(SEGV, source_path="s")[1], "oomNEW")

    def test_tuple_freelist_segv_site_is_segv_not_new(self):
        # The gdb-resolved chain bottoms out at the tuple-freelist detector (tuple_alloc's
        # freelist-POP hash-cache reset) -- an OOM-0036 SEGV face with no in-stack producer
        # (fusil-fleet10, gdb-pinned). Must be oomSEGV (needs rr), NEVER a discriminating oomNEW
        # keyed on tuple_alloc; the eval-plumbing frames under it must not match either.
        d = self._deduper(
            resolver=lambda sp: [
                "tuple_alloc@Objects/tupleobject.c:48",
                "_PyTuple_FromStackRefStealOnSuccess@Objects/tupleobject.c:467",
                "_PyEval_EvalFrameDefault@Python/generated_cases.c.h:1792",
            ]
        )
        keep, label = d.decide(SEGV, source_path="s")
        self.assertEqual((keep, label), (True, "oomSEGV"))
        self.assertFalse(any("tuple_alloc" in k for k in d.seen))

    def test_stackref_steal_builder_segv_site_is_segv_not_new(self):
        # Same when the steal builder itself is the innermost resolved frame.
        d = self._deduper(
            resolver=lambda sp: ["_PyTuple_FromStackRefStealOnSuccess@Objects/tupleobject.c:467"]
        )
        self.assertEqual(d.decide(SEGV, source_path="s")[1], "oomSEGV")


# A real ASan SEGV backtrace as captured in a session's stdout (stderr is merged in).
# The leading nptl/libc frames carry no CPython path; the real site is frame #5.
ASAN_SEGV = "\n".join(
    [
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
    ]
)


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
            "Objects/dictobject.c:5532", "Objects/zzz.c:9"
        )
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
        bt = "\n".join(
            [
                "==1==ERROR: AddressSanitizer: SEGV on unknown address",
                "    #4 0x0 in _Py_atomic_load_uint32_relaxed "
                "/p/./Include/cpython/pyatomic_gcc.h:367:10",
                "    #5 0x0 in Py_DECREF /p/./Include/refcount.h:345:22",
                "    #6 0x0 in code_dealloc /p/Objects/codeobject.c:2440:9",
            ]
        )
        sites = oom_dedup.extract_native_sites(bt)
        self.assertEqual(sites[0], "code_dealloc@Objects/codeobject.c:2440")
        # and it matches the catalog bug keyed on that .c line, not labelled oomNEW.
        self.assertEqual(self._deduper().decide(bt, source_path=None), (True, "OOM-0003"))

    def test_gcc_relative_path_frames_parsed(self):
        # GCC-built ASan traces use a RELATIVE source path and no column (Objects/foo.c:68),
        # vs Clang's absolute path + column (/abs/Objects/foo.c:68:9). Both must parse, else
        # GCC crashes fall back to faulthandler's inlined C-stack and known bugs (here the
        # OOM-0003 site) get mislabelled oomNEW.
        bt = "\n".join(
            [
                "==1==ERROR: AddressSanitizer: SEGV on unknown address",
                "    #5 0x5e in Py_DECREF Include/refcount.h:359",
                "    #6 0x5e in code_dealloc Objects/codeobject.c:2440",
            ]
        )
        sites = oom_dedup.extract_native_sites(bt)
        self.assertEqual(sites[0], "code_dealloc@Objects/codeobject.c:2440")
        self.assertEqual(self._deduper().decide(bt, source_path=None), (True, "OOM-0003"))

    def test_overdecref_detector_frames_skipped(self):
        # The eval-loop operand-stack teardown (PyStackRef_XCLOSE / _PyFrame_ClearLocals /
        # clear_thread_frame) and the generic _Py_Dealloc dispatch CATCH an already-corrupted
        # object; they must never be the resolved site (kept in lockstep with the catalog's
        # GENERIC_DETECTOR_FUNCS).
        # (a) When they are the only CPython frames, no spurious site is extracted -- the crash
        # surfaces for rr-triage instead of being mislabelled to whatever bug shares the frame.
        detectors_only = "\n".join(
            [
                "==1==ERROR: AddressSanitizer: SEGV on unknown address",
                "    #3 0x0 in PyStackRef_XCLOSE /p/./Include/internal/pycore_stackref.h:726:10",
                "    #4 0x0 in _PyFrame_ClearLocals /p/Python/frame.c:101:9",
                "    #5 0x0 in _Py_Dealloc /p/Objects/object.c:3319:5",
            ]
        )
        self.assertEqual(oom_dedup.extract_native_sites(detectors_only), [])
        # (b) When a real dealloc lies beneath the detectors, resolution skips past them to it.
        with_real = "\n".join(
            [
                "==1==ERROR: AddressSanitizer: SEGV on unknown address",
                "    #3 0x0 in PyStackRef_XCLOSE /p/./Include/internal/pycore_stackref.h:726:10",
                "    #4 0x0 in clear_thread_frame /p/Python/pystate.c:3030:9",
                "    #5 0x0 in dictiter_dealloc /p/Objects/dictobject.c:5532:9",
            ]
        )
        self.assertEqual(
            oom_dedup.extract_native_sites(with_real)[0],
            "dictiter_dealloc@Objects/dictobject.c:5532",
        )


class TestExtractSite(unittest.TestCase):
    def test_skips_plumbing_returns_real_site(self):
        self.assertEqual(
            oom_dedup.extract_site_from_bt(BT), "dictiter_dealloc@Objects/dictobject.c:5532"
        )

    def test_no_cpython_frame_returns_none(self):
        self.assertIsNone(
            oom_dedup.extract_site_from_bt(
                "#0 __pthread_kill at nptl/pthread_kill.c:44\n#1 raise at sysdeps/raise.c:26"
            )
        )


class TestSegvResolution(unittest.TestCase):
    def _deduper(self, resolver, keep=5, prune=False):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        return oom_dedup.Deduper(
            path, keep=keep, prune=prune, resolve_segv=True, segv_resolver=resolver
        )

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

    def test_resolver_exception_does_not_break_decide(self):
        # A resolver that raises (e.g. gdb's captured output is binary -> UnicodeDecodeError)
        # must not propagate out of decide(): segv resolution is best-effort, and a raise here
        # previously aborted the session's keep/rename in deinit, leaving dirs as session-NNNN.
        def boom(sp):
            raise UnicodeDecodeError("utf-8", b"\x8b", 0, 1, "invalid start byte")

        d = self._deduper(boom)
        self.assertEqual(d.decide(SEGV, source_path="s"), (True, "oomSEGV"))

    def test_resolved_known_segv_prunes_over_cap(self):
        d = self._deduper(
            lambda sp: "dictiter_dealloc@Objects/dictobject.c:5532", keep=1, prune=True
        )
        self.assertTrue(d.decide(SEGV, source_path="s")[0])
        self.assertFalse(d.decide(SEGV, source_path="s")[0])

    def test_resolve_disabled_never_calls_resolver(self):
        called = []
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        d = oom_dedup.Deduper(path, resolve_segv=False, segv_resolver=lambda sp: called.append(sp))
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
            oom_dedup.gdb_crash_site("/bin/python", self.SRC, drop_uid=drop_uid, drop_gid=drop_gid)
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


class TestReadCrashStdout(unittest.TestCase):
    """Bounded stdout reader: huge OOM-verbose / binary stdout must not stall the regexes."""

    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix=".stdout")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.remove, path)
        return path

    def test_small_file_read_whole(self):
        path = self._write(b"hello\nFatal Python error: boom\n")
        text = oom_dedup.read_crash_stdout(path)
        self.assertIn("Fatal Python error: boom", text)
        self.assertNotIn("elided", text)  # small files are returned intact

    def test_huge_file_keeps_tail_fatal(self):
        body = b"[OOM-SEQ] start=x\n" * 200000  # ~3.4 MB of spew in the middle
        fatal = (
            b"Fatal Python error: _Py_Dealloc: Deallocator of type "
            b"'collections.deque' cleared the current exception\n"
        )
        text = oom_dedup.read_crash_stdout(self._write(body + fatal))
        self.assertIn("'collections.deque' cleared the current exception", text)
        self.assertIn("elided", text)  # the middle was dropped
        self.assertTrue(oom_dedup.FATAL.search(text))

    def test_huge_file_keeps_head_assert(self):
        head = (
            b"python: Objects/codeobject.c:2440: void code_dealloc(PyObject *): "
            b"Assertion `co != NULL' failed.\n"
        )
        text = oom_dedup.read_crash_stdout(self._write(head + b"x" * (4 * 1024 * 1024)))
        self.assertEqual(len(oom_dedup.all_asserts(text)), 1)  # head assert survives + parses

    def test_giant_binary_line_is_capped(self):
        # A multi-MB line with no newline is what makes the `.*?` regexes backtrack; it must
        # be truncated, and a trailing crash signature must still be found.
        blob = b"A(:)" * (3 * 1024 * 1024)  # ~12 MB, no newline -> one giant "line"
        text = oom_dedup.read_crash_stdout(
            self._write(blob + b"\nFatal Python error: Segmentation fault\n")
        )
        self.assertTrue(all(len(ln) <= oom_dedup._STDOUT_LINE_CAP for ln in text.split("\n")))
        self.assertTrue(oom_dedup.SEGV.search(text))  # regexes complete and see the segv

    def test_huge_tail_fatal_still_dedupes(self):
        # End-to-end: a huge stdout whose tail carries a known fatal still labels correctly.
        fd, snap = tempfile.mkstemp(suffix=".tsv")
        os.write(fd, SNAPSHOT.encode())
        os.close(fd)
        self.addCleanup(os.remove, snap)
        d = oom_dedup.Deduper(snap, keep=5, prune=True)
        text = oom_dedup.read_crash_stdout(
            self._write(b"[OOM] noise\n" * 200000 + FATAL_0022.encode() + b"\n")
        )
        keep, label = d.decide(text)
        self.assertEqual(label, "OOM-0022")


class TestFaulthandlerMatch(unittest.TestCase):
    """fh_match: SEGVs with only a faulthandler symbol-stack (no ASan file:line frames)
    resolve by innermost catalog-keyed func name instead of falling to oomSEGV."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".tsv")
        os.write(fd, SNAPSHOT.encode())
        os.close(fd)
        self.addCleanup(os.remove, self.path)
        self.snap = oom_dedup.load_snapshot_file(self.path)

    def _segv(self, *funcs):
        frames = "\n".join(f'  Binary file "python", at {f}+0x10 [0x55]' for f in funcs)
        return (
            "Fatal Python error: Segmentation fault\n"
            "Current thread's C stack trace (most recent call first):\n" + frames + "\n"
        )

    def test_innermost_keyed_func_wins(self):
        # detector/eval frames skipped -> code_dealloc (OOM-0003) is the innermost keyed func
        oids, fn = oom_dedup.fh_match(
            self._segv("_Py_DumpStack", "_Py_Dealloc", "code_dealloc", "_PyEval_EvalFrameDefault"),
            self.snap,
        )
        self.assertEqual((oids, fn), ({"OOM-0003"}, "code_dealloc"))

    def test_plumbing_and_eval_never_match(self):
        # _PyEval_EvalFrameDefault IS keyed (OOM-0027) but is generic plumbing -> skipped
        oids, _ = oom_dedup.fh_match(
            self._segv("_Py_Dealloc", "Py_DECREF", "_PyEval_EvalFrameDefault", "PyEval_EvalCode"),
            self.snap,
        )
        self.assertEqual(oids, set())

    def test_decide_uses_fh_fallback(self):
        d = oom_dedup.Deduper(self.path, keep=5)
        keep, label = d.decide(self._segv("_Py_Dealloc", "dictiter_dealloc"))
        self.assertEqual(label, "OOM-0006")

    def test_decide_unkeyed_symbol_segv_stays_oomSEGV(self):
        d = oom_dedup.Deduper(self.path, keep=5)
        keep, label = d.decide(self._segv("_Py_Dealloc", "some_unkeyed_helper"))
        self.assertEqual(label, "oomSEGV")

    def test_generic_call_dispatch_frames_never_match(self):
        # Regression (fusil-fleet7): a faulthandler-only over-decref segv whose only catalog-keyed
        # frame is a generic call/vectorcall/stackref-steal trampoline must NOT fh_match the bug
        # that keys it (OOM-0026 absorbed 210 unrelated dirs via _PyObject_MakeTpCall). Build a
        # snapshot keying such frames to a fake bug and assert they are skipped.
        fd, path = tempfile.mkstemp(suffix=".tsv")
        os.write(
            fd,
            (
                SNAPSHOT + "\n"
                "OOM-9001\tsegv\tfunc\tObjects/call.c:_PyObject_MakeTpCall\n"
                "OOM-9001\tsegv\tfunc\tPython/ceval.c:_Py_VectorCall_StackRefSteal\n"
                "OOM-9001\tsegv\tfunc\tPython/ceval.c:_Py_BuiltinCallFastWithKeywords_StackRef\n"
            ).encode(),
        )
        os.close(fd)
        self.addCleanup(os.remove, path)
        snap = oom_dedup.load_snapshot_file(path)
        # every generic dispatch/steal frame is skipped -> no match -> the segv needs resolution.
        oids, fn = oom_dedup.fh_match(
            self._segv(
                "_PyTuple_FromStackRefStealOnSuccess",
                "_Py_VectorCall_StackRefSteal",
                "_PyObject_MakeTpCall",
                "cfunction_call",
                "_PyEval_EvalFrameDefault",
            ),
            snap,
        )
        self.assertEqual((oids, fn), (set(), None))
        # but a real discriminating frame deeper than the generic plumbing still wins.
        oids2, fn2 = oom_dedup.fh_match(
            self._segv("_PyObject_MakeTpCall", "dictiter_dealloc"), snap
        )
        self.assertEqual((oids2, fn2), ({"OOM-0006"}, "dictiter_dealloc"))


class TestMsgFamily(unittest.TestCase):
    """msgfam catch-all: a new/fuzzer clears-exc type dedups to the family (OOM-0023) while
    type-specific keys still win (Context->0007, deque->0039), and other invariant variants
    ('raised'/'overrode') are NOT absorbed."""

    SNAP = "\n".join(
        [
            "# oom_id\tkind\tkeytype\tkey",
            "OOM-0007\tfatal\tmsg\t_Py_Dealloc: Deallocator of type 'Context' cleared the curre",
            "OOM-0039\tfatal\tmsg\t_Py_Dealloc: Deallocator of type 'collections.deque' cleared",
            "OOM-0023\tfatal\tmsg\t_Py_Dealloc: Deallocator of type '_StoreAction' cleared the ",
            "OOM-0023\tfatal\tmsgfam\tcleared the current exception",
        ]
    )

    def setUp(self):
        self.snap = oom_dedup.load_snapshot(self.SNAP.splitlines())

    def _m(self, typ, verb="cleared the current exception"):
        msg = f"_Py_Dealloc: Deallocator of type '{typ}' {verb}"
        return oom_dedup.match(dict(fatal_msg=msg), self.snap)[0]

    def test_type_specific_keys_win_over_family(self):
        self.assertEqual(self._m("Context"), {"OOM-0007"})
        self.assertEqual(self._m("collections.deque"), {"OOM-0039"})
        self.assertEqual(self._m("_StoreAction"), {"OOM-0023"})

    def test_new_and_fuzzer_types_fall_back_to_family(self):
        self.assertEqual(self._m("Evil"), {"OOM-0023"})
        self.assertEqual(self._m("weird_deque"), {"OOM-0023"})
        self.assertEqual(self._m("UnknownHandler"), {"OOM-0023"})

    def test_other_invariant_variants_not_absorbed(self):
        self.assertEqual(self._m("Foo", "raised an exception"), set())
        self.assertEqual(self._m("Bar", "overrode the current exception"), set())


if __name__ == "__main__":
    unittest.main()
