"""Unit tests for the in-loop TSan race deduper (fusil.python.tsan_dedup).

Pure-Python: parse canned ThreadSanitizer reports into race signatures and exercise the
catalog dedupe / prune / suppression / framework decisions without the runtime stack.
Mirrors test_oom_dedup.
"""

import os
import tempfile
import unittest

from fusil.python import tsan_dedup

# A race between two distinct sites (list_append writes, list_extend reads). #0 of the write
# stanza is the memset interceptor (<null> source) + is skipped; the eval/thread frames are
# plumbing/scaffolding and skipped, so each stanza reduces to its real listobject.c site.
REPORT_TWO_SITES = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=1)",
        "  Write of size 8 at 0x7f00 by thread T1:",
        "    #0 memset <null> (python+0x1) (BuildId: aa)",
        "    #1 list_append /b/./Objects/listobject.c:900:5 (python+0x2) (BuildId: aa)",
        "    #2 _PyEval_EvalFrameDefault /b/Python/ceval.c:1000:3 (python+0x3) (BuildId: aa)",
        "    #3 thread_run /b/./Modules/_threadmodule.c:388:21 (python+0x4) (BuildId: aa)",
        "",
        "  Previous read of size 8 at 0x7f00 by thread T2:",
        "    #0 list_extend /b/Objects/listobject.c:850:9 (python+0x5) (BuildId: aa)",
        "    #1 _PyEval_EvalFrameDefault /b/Python/ceval.c:1000:3 (python+0x6) (BuildId: aa)",
        "    #2 thread_run /b/./Modules/_threadmodule.c:388:21 (python+0x7) (BuildId: aa)",
        "",
        "  Thread T1 (tid=2, running) created by main thread at:",
        "    #0 pthread_create <null> (python+0x8) (BuildId: aa)",
        "SUMMARY: ThreadSanitizer: data race (python+0x2) in list_append",
    ]
)

# Same race, threads swapped (read/write and T1/T2 exchanged) -> MUST canonicalize identically.
REPORT_SWAPPED = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=9)",
        "  Write of size 8 at 0x7f00 by thread T2:",
        "    #0 list_extend /b/Objects/listobject.c:850:9 (python+0x5) (BuildId: aa)",
        "    #1 _PyEval_EvalFrameDefault /b/Python/ceval.c:1000:3 (python+0x6) (BuildId: aa)",
        "",
        "  Previous write of size 8 at 0x7f00 by thread T1:",
        "    #0 memset <null> (python+0x1) (BuildId: aa)",
        "    #1 list_append /b/./Objects/listobject.c:900:5 (python+0x2) (BuildId: aa)",
        "",
        "SUMMARY: ThreadSanitizer: data race (python+0x5) in list_extend",
    ]
)

# A race whose both access sites live only in the thread machinery -> framework noise.
# Genuine framework noise: BOTH sites are the harness's own thread-lifecycle path (spinning
# workers up/down), not any target data.
REPORT_FRAMEWORK = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=3)",
        "  Write of size 8 at 0x7f00 by thread T1:",
        "    #0 ThreadHandle_start /b/./Modules/_threadmodule.c:475:9 (python+0x1)",
        "",
        "  Previous read of size 8 at 0x7f00 by thread T2:",
        "    #0 thread_run /b/./Modules/_threadmodule.c:330:2 (python+0x2)",
        "",
        "SUMMARY: ThreadSanitizer: data race in ThreadHandle_start",
    ]
)

# NOT framework noise: Modules/_threadmodule.c also holds the PUBLIC _thread API. A race between
# public lock/RLock methods is a genuine finding -- the old file-level `_threadmodule.c` match
# buried the real RLock repr race (cf. cpython#153292) as scaffolding.
REPORT_PUBLIC_THREAD_API = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=3)",
        "  Write of size 8 at 0x7f00 by thread T1:",
        "    #0 _thread_RLock__release_save_impl /b/./Modules/_threadmodule.c:1233:22 (python+0x1)",
        "",
        "  Previous read of size 8 at 0x7f00 by thread T2:",
        "    #0 rlock_repr /b/./Modules/_threadmodule.c:1295:28 (python+0x2)",
        "",
        "SUMMARY: ThreadSanitizer: data race in rlock_repr",
    ]
)

# TSan lowercases the whole SECOND access line, including the `atomic` qualifier: "Previous
# atomic write". The reader-vs-atomic-writer shape is the single most common race class in the
# catalog, so failing to match this header dropped the 2nd stanza and (via the len<2 fallback)
# fabricated a symmetric "A | A" signature.
REPORT_PREVIOUS_ATOMIC = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=4)",
        "  Read of size 8 at 0x7f00 by thread T3:",
        "    #0 rlock_repr /b/./Modules/_threadmodule.c:1291:41 (python+0x1)",
        "",
        "  Previous atomic write of size 8 at 0x7f00 by thread T1:",
        "    #0 _Py_atomic_store_ullong_relaxed /b/./Include/cpython/pyatomic_gcc.h:518:3 (python+0x2)",
        "",
        "SUMMARY: ThreadSanitizer: data race in rlock_repr",
    ]
)

NO_RACE = "hello, no ThreadSanitizer here\nSUMMARY: nothing\n"

# A SEGV whose stack TSan couldn't unwind (nested bug) -> signature is the fault addr + pc.
REPORT_SEGV_NOFRAMES = "\n".join(
    [
        "==123==ERROR: ThreadSanitizer: SEGV on unknown address 0x0000000000d8"
        " (pc 0x5555556bf69f bp 0xdead sp 0xbeef T123)",
        "==123==The signal is caused by a READ memory access.",
        "ThreadSanitizer: nested bug in the same thread, aborting.",
    ]
)

# Slice D: a race whose BOTH real sites live in an out-of-tree C extension (cereggii). The only
# CPython-ish frames are the <null> interceptor, so WITHOUT --tsan-source-root the report reduces
# to nothing (noparse); WITH the extension's root it resolves to root-relative sites.
REPORT_EXT_VS_EXT = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=7)",
        "  Write of size 8 at 0x7f00 by thread T1:",
        "    #0 memset <null> (cereggii.so+0x1) (BuildId: bb)",
        "    #1 AtomicDict_SetItem /build/cereggii/src/atomic_dict.c:412:9 (cereggii.so+0x2)",
        "",
        "  Previous read of size 8 at 0x7f00 by thread T2:",
        "    #0 AtomicDict_GetItem /build/cereggii/src/atomic_dict.c:355:5 (cereggii.so+0x3)",
        "",
        "SUMMARY: ThreadSanitizer: data race in AtomicDict_SetItem",
    ]
)

# Slice D: a race across the boundary -- one CPython site, one extension site. The CPython side
# always resolves; the extension side is "?" without a root and resolves with one.
REPORT_EXT_VS_CPYTHON = "\n".join(
    [
        "WARNING: ThreadSanitizer: data race (pid=8)",
        "  Write of size 8 at 0x7f00 by thread T1:",
        "    #0 AtomicRef_Set /build/cereggii/src/atomic_ref.c:88:3 (cereggii.so+0x1)",
        "",
        "  Previous read of size 8 at 0x7f00 by thread T2:",
        "    #0 list_extend /b/Objects/listobject.c:850:9 (python+0x5) (BuildId: aa)",
        "",
        "SUMMARY: ThreadSanitizer: data race in AtomicRef_Set",
    ]
)

# A use-after-free with a symbolized crash stack -> signature is the top real site.
REPORT_UAF_FRAMES = "\n".join(
    [
        "==1==ERROR: ThreadSanitizer: heap-use-after-free on address 0x7f00"
        " (pc 0x1234 bp 0x1 sp 0x2 T1)",
        "    #0 dictiter_dealloc /b/./Objects/dictobject.c:5620:9 (python+0x1) (BuildId: aa)",
        "    #1 _Py_Dealloc /b/Objects/object.c:3319:5 (python+0x2) (BuildId: aa)",
        "SUMMARY: ThreadSanitizer: heap-use-after-free Objects/dictobject.c:5620 in dictiter_dealloc",
    ]
)


class TestParseAll(unittest.TestCase):
    """parse_all_reports: extract EVERY race from a report-and-continue (halt_on_error=0) stdout."""

    def test_multiple_distinct_races(self):
        text = "\n".join([REPORT_TWO_SITES, REPORT_PREVIOUS_ATOMIC, REPORT_SEGV_NOFRAMES])
        reps = tsan_dedup.parse_all_reports(text)
        self.assertEqual([r["kind"] for r in reps], ["race", "race", "segv"])
        self.assertEqual([r["order"] for r in reps], [0, 1, 2])  # stream position preserved
        sigs = {r["signature"] for r in reps}
        self.assertIn("Objects/listobject.c:list_append | Objects/listobject.c:list_extend", sigs)
        self.assertEqual(len(sigs), 3)

    def test_dedup_by_signature(self):
        # the same race reported twice (here swapped-thread form) collapses to one entry
        text = "\n".join([REPORT_TWO_SITES, REPORT_SWAPPED])
        reps = tsan_dedup.parse_all_reports(text)
        self.assertEqual(len(reps), 1)
        self.assertEqual(
            reps[0]["signature"],
            "Objects/listobject.c:list_append | Objects/listobject.c:list_extend",
        )

    def test_single_report_and_empty(self):
        self.assertEqual(len(tsan_dedup.parse_all_reports(REPORT_TWO_SITES)), 1)
        self.assertEqual(tsan_dedup.parse_all_reports(NO_RACE), [])
        self.assertEqual(tsan_dedup.parse_all_reports(""), [])

    def test_parse_report_still_first_only(self):
        # the contract for the sibling catalog: parse_report is unchanged (first report only).
        text = "\n".join([REPORT_TWO_SITES, REPORT_PREVIOUS_ATOMIC])
        self.assertEqual(
            tsan_dedup.parse_report(text)["signature"],
            "Objects/listobject.c:list_append | Objects/listobject.c:list_extend",
        )


class TestParse(unittest.TestCase):
    def test_signature_is_sorted_site_pair(self):
        r = tsan_dedup.parse_report(REPORT_TWO_SITES)
        self.assertEqual(
            r["signature"],
            "Objects/listobject.c:list_append | Objects/listobject.c:list_extend",
        )
        self.assertFalse(r["framework"])

    def test_swapped_threads_canonicalize_identically(self):
        a = tsan_dedup.parse_report(REPORT_TWO_SITES)["signature"]
        b = tsan_dedup.parse_report(REPORT_SWAPPED)["signature"]
        self.assertEqual(a, b)

    def test_interceptor_and_plumbing_frames_skipped(self):
        # the top site of the write stanza is list_append, NOT memset / _PyEval_EvalFrameDefault.
        r = tsan_dedup.parse_report(REPORT_TWO_SITES)
        funcs = {s[1] for s in r["sites"] if s}
        self.assertEqual(funcs, {"list_append", "list_extend"})
        self.assertNotIn("memset", funcs)
        self.assertNotIn("_PyEval_EvalFrameDefault", funcs)

    def test_no_race_returns_none(self):
        self.assertIsNone(tsan_dedup.parse_report(NO_RACE))

    def test_framework_race_flagged(self):
        r = tsan_dedup.parse_report(REPORT_FRAMEWORK)
        self.assertTrue(r["framework"])

    def test_public_thread_api_race_is_not_framework(self):
        # Modules/_threadmodule.c holds the public _thread API too; a race between public
        # RLock methods is a real finding, not harness scaffolding.
        r = tsan_dedup.parse_report(REPORT_PUBLIC_THREAD_API)
        self.assertFalse(r["framework"])
        self.assertEqual(
            r["signature"],
            "Modules/_threadmodule.c:_thread_RLock__release_save_impl"
            " | Modules/_threadmodule.c:rlock_repr",
        )

    def test_previous_atomic_write_stanza_parsed(self):
        # "Previous atomic write" (lowercased `atomic`) must be recognised as the 2nd access
        # stanza; otherwise it is dropped and the 1st stanza duplicated into "A | A".
        r = tsan_dedup.parse_report(REPORT_PREVIOUS_ATOMIC)
        self.assertEqual(
            r["signature"],
            "Include/cpython/pyatomic_gcc.h:_Py_atomic_store_ullong_relaxed"
            " | Modules/_threadmodule.c:rlock_repr",
        )
        self.assertFalse(r["framework"])

    def test_access_header_variants_match(self):
        for header in (
            "  Write of size 8 at 0x7f00 by thread T1:",
            "  Read of size 8 at 0x7f00 by thread T1:",
            "  Previous write of size 8 at 0x7f00 by thread T1:",
            "  Previous read of size 8 at 0x7f00 by thread T1:",
            "  Atomic write of size 8 at 0x7f00 by thread T1:",
            "  Atomic read of size 8 at 0x7f00 by thread T1:",
            "  Previous atomic write of size 8 at 0x7f00 by thread T1:",
            "  Previous atomic read of size 8 at 0x7f00 by thread T1:",
        ):
            self.assertTrue(tsan_dedup.ACCESS.search(header), header)


class TestDecide(unittest.TestCase):
    def _deduper(self, catalog_rows=(), keep=5, prune=False, supp_lines=None):
        d = tsan_dedup.TSanDeduper(keep=keep, prune=prune)
        d.snap = tsan_dedup.load_catalog(list(catalog_rows))
        if supp_lines is not None:
            d.suppressor = tsan_dedup.Suppressor.from_lines(supp_lines)
        return d

    def test_new_race_is_tsannew_and_kept(self):
        self.assertEqual(self._deduper().decide(REPORT_TWO_SITES), (True, "tsanNEW"))

    def test_known_race_labeled(self):
        sig = tsan_dedup.parse_report(REPORT_TWO_SITES)["signature"]
        d = self._deduper(catalog_rows=["TSAN-0001\t%s" % sig])
        self.assertEqual(d.decide(REPORT_TWO_SITES), (True, "TSAN-0001"))

    def test_known_pruned_past_cap(self):
        sig = tsan_dedup.parse_report(REPORT_TWO_SITES)["signature"]
        d = self._deduper(catalog_rows=["TSAN-0001\t%s" % sig], keep=1, prune=True)
        self.assertEqual([d.decide(REPORT_TWO_SITES)[0] for _ in range(3)], [True, False, False])

    def test_known_not_pruned_without_prune(self):
        sig = tsan_dedup.parse_report(REPORT_TWO_SITES)["signature"]
        d = self._deduper(catalog_rows=["TSAN-0001\t%s" % sig], keep=1, prune=False)
        self.assertTrue(all(d.decide(REPORT_TWO_SITES)[0] for _ in range(3)))

    def test_suppressed_race_pruned(self):
        # `race:list_append` matches one of the racing site funcs -> drop.
        d = self._deduper(supp_lines=["race:list_append"])
        self.assertEqual(d.decide(REPORT_TWO_SITES), (False, None))

    def test_suppression_by_signature_regex(self):
        d = self._deduper(supp_lines=["listobject.*list_extend"])
        self.assertEqual(d.decide(REPORT_TWO_SITES), (False, None))

    def test_framework_race_labeled_not_new(self):
        d = self._deduper()
        self.assertEqual(d.decide(REPORT_FRAMEWORK), (True, "tsanFRAME"))

    def test_unparseable_kept(self):
        self.assertEqual(self._deduper().decide(NO_RACE), (True, "tsanNOPARSE"))


class TestSegv(unittest.TestCase):
    def test_segv_no_frames_keyed_on_addr_and_pc(self):
        r = tsan_dedup.parse_report(REPORT_SEGV_NOFRAMES)
        self.assertEqual(r["kind"], "segv")
        self.assertEqual(r["signature"], "SEGV addr=0xd8 pc=0x5555556bf69f")
        self.assertFalse(r["framework"])

    def test_uaf_with_frames_keyed_on_site(self):
        r = tsan_dedup.parse_report(REPORT_UAF_FRAMES)
        self.assertEqual(r["kind"], "segv")
        self.assertEqual(
            r["signature"], "heap-use-after-free Objects/dictobject.c:dictiter_dealloc"
        )

    def test_new_segv_labeled_tsansegv(self):
        self.assertEqual(tsan_dedup.TSanDeduper().decide(REPORT_SEGV_NOFRAMES), (True, "tsanSEGV"))

    def test_known_segv_labeled_and_prunable(self):
        d = tsan_dedup.TSanDeduper(keep=1, prune=True)
        d.snap = tsan_dedup.load_catalog(["TSAN-0009\tSEGV addr=0xd8 pc=0x5555556bf69f"])
        self.assertEqual(
            [d.decide(REPORT_SEGV_NOFRAMES) for _ in range(2)],
            [(True, "TSAN-0009"), (False, "TSAN-0009")],
        )

    def test_segv_suppressible(self):
        d = tsan_dedup.TSanDeduper()
        d.suppressor = tsan_dedup.Suppressor.from_lines(["dictiter_dealloc"])
        self.assertEqual(d.decide(REPORT_UAF_FRAMES), (False, None))


class TestSourceRoots(unittest.TestCase):
    """Slice D: external C-extension source roots. The mandatory invariant is that the DEFAULT
    (no roots) is byte-for-byte the CPython-only behaviour -- the cross-repo signature contract."""

    CEREGGII = "/build/cereggii"

    def test_default_is_unchanged_cpython_only(self):
        # No roots -> identical to the pre-Slice-D signature.
        r = tsan_dedup.parse_report(REPORT_TWO_SITES)
        self.assertEqual(
            r["signature"],
            "Objects/listobject.c:list_append | Objects/listobject.c:list_extend",
        )

    def test_cpython_matched_first_even_when_a_root_would_match(self):
        # Passing a broad root that also contains the CPython build dir must NOT change a CPython
        # frame's signature -- CPython is always resolved first.
        r = tsan_dedup.parse_report(REPORT_TWO_SITES, source_roots=["/b"])
        self.assertEqual(
            r["signature"],
            "Objects/listobject.c:list_append | Objects/listobject.c:list_extend",
        )

    def test_ext_vs_ext_is_noparse_without_roots(self):
        self.assertIsNone(tsan_dedup.parse_report(REPORT_EXT_VS_EXT))

    def test_ext_vs_ext_resolves_with_root(self):
        r = tsan_dedup.parse_report(REPORT_EXT_VS_EXT, source_roots=[self.CEREGGII])
        self.assertEqual(
            r["signature"],
            "src/atomic_dict.c:AtomicDict_GetItem | src/atomic_dict.c:AtomicDict_SetItem",
        )

    def test_ext_vs_cpython_resolves_both_sides_with_root(self):
        r = tsan_dedup.parse_report(REPORT_EXT_VS_CPYTHON, source_roots=[self.CEREGGII])
        self.assertEqual(
            r["signature"],
            "Objects/listobject.c:list_extend | src/atomic_ref.c:AtomicRef_Set",
        )

    def test_ext_vs_cpython_degrades_to_question_without_root(self):
        # Without a root the extension side is unresolved ("?"), but the CPython side still keys.
        r = tsan_dedup.parse_report(REPORT_EXT_VS_CPYTHON)
        self.assertEqual(r["signature"], "? | Objects/listobject.c:list_extend")

    def test_relative_to_root_absolute_prefix(self):
        self.assertEqual(
            tsan_dedup._relative_to_root("/build/cereggii/src/atomic_dict.c", "/build/cereggii"),
            "src/atomic_dict.c",
        )

    def test_relative_to_root_basename_anchor_when_build_path_differs(self):
        # The path baked into the .so can differ from the local root; fall back to the /name/ anchor.
        self.assertEqual(
            tsan_dedup._relative_to_root(
                "/somewhere/else/cereggii/src/atomic_dict.c", "/home/me/cereggii"
            ),
            "src/atomic_dict.c",
        )

    def test_relative_to_root_not_under_root(self):
        self.assertIsNone(tsan_dedup._relative_to_root("/other/pkg/foo.c", "/build/cereggii"))

    def test_deduper_resolves_ext_race_with_source_roots(self):
        # End-to-end: an ext-vs-ext race that would be noparse is a real tsanNEW with a root.
        d_default = tsan_dedup.TSanDeduper()
        self.assertEqual(d_default.decide(REPORT_EXT_VS_EXT), (True, "tsanNOPARSE"))
        d_roots = tsan_dedup.TSanDeduper(source_roots=[self.CEREGGII])
        self.assertEqual(d_roots.decide(REPORT_EXT_VS_EXT), (True, "tsanNEW"))


class TestReadStdout(unittest.TestCase):
    def test_small_file_read_whole(self):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fh:
            fh.write(REPORT_TWO_SITES)
        self.assertIn("data race", tsan_dedup.read_crash_stdout(path))


if __name__ == "__main__":
    unittest.main()
