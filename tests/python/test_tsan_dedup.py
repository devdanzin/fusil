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


class TestReadStdout(unittest.TestCase):
    def test_small_file_read_whole(self):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fh:
            fh.write(REPORT_TWO_SITES)
        self.assertIn("data race", tsan_dedup.read_crash_stdout(path))


if __name__ == "__main__":
    unittest.main()
