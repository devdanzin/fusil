"""Unit tests for the in-loop RustPython crash deduper (fusil.python.rustpython_dedup).

Pure-Python: parse canned RustPython panic/segfault stdout into site signatures and exercise the
catalog dedupe / prune / segv-resolution decisions without the runtime stack. Mirrors
test_tsan_dedup / test_oom_dedup.
"""

import unittest

from fusil.python import rustpython_dedup as rd

# Real RustPython panic headers (captured from rustpython 0.5.0). The newer toolchain prints a
# thread-id in parens; the older one does not -- both must parse to the same site signature.
PANIC_STRUCTSEQ_TID = "\n".join(
    [
        "",
        "thread 'main' (2430955) panicked at crates/vm/src/types/structseq.rs:311:21:",
        "index out of bounds: the len is 0 but the index is 0",
        "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace",
    ]
)
PANIC_STRUCTSEQ_NO_TID = "\n".join(
    [
        "thread 'main' panicked at crates/vm/src/types/structseq.rs:311:21:",
        "index out of bounds: the len is 0 but the index is 0",
    ]
)
PANIC_STATICMETHOD = (
    "thread 'main' (7) panicked at crates/vm/src/builtins/staticmethod.rs:182:54:\n"
    "called `Result::unwrap()` on an `Err` value: PyBaseException"
)
# A worker-thread panic that prints MID-stdout (RUSTPY-0001 class), with real output after it.
PANIC_WORKER_MIDSTREAM = "\n".join(
    [
        "[CSTRESS] entering region",
        "some worker output",
        "thread '<unnamed>' (99) panicked at crates/vm/src/stdlib/thread.rs:977:13:",
        "already borrowed: BorrowMutError",
        "more output printed after the panic",
    ]
)
# A build that baked in an absolute checkout path -> must normalise to the crates/ tail.
PANIC_ABSOLUTE_PATH = (
    "thread 'main' panicked at "
    "/home/x/.cargo/git/checkouts/rustpython-abc123/a9c2c52/crates/vm/src/x.rs:42:1:\n"
    "boom"
)
# A bare segfault: no panic line at all.
SEGV_NO_PANIC = "\n".join(
    [
        "Importing target module: re",
        "[NEW-UNINIT] entering uninitialized-object region",
        "[NEW-UNINIT] poking Match",
    ]
)
# A gdb backtrace whose top real frame is a RustPython hash function (plumbing above it skipped).
GDB_BT = "\n".join(
    [
        "Program received signal SIGSEGV, Segmentation fault.",
        "#0  0x00007f00 in __memmove_avx_unaligned ()",
        "#1  0x00007f01 in core::panicking::panic ()",
        "#2  0x00007f02 in rustpython_vm::builtins::int::PyInt::hash () at crates/vm/src/x.rs:9",
        "#3  0x00007f03 in _PyEval_EvalFrameDefault ()",
    ]
)


class TestParseReport(unittest.TestCase):
    def test_panic_with_tid(self):
        rep = rd.parse_report(PANIC_STRUCTSEQ_TID)
        self.assertIsNotNone(rep)
        self.assertEqual(rep["kind"], "panic")
        self.assertEqual(rep["signature"], "crates/vm/src/types/structseq.rs:311")

    def test_panic_without_tid(self):
        rep = rd.parse_report(PANIC_STRUCTSEQ_NO_TID)
        self.assertEqual(rep["signature"], "crates/vm/src/types/structseq.rs:311")

    def test_tid_and_no_tid_dedupe_identically(self):
        self.assertEqual(
            rd.parse_report(PANIC_STRUCTSEQ_TID)["signature"],
            rd.parse_report(PANIC_STRUCTSEQ_NO_TID)["signature"],
        )

    def test_column_is_dropped(self):
        # :182:54 -> drop the :54 column.
        self.assertEqual(
            rd.parse_report(PANIC_STATICMETHOD)["signature"],
            "crates/vm/src/builtins/staticmethod.rs:182",
        )

    def test_worker_panic_midstream(self):
        rep = rd.parse_report(PANIC_WORKER_MIDSTREAM)
        self.assertEqual(rep["signature"], "crates/vm/src/stdlib/thread.rs:977")

    def test_absolute_path_normalised(self):
        rep = rd.parse_report(PANIC_ABSOLUTE_PATH)
        self.assertEqual(rep["signature"], "crates/vm/src/x.rs:42")

    def test_no_panic_returns_none(self):
        self.assertIsNone(rd.parse_report(SEGV_NO_PANIC))

    def test_first_panic_wins(self):
        two = PANIC_STATICMETHOD + "\n" + PANIC_STRUCTSEQ_NO_TID
        self.assertEqual(
            rd.parse_report(two)["signature"], "crates/vm/src/builtins/staticmethod.rs:182"
        )


class TestParseAllPanics(unittest.TestCase):
    def test_distinct_panics_collected_in_order(self):
        text = PANIC_STATICMETHOD + "\n" + PANIC_STRUCTSEQ_NO_TID + "\n" + PANIC_STATICMETHOD
        sigs = rd.parse_all_panics(text)
        self.assertEqual(
            sigs,
            [
                "crates/vm/src/builtins/staticmethod.rs:182",
                "crates/vm/src/types/structseq.rs:311",
            ],
        )

    def test_none_when_no_panic(self):
        self.assertEqual(rd.parse_all_panics(SEGV_NO_PANIC), [])


class TestCatalog(unittest.TestCase):
    def test_load_catalog_skips_comments_and_bad_rows(self):
        lines = [
            "# a comment",
            "RUSTPY-0002\tcrates/vm/src/types/structseq.rs:311",
            "RUSTPY-0009\tcrates/vm/src/builtins/staticmethod.rs:182",
            "malformed line without tab",
            "",
        ]
        cat = rd.load_catalog(lines)
        self.assertEqual(cat["crates/vm/src/types/structseq.rs:311"], "RUSTPY-0002")
        self.assertEqual(cat["crates/vm/src/builtins/staticmethod.rs:182"], "RUSTPY-0009")
        self.assertEqual(len(cat), 2)


class TestGdbTopFrame(unittest.TestCase):
    def test_skips_plumbing_to_real_frame(self):
        self.assertEqual(rd._gdb_top_frame(GDB_BT), "rustpython_vm::builtins::int::PyInt::hash")

    def test_none_when_no_frames(self):
        self.assertIsNone(rd._gdb_top_frame("no frames here"))


class TestDeduperPanics(unittest.TestCase):
    def _cat(self):
        return {
            "crates/vm/src/types/structseq.rs:311": "RUSTPY-0002",
            "crates/vm/src/builtins/staticmethod.rs:182": "RUSTPY-0009",
        }

    def test_known_panic_labelled(self):
        d = rd.RustPyDeduper()
        d.snap = self._cat()
        keep, label = d.decide(PANIC_STRUCTSEQ_TID)
        self.assertTrue(keep)
        self.assertEqual(label, "RUSTPY-0002")

    def test_new_panic_labelled_rustpynew(self):
        d = rd.RustPyDeduper()
        d.snap = self._cat()
        keep, label = d.decide(PANIC_WORKER_MIDSTREAM)  # thread.rs:977 not in catalog
        self.assertTrue(keep)
        self.assertEqual(label, "rustpyNEW")

    def test_prune_past_keep_cap(self):
        d = rd.RustPyDeduper(keep=2, prune=True)
        d.snap = self._cat()
        labels = [d.decide(PANIC_STRUCTSEQ_TID) for _ in range(4)]
        # First 2 kept, rest pruned (keep=False) but still labelled with the id.
        self.assertEqual([k for k, _ in labels], [True, True, False, False])
        self.assertTrue(all(lbl == "RUSTPY-0002" for _, lbl in labels))
        self.assertEqual(d.seen["RUSTPY-0002"], 4)
        self.assertEqual(d.kept["RUSTPY-0002"], 2)

    def test_no_prune_keeps_all(self):
        d = rd.RustPyDeduper(keep=2, prune=False)
        d.snap = self._cat()
        keeps = [d.decide(PANIC_STRUCTSEQ_TID)[0] for _ in range(4)]
        self.assertEqual(keeps, [True, True, True, True])


class TestDeduperSegv(unittest.TestCase):
    def test_segv_without_resolver_buckets(self):
        d = rd.RustPyDeduper()  # resolve_segv defaults False
        keep, label = d.decide(SEGV_NO_PANIC, source_path="/x/source.py")
        self.assertTrue(keep)
        self.assertEqual(label, "rustpySEGV")

    def test_segv_resolved_new(self):
        d = rd.RustPyDeduper(resolve_segv=True, segv_resolver=lambda p: "PyInt::hash")
        keep, label = d.decide(SEGV_NO_PANIC, source_path="/x/source.py")
        self.assertTrue(keep)
        self.assertEqual(label, "rustpySEGV")
        self.assertIn("NEW-SEGV:SEGV PyInt::hash", d.seen)

    def test_segv_resolved_known(self):
        d = rd.RustPyDeduper(resolve_segv=True, segv_resolver=lambda p: "PyInt::hash")
        d.snap = {"SEGV PyInt::hash": "RUSTPY-0007a"}
        keep, label = d.decide(SEGV_NO_PANIC, source_path="/x/source.py")
        self.assertTrue(keep)
        self.assertEqual(label, "RUSTPY-0007a")

    def test_resolver_failure_falls_back_to_bucket(self):
        def boom(_p):
            raise RuntimeError("gdb blew up")

        d = rd.RustPyDeduper(resolve_segv=True, segv_resolver=boom)
        keep, label = d.decide(SEGV_NO_PANIC, source_path="/x/source.py")
        self.assertTrue(keep)
        self.assertEqual(label, "rustpySEGV")

    def test_resolver_returns_list(self):
        d = rd.RustPyDeduper(resolve_segv=True, segv_resolver=lambda p: ["top::frame", "next"])
        d.snap = {"SEGV top::frame": "RUSTPY-0099"}
        keep, label = d.decide(SEGV_NO_PANIC, source_path="/x/source.py")
        self.assertEqual(label, "RUSTPY-0099")


class TestReport(unittest.TestCase):
    def test_report_lists_seen_and_kept(self):
        d = rd.RustPyDeduper()
        d.snap = {"crates/vm/src/types/structseq.rs:311": "RUSTPY-0002"}
        d.decide(PANIC_STRUCTSEQ_TID)
        text = d.report()
        self.assertIn("RustPython dedupe summary", text)
        self.assertIn("RUSTPY-0002", text)


if __name__ == "__main__":
    unittest.main()
