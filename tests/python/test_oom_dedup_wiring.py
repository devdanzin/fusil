"""Wiring tests for the OOM keep-policy glue (Fuzzer._oom_keep_policy).

Unlike test_oom_dedup (pure engine), this exercises the method that SessionDirectory
calls, so it imports the runtime stack and SKIPS where python-ptrace is unavailable.
It locks the contract the core hook depends on: reading <session.directory.directory>/
stdout, calling the deduper, and never losing a crash on a read error.
"""

import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace

try:
    from fusil.python import Fuzzer
    from fusil.python.oom_dedup import Deduper

    HAVE_FUSIL = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_FUSIL = False

SNAPSHOT = "\n".join(
    [
        "OOM-0003\tabort\tfunc\tObjects/codeobject.c:code_dealloc",
        "OOM-0003\tabort\tline\tObjects/codeobject.c:2440",
    ]
)
ABORT = "python: Objects/codeobject.c:2440: void code_dealloc(PyObject *): Assertion `co != NULL' failed."


@unittest.skipUnless(HAVE_FUSIL, "fusil runtime stack (python-ptrace) not importable")
class TestKeepPolicy(unittest.TestCase):
    def _fake_self(self, prune=False, keep=5):
        fd, path = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write(SNAPSHOT)
        self.addCleanup(os.unlink, path)
        return SimpleNamespace(_deduper=Deduper(path, keep=keep, prune=prune))

    def _session(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "stdout"), "w") as fh:
            fh.write(text)
        return SimpleNamespace(directory=SimpleNamespace(directory=d))

    def test_known_crash_kept_and_labeled(self):
        keep, label = Fuzzer._oom_keep_policy(self._fake_self(), self._session(ABORT))
        self.assertTrue(keep)
        self.assertEqual(label, "OOM-0003")

    def test_prune_over_cap(self):
        fs = self._fake_self(prune=True, keep=1)
        sess = self._session(ABORT)
        self.assertTrue(Fuzzer._oom_keep_policy(fs, sess)[0])
        self.assertFalse(Fuzzer._oom_keep_policy(fs, sess)[0])

    def test_missing_stdout_is_kept_unlabeled(self):
        fs = self._fake_self()
        sess = SimpleNamespace(directory=SimpleNamespace(directory="/no/such/dir/xyz"))
        keep, label = Fuzzer._oom_keep_policy(fs, sess)
        self.assertTrue(keep)
        self.assertIsNone(label)


if __name__ == "__main__":
    unittest.main()
