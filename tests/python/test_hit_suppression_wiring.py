"""Wiring tests for the hit-suppression keep-policy glue (Fuzzer._suppression_keep_policy).

Unlike test_hit_suppression (pure engine), this exercises the method SessionDirectory calls,
so it imports the runtime stack and SKIPS where python-ptrace is unavailable. It locks the
contract the core hook depends on: reading <session.directory.directory>/stdout, consulting
the suppressor, deferring to a previously-installed policy (e.g. OOM dedupe) when nothing
matches, suppression winning over that policy, and never losing a crash on a read error.
"""

import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace

try:
    from fusil.python import Fuzzer
    from fusil.python.hit_suppression import build_suppressor

    HAVE_FUSIL = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_FUSIL = False

CRASH = "python: Objects/dictobject.c:205: set_keys: Assertion failed."


@unittest.skipUnless(HAVE_FUSIL, "fusil runtime stack (python-ptrace) not importable")
class TestSuppressionKeepPolicy(unittest.TestCase):
    def _fake_self(self, suppressor, prev_policy=None):
        # `error` mirrors the Application logger the real Fuzzer has; the keep-policy uses it
        # to log a suppression (or a failure before falling back to keep).
        self.logged = []
        return SimpleNamespace(
            _hit_suppressor=suppressor,
            _suppression_prev_policy=prev_policy,
            error=lambda *a, **k: self.logged.append(a[0] if a else ""),
        )

    def _session(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "stdout"), "w") as fh:
            fh.write(text)
        return SimpleNamespace(directory=SimpleNamespace(directory=d))

    def test_matching_hit_is_pruned_and_logged(self):
        sup = build_suppressor(regexes=[r"dictobject\.c:205"])
        fs = self._fake_self(sup)
        keep, label = Fuzzer._suppression_keep_policy(fs, self._session(CRASH))
        self.assertFalse(keep)
        self.assertIsNone(label)
        self.assertEqual(sup.suppressed_count, 1)
        self.assertTrue(any("Hit suppressed by regex" in m for m in self.logged))

    def test_non_matching_hit_is_kept(self):
        sup = build_suppressor(regexes=["never-appears"])
        keep, label = Fuzzer._suppression_keep_policy(self._fake_self(sup), self._session(CRASH))
        self.assertTrue(keep)
        self.assertIsNone(label)

    def test_non_match_defers_to_prev_policy(self):
        sup = build_suppressor(regexes=["never-appears"])
        prev = lambda session: (True, "OOM-0036")  # noqa: E731
        keep, label = Fuzzer._suppression_keep_policy(
            self._fake_self(sup, prev_policy=prev), self._session(CRASH)
        )
        self.assertTrue(keep)
        self.assertEqual(label, "OOM-0036")

    def test_suppression_wins_over_prev_policy(self):
        # A hit the prev policy (OOM dedupe) would keep is still pruned when a rule matches,
        # and the prev policy is never consulted.
        sup = build_suppressor(regexes=[r"dictobject\.c:205"])
        calls = []

        def prev(session):
            calls.append(session)
            return True, "OOM-0036"

        keep, label = Fuzzer._suppression_keep_policy(
            self._fake_self(sup, prev_policy=prev), self._session(CRASH)
        )
        self.assertFalse(keep)
        self.assertEqual(calls, [])

    def test_missing_stdout_is_kept(self):
        sup = build_suppressor(regexes=[r"dictobject\.c:205"])
        sess = SimpleNamespace(directory=SimpleNamespace(directory="/no/such/dir/xyz"))
        keep, label = Fuzzer._suppression_keep_policy(self._fake_self(sup), sess)
        self.assertTrue(keep)
        self.assertIsNone(label)


if __name__ == "__main__":
    unittest.main()
