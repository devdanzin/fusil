import importlib.util
import os
import stat
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_PY = os.path.join(SCRIPT_DIR, "..", "..", "fusil", "python", "fixtures.py")


def _load_fixtures():
    # fixtures.py is intentionally dependency-free; load it directly so the test does not
    # require the fusil.python package __init__ (which pulls in python-ptrace).
    spec = importlib.util.spec_from_file_location("fusil_fixtures_under_test", FIXTURES_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fx = _load_fixtures()


class TestSafeFixtures(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = os.environ.get("FUSIL_FIXTURE_DIR")
        os.environ["FUSIL_FIXTURE_DIR"] = os.path.join(self._tmp.name, "fixtures")

    def tearDown(self):
        if self._old is None:
            os.environ.pop("FUSIL_FIXTURE_DIR", None)
        else:
            os.environ["FUSIL_FIXTURE_DIR"] = self._old
        self._tmp.cleanup()

    def test_creates_absolute_existing_readonly_files(self):
        paths = fx.ensure_fixture_files()
        self.assertTrue(paths)
        for p in paths:
            self.assertTrue(os.path.isabs(p))
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 0)
            mode = stat.S_IMODE(os.stat(p).st_mode)
            self.assertEqual(mode & 0o222, 0, f"{p} is writable (mode {oct(mode)})")

    def test_never_points_at_system_files(self):
        # The whole point of the fix: defaults must be expendable, never real system files.
        for p in fx.ensure_fixture_files():
            self.assertNotIn(p, ("/bin/sh", "/etc/machine-id"))
            self.assertTrue(p.startswith(fx.fixture_dir()))

    def test_idempotent(self):
        self.assertEqual(fx.ensure_fixture_files(), fx.ensure_fixture_files())

    def test_self_heals_after_clobber(self):
        paths = fx.ensure_fixture_files()
        victim = paths[0]
        size = os.path.getsize(victim)
        os.chmod(victim, 0o644)
        open(victim, "wb").close()  # simulate a fuzzed call truncating it
        self.assertEqual(os.path.getsize(victim), 0)
        fx.ensure_fixture_files()
        self.assertEqual(os.path.getsize(victim), size)


if __name__ == "__main__":
    unittest.main()
