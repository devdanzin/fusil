"""Unit tests for fusil.project_directory.ProjectDirectory.

ProjectDirectory owns the per-run ``run-NNNN/`` working directory: it names + creates it on
construction, then at teardown decides whether to keep it (crash artifacts) or ``rmtree`` it.
The keep/drop decision (keepDirectory) is the counterpart to SessionDirectory.checkKeepDirectory
tested in test_session_directory.py -- here it is exercised on bare instances (no MAS, no
Univers loop) with only the collaborators each method touches stubbed. A couple of
full-construction tests use a real temp base_dir (via the injectable ``base_dir`` param) so no
run dir is created under the repo. Runtime-free.
"""

import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace

from fusil.project_directory import ProjectDirectory
from tests.mas_harness import FakeProject


# --------------------------------------------------------------------------------------
# Bare-instance helper for the pure keep/drop logic (mirrors test_session_directory.py).
# --------------------------------------------------------------------------------------
def _bare_pd(
    *,
    directory="/fake/run-0001",
    exitcode=0,
    session_executed=1,
    keep_sessions=False,
    empty_ignore_generated=True,
):
    """A ProjectDirectory with only the state keepDirectory()/rmtree()/destroy() touch."""
    pd = ProjectDirectory.__new__(ProjectDirectory)
    pd.directory = directory
    pd.files = set()
    pd.info = lambda *a, **k: None
    pd.warning = lambda *a, **k: None
    pd.error = lambda *a, **k: None
    # isEmpty(True) is the only call keepDirectory makes; True == "nothing worth keeping".
    pd.isEmpty = lambda ignore_generated=False: empty_ignore_generated
    options = SimpleNamespace(keep_sessions=keep_sessions)
    application = SimpleNamespace(exitcode=exitcode, options=options)
    pd.application = lambda: application
    project = SimpleNamespace(session_executed=session_executed)
    pd.project = lambda: project
    # Neutralize the GC-time destroy(): Agent.__del__ calls self.destroy(), and the real
    # ProjectDirectory.destroy() would rmtree the fake path (a caught-but-noisy error). Tests
    # that exercise destroy() call ProjectDirectory.destroy(pd) on the class explicitly.
    pd.destroy = lambda: None
    return pd


class TestKeepDirectory(unittest.TestCase):
    """Every branch of the keep/drop decision that produces (or discards) run dirs."""

    def test_no_directory_returns_false(self):
        pd = _bare_pd(directory=None)
        self.assertFalse(pd.keepDirectory())

    def test_fusil_error_keeps_even_without_sessions(self):
        # The exitcode check precedes the "no session executed" check, so a fusil-level error
        # keeps the directory even when nothing ran.
        pd = _bare_pd(exitcode=1, session_executed=0)
        self.assertTrue(pd.keepDirectory())

    def test_no_session_executed_dropped(self):
        pd = _bare_pd(exitcode=0, session_executed=0, keep_sessions=False)
        self.assertFalse(pd.keepDirectory())

    def test_no_session_executed_but_keep_sessions_falls_through(self):
        # keep_sessions bypasses the "no session executed" drop; a non-empty dir is then kept.
        pd = _bare_pd(session_executed=0, keep_sessions=True, empty_ignore_generated=False)
        self.assertTrue(pd.keepDirectory())

    def test_nonempty_dir_kept(self):
        pd = _bare_pd(session_executed=1, empty_ignore_generated=False)
        self.assertTrue(pd.keepDirectory())

    def test_empty_dir_dropped(self):
        pd = _bare_pd(session_executed=1, empty_ignore_generated=True)
        self.assertFalse(pd.keepDirectory())

    def test_verbose_false_suppresses_logging(self):
        # destroy() calls keepDirectory(verbose=False); make sure that path still decides.
        calls = []
        pd = _bare_pd(session_executed=1, empty_ignore_generated=False)
        pd.error = lambda *a, **k: calls.append(a)
        self.assertTrue(pd.keepDirectory(verbose=False))
        self.assertEqual(calls, [])


class TestRmtree(unittest.TestCase):
    def test_rmtree_none_directory_is_noop(self):
        pd = _bare_pd(directory=None)
        removed = []
        # If it did not short-circuit it would call Directory.rmtree; make that observable.
        pd.rmtree()  # must not raise
        self.assertIsNone(pd.directory)
        self.assertEqual(removed, [])

    def test_rmtree_removes_real_dir_and_clears_attr(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        target = os.path.join(tmp, "run-0001")
        os.mkdir(target)
        open(os.path.join(target, "source.py"), "w").close()

        pd = _bare_pd(directory=target)
        pd.rmtree()

        self.assertFalse(os.path.exists(target))
        self.assertIsNone(pd.directory)


class TestDestroy(unittest.TestCase):
    """destroy() = keepDirectory(verbose=False) -> rmtree() only when not kept."""

    def test_destroy_keeps_when_keepdirectory_true(self):
        pd = _bare_pd()
        pd.keepDirectory = lambda verbose=True: True
        removed = []
        pd.rmtree = lambda: removed.append(True)
        ProjectDirectory.destroy(pd)  # real method (instance-level destroy is neutralized)
        self.assertEqual(removed, [])

    def test_destroy_removes_when_keepdirectory_false(self):
        pd = _bare_pd()
        pd.keepDirectory = lambda verbose=True: False
        removed = []
        pd.rmtree = lambda: removed.append(True)
        ProjectDirectory.destroy(pd)  # real method (instance-level destroy is neutralized)
        self.assertEqual(removed, [True])


# --------------------------------------------------------------------------------------
# Full construction against a real temp base_dir (exercises __init__ + mkdir end-to-end).
# --------------------------------------------------------------------------------------
class TestConstruction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _project(self, **opts):
        # only_generate defaults True -> mkdir(change_owner=False) so no chown-to-fusil attempt.
        opts.setdefault("only_generate", True)
        project = FakeProject(**opts)
        app = project.application()
        app.NAME = "runtest"
        app.exitcode = 0  # keepDirectory() reads application.exitcode
        return project

    def test_creates_named_run_dir_on_disk(self):
        project = self._project()
        pd = ProjectDirectory(project, base_dir=self.tmp)
        self.addCleanup(pd.rmtree)
        self.assertTrue(os.path.isdir(pd.directory))
        self.assertEqual(os.path.dirname(pd.directory), self.tmp)
        self.assertEqual(os.path.basename(pd.directory), "runtest")

    def test_agent_name_and_registration(self):
        project = self._project()
        pd = ProjectDirectory(project, base_dir=self.tmp)
        self.addCleanup(pd.rmtree)
        self.assertEqual(pd.name, "directory:runtest")
        # ProjectAgent.__init__ registers itself with the project.
        self.assertIn(pd, project.registered)

    def test_second_directory_gets_unique_suffix(self):
        p1 = self._project()
        pd1 = ProjectDirectory(p1, base_dir=self.tmp)
        self.addCleanup(pd1.rmtree)
        p2 = self._project()
        pd2 = ProjectDirectory(p2, base_dir=self.tmp)
        self.addCleanup(pd2.rmtree)
        self.assertNotEqual(pd1.directory, pd2.directory)
        self.assertEqual(os.path.basename(pd2.directory), "runtest-2")

    def test_base_dir_defaults_to_cwd(self):
        # No base_dir -> run dir is created under the process working directory (getcwd()).
        # chdir into the temp dir so nothing lands in the repo, and restore cwd afterwards.
        prev = os.getcwd()
        self.addCleanup(os.chdir, prev)
        os.chdir(self.tmp)
        project = self._project()
        pd = ProjectDirectory(project)
        self.addCleanup(pd.rmtree)
        self.assertEqual(
            os.path.realpath(os.path.dirname(pd.directory)), os.path.realpath(self.tmp)
        )

    def test_keep_and_rmtree_on_real_dir(self):
        # A dir with an extra (non-generated) file is kept; then rmtree really removes it.
        project = self._project()
        pd = ProjectDirectory(project, base_dir=self.tmp)
        open(os.path.join(pd.directory, "crash.txt"), "w").close()
        # Wire the collaborators keepDirectory() needs onto the real instance.
        pd.project = lambda: SimpleNamespace(session_executed=1)
        self.assertTrue(pd.keepDirectory())
        directory = pd.directory
        pd.rmtree()
        self.assertFalse(os.path.exists(directory))


if __name__ == "__main__":
    unittest.main()
