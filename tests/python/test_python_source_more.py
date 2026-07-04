"""Additional unit tests for fusil.python.python_source.PythonSource.

Complements tests/python/test_python_source.py (which pins the SystemExit-at-import skip
path via a bare, __init__-bypassing instance) by exercising the parts that test does not:
the real constructor (explicit-module parsing, blacklist removal, --filenames validation and
the fixture fallback, plugin-manager detection, and the "*" discovery path), plus loadModule
and the full on_session_start wiring.

Runtime-free and side-effect-free: a real MTA-backed FakeProject constructs the agent, and
the two heavyweight collaborators are injected via the constructor's
``module_lister_factory`` / ``write_code_factory`` seams so no whole-stdlib scan or real code
generation happens. ``FUSIL_FIXTURE_DIR`` is pointed at a temp dir so the fixture-fallback
test writes nothing outside it.
"""

import os
import sys
import tempfile
import unittest
from types import ModuleType, SimpleNamespace

from fusil.python.python_source import PythonSource
from tests.mas_harness import FakeProject

# Baseline option set: explicit single module (so the constructor never scans the stdlib),
# no packages, no blacklist, threads/async on. Individual tests override what they exercise.
_DEFAULT_OPTIONS = dict(
    modules="json",
    packages="*",
    blacklist="",
    only_c=False,
    no_site_packages=False,
    skip_test=False,
    verbose=False,
    no_threads=False,
    no_async=False,
    filenames="",
)


def _options(**overrides):
    opts = dict(_DEFAULT_OPTIONS)
    opts.update(overrides)
    return SimpleNamespace(**opts)


class _FakeWriter:
    """Stand-in for WritePythonCode: records generate_fuzzing_script() calls."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.generate_calls = 0

    def generate_fuzzing_script(self):
        self.generate_calls += 1


class _WriterFactory:
    """Callable module_lister-style factory returning (and remembering) a _FakeWriter."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.writer: _FakeWriter | None = None

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.writer = _FakeWriter(*args, **kwargs)
        return self.writer


def _lister_factory(search=(), discover=()):
    """Build a module_lister_factory whose instances return canned search/discover results
    and which captures the constructor args of the last instance built."""
    captured: dict = {}

    def factory(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            search_modules=lambda: set(search),
            discover_modules=lambda paths, prefix: list(discover),
        )

    factory.captured = captured
    return factory


def _make_source(*, tmpfile=None, write_code_factory=None, module_lister_factory=None, **opt):
    """Construct a real PythonSource over a FakeProject with injected collaborators.

    ``project.error`` is stubbed because the constructor logs the chosen filenames through
    it directly (FakeProject is not an Agent). Returns (source, project).
    """
    project = FakeProject()
    project.error = lambda *a, **k: None
    options = _options(**opt)
    source = PythonSource(
        project,
        options,
        source_output_path=tmpfile,
        module_lister_factory=module_lister_factory,
        write_code_factory=write_code_factory,
    )
    return source, project


class TestConstructionModuleSelection(unittest.TestCase):
    def setUp(self):
        # An absolute, existing throwaway file so --filenames validation passes.
        fd, self.path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(self.path) and os.unlink(self.path))

    def test_explicit_modules_parsed_stripped_and_sorted(self):
        # Whitespace is stripped and empty entries (trailing comma) dropped.
        src, _ = _make_source(modules="sqlite3, json ,,", filenames=self.path)
        self.assertEqual(src.modules, {"json", "sqlite3"})
        self.assertEqual(src.modules_list, ["json", "sqlite3"])

    def test_blacklist_removes_modules(self):
        src, _ = _make_source(modules="json,sqlite3,os", blacklist="os", filenames=self.path)
        self.assertNotIn("os", src.modules)
        self.assertEqual(src.modules_list, ["json", "sqlite3"])

    def test_star_modules_uses_injected_lister(self):
        # The "*" path builds a discoverer and takes its search_modules() result verbatim,
        # instead of scanning the real interpreter's module set.
        factory = _lister_factory(search={"aaa", "bbb"})
        src, _ = _make_source(modules="*", filenames=self.path, module_lister_factory=factory)
        self.assertEqual(src.modules, {"aaa", "bbb"})
        # The discoverer got the option-derived arguments (self, only_c, site_package, ...).
        args = factory.captured["args"]
        self.assertIs(args[0], src)
        self.assertFalse(args[1])  # only_c
        self.assertTrue(args[2])  # not no_site_packages
        self.assertEqual(factory.captured["kwargs"], {"verbose": False})

    def test_packages_path_merges_discovered_submodules(self):
        # With --packages set, the discoverer's discover_modules() output is unioned in.
        # The trailing empty entries (from "json, ,") are skipped, exercising that guard.
        factory = _lister_factory(discover=[(None, "json.tool", False)])
        src, _ = _make_source(
            modules="json", packages="json, ,", filenames=self.path, module_lister_factory=factory
        )
        self.assertIn("json.tool", src.modules)
        self.assertIn("json", src.modules)


class TestConstructionFilenames(unittest.TestCase):
    def test_explicit_absolute_existing_filenames_accepted(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, path)
        src, _ = _make_source(filenames=path)
        self.assertEqual(src.filenames, [path])

    def test_relative_filename_rejected(self):
        with self.assertRaises(ValueError):
            _make_source(filenames="relative/path.txt")

    def test_nonexistent_filename_rejected(self):
        missing = os.path.join(tempfile.gettempdir(), "fusil-does-not-exist-xyz-12345")
        self.assertFalse(os.path.exists(missing))
        with self.assertRaises(ValueError):
            _make_source(filenames=missing)

    def test_empty_filenames_fall_back_to_fixtures(self):
        # No --filenames -> auto-created throwaway fixture files (redirected to a temp dir).
        fixture_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(fixture_dir, ignore_errors=True))
        old = os.environ.get("FUSIL_FIXTURE_DIR")
        os.environ["FUSIL_FIXTURE_DIR"] = fixture_dir
        self.addCleanup(
            lambda: (
                os.environ.__setitem__("FUSIL_FIXTURE_DIR", old)
                if old is not None
                else os.environ.pop("FUSIL_FIXTURE_DIR", None)
            )
        )
        src, _ = _make_source(filenames="")
        self.assertTrue(src.filenames)
        for path in src.filenames:
            self.assertTrue(os.path.isabs(path))
            self.assertTrue(os.path.exists(path))


class TestPluginManagerDetection(unittest.TestCase):
    def test_plugin_manager_absent_is_none(self):
        src, _ = _make_source()
        self.assertIsNone(src.plugin_manager)

    def test_plugin_manager_picked_up_from_application(self):
        project = FakeProject()
        project.error = lambda *a, **k: None
        sentinel = object()
        project.application().plugin_manager = sentinel
        src = PythonSource(project, _options())
        self.assertIs(src.plugin_manager, sentinel)


class TestLoadModule(unittest.TestCase):
    def test_loads_module_and_builds_writer_via_factory(self):
        factory = _WriterFactory()
        src, _ = _make_source(write_code_factory=factory)
        src.filename = "somewhere/source.py"
        src.loadModule("json")

        import json

        self.assertIs(src.module, json)
        self.assertEqual(src.module_name, "json")
        self.assertIs(src.write, factory.writer)
        # The factory received the parent, filename, module, name and the option-derived flags.
        args, kwargs = factory.calls[-1]
        self.assertIs(args[0], src)
        self.assertEqual(args[1], "somewhere/source.py")
        self.assertIs(args[2], json)
        self.assertEqual(args[3], "json")
        self.assertTrue(kwargs["threads"])
        self.assertTrue(kwargs["_async"])

    def test_dotted_module_name_resolves_submodule(self):
        factory = _WriterFactory()
        src, _ = _make_source(write_code_factory=factory)
        src.loadModule("os.path")
        import os.path as ospath

        self.assertIs(src.module, ospath)
        self.assertEqual(src.module_name, "os.path")
        self.assertIsInstance(src.module, ModuleType)

    def test_builtin_module_without_file_is_loadable(self):
        # A builtin module (no __file__) must load without the missing-attribute lookup raising.
        factory = _WriterFactory()
        src, _ = _make_source(write_code_factory=factory)
        src.loadModule("sys")
        self.assertIs(src.module, sys)
        self.assertIs(src.write, factory.writer)

    def test_thread_and_async_flags_forwarded(self):
        factory = _WriterFactory()
        src, _ = _make_source(write_code_factory=factory, no_threads=True, no_async=True)
        src.loadModule("json")
        _, kwargs = factory.calls[-1]
        self.assertFalse(kwargs["threads"])
        self.assertFalse(kwargs["_async"])


class TestOnSessionStart(unittest.TestCase):
    def _recording_source(self, **opt):
        factory = _WriterFactory()
        src, project = _make_source(
            tmpfile="/tmp/fusil-test-source.py", write_code_factory=factory, **opt
        )
        src.sent: list[tuple] = []
        src.send = lambda event, *a: src.sent.append((event, a))
        return src, factory

    def test_happy_path_generates_and_wires(self):
        src, factory = self._recording_source(modules="json")
        src.on_session_start()
        # source_output_path was set -> used as-is (no session().createFilename()).
        self.assertEqual(src.filename, "/tmp/fusil-test-source.py")
        # The chosen module was announced and the generated source handed downstream.
        self.assertIn(("session_rename", ("json",)), src.sent)
        self.assertIn(("python_source", ("/tmp/fusil-test-source.py",)), src.sent)
        self.assertNotIn("project_stop", [e for e, _ in src.sent])
        # The writer was actually driven exactly once.
        self.assertEqual(factory.writer.generate_calls, 1)

    def test_uses_session_createFilename_without_output_path(self):
        factory = _WriterFactory()
        src, project = _make_source(modules="json", write_code_factory=factory)
        project.session = SimpleNamespace(createFilename=lambda name: "/session/dir/" + name)
        src.sent = []
        src.send = lambda event, *a: src.sent.append((event, a))
        src.on_session_start()
        self.assertEqual(src.filename, "/session/dir/source.py")

    def test_all_modules_unloadable_sends_project_stop(self):
        # A module that cannot be imported is dropped; when none remain the run ends cleanly
        # via project_stop rather than crashing.
        src, factory = self._recording_source(modules="__fusil_no_such_module_xyz__")
        src.on_session_start()
        self.assertEqual(src.modules_list, [])
        self.assertEqual([e for e, _ in src.sent], ["project_stop"])

    def test_restores_sys_modules_after_session(self):
        # on_session_start snapshots sys.modules and restores it, so a module imported only
        # for the session does not leak into the interpreter's module table.
        src, factory = self._recording_source(modules="json")
        marker = "__fusil_test_marker_module__"

        real_module = ModuleType("jsonshim")

        def fake_load(name):
            sys.modules[marker] = ModuleType(marker)  # a "newly imported" module
            src.module = real_module
            src.module_name = name
            src.write = factory("p", "f", real_module, name, threads=True, _async=True)

        src.loadModule = fake_load
        self.assertNotIn(marker, sys.modules)
        src.on_session_start()
        # The session-only module was unloaded during restore.
        self.assertNotIn(marker, sys.modules)
        # ...and the real generate/wire still ran.
        self.assertEqual(factory.writer.generate_calls, 1)


if __name__ == "__main__":
    unittest.main()
