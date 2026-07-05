"""Complementary unit tests for fusil.plugin_manager.PluginManager.

``tests/test_plugin_manager.py`` already covers the instance-dispatcher / class-handler /
blacklist-whitelist / suppression registration surface. This file fills the remaining gaps:
plugin discovery & loading (via an injected fake ``entry_points``), CLI options, argument
generators (weighting, conditions, category filtering, bad-category error), definitions and
scenario providers, fuzzing modes + ``get_active_mode`` arbitration, lifecycle hooks
(including error isolation), dependency/incompatibility declaration and checking, and the
module-level ``get_plugin_manager`` singleton.

Runtime-free: imports only fusil.plugin_manager; entry-point discovery is exercised through
the injectable ``entry_points_func`` parameter (no real installed plugins needed).
"""

import contextlib
import io
import unittest

from fusil import plugin_manager as pm_module
from fusil.plugin_manager import PluginManager, PluginMetadata, get_plugin_manager


class _FakeEP:
    """Minimal importlib.metadata EntryPoint stand-in: a ``name`` and a ``load()`` that
    returns (or raises to simulate an import failure) the plugin's register callable."""

    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


def _eps_func(eps):
    """Build a fake ``entry_points`` accepting the 3.10+ ``group=`` keyword."""

    def fake(group=None):
        return list(eps)

    return fake


@contextlib.contextmanager
def _quiet_stderr():
    """Swallow the manager's stderr diagnostics (print + traceback) during a test."""
    with contextlib.redirect_stderr(io.StringIO()) as buf:
        yield buf


class TestDiscoverAndLoad(unittest.TestCase):
    def test_successful_load_registers_plugin_and_calls_register(self):
        seen = []

        def register(manager):
            seen.append(manager)
            manager.add_cli_option("--demo", action="store_true")

        ep = _FakeEP("demo", lambda: register)
        m = PluginManager()
        with _quiet_stderr():
            m.discover_and_load_plugins(entry_points_func=_eps_func([ep]))

        self.assertIn("demo", m.plugins)
        self.assertIsInstance(m.plugins["demo"], PluginMetadata)
        self.assertEqual(seen, [m])  # register() got the manager
        self.assertEqual(len(m.get_cli_options()), 1)

    def test_load_failure_is_isolated_and_plugin_not_registered(self):
        def boom():
            raise ImportError("no such module")

        ok_calls = []
        good = _FakeEP("good", lambda: lambda mgr: ok_calls.append(mgr))
        bad = _FakeEP("bad", boom)

        m = PluginManager()
        with _quiet_stderr() as buf:
            m.discover_and_load_plugins(entry_points_func=_eps_func([bad, good]))

        # The bad plugin's load() raised before metadata was stored.
        self.assertNotIn("bad", m.plugins)
        # The good plugin still loaded (failure of one does not abort the loop).
        self.assertIn("good", m.plugins)
        self.assertEqual(ok_calls, [m])
        self.assertIn("ERROR loading plugin bad", buf.getvalue())

    def test_register_exception_leaves_metadata_but_is_caught(self):
        def register(manager):
            raise RuntimeError("register blew up")

        ep = _FakeEP("halfbaked", lambda: register)
        m = PluginManager()
        with _quiet_stderr():
            m.discover_and_load_plugins(entry_points_func=_eps_func([ep]))

        # Metadata is stored before register() is invoked, so it survives the failure.
        self.assertIn("halfbaked", m.plugins)

    def test_no_entry_points_is_a_noop(self):
        m = PluginManager()
        with _quiet_stderr():
            m.discover_and_load_plugins(entry_points_func=_eps_func([]))
        self.assertEqual(m.plugins, {})


class TestCliOptions(unittest.TestCase):
    def test_add_and_get_preserve_args_and_kwargs(self):
        m = PluginManager()
        m.add_cli_option("--foo", "-f", action="store_true", help="do foo")
        m.add_cli_option("--bar", default=3)
        opts = m.get_cli_options()
        self.assertEqual(opts[0], (("--foo", "-f"), {"action": "store_true", "help": "do foo"}))
        self.assertEqual(opts[1], (("--bar",), {"default": 3}))


class TestArgumentGenerators(unittest.TestCase):
    def test_invalid_category_raises(self):
        m = PluginManager()
        with self.assertRaises(ValueError):
            m.add_argument_generator(lambda: ["x"], "not-a-category")

    def test_weight_duplicates_generator(self):
        m = PluginManager()

        def gen():
            return ["1"]

        m.add_argument_generator(gen, "simple", weight=3)
        got = m.get_argument_generators(config=None, module_name="mod", category="simple")
        self.assertEqual(got, [gen, gen, gen])

    def test_category_filtering(self):
        m = PluginManager()
        simple = lambda: ["s"]  # noqa: E731
        complex_ = lambda: ["c"]  # noqa: E731
        m.add_argument_generator(simple, "simple")
        m.add_argument_generator(complex_, "complex")
        self.assertEqual(m.get_argument_generators(None, "mod", "simple"), [simple])
        self.assertEqual(m.get_argument_generators(None, "mod", "complex"), [complex_])
        self.assertEqual(m.get_argument_generators(None, "mod", "hashable"), [])

    def test_condition_gates_generator(self):
        m = PluginManager()
        gen = lambda: ["x"]  # noqa: E731
        m.add_argument_generator(gen, "simple", condition=lambda cfg, mod: mod == "wanted")
        self.assertEqual(m.get_argument_generators(None, "wanted", "simple"), [gen])
        self.assertEqual(m.get_argument_generators(None, "other", "simple"), [])


class TestDefinitionsProviders(unittest.TestCase):
    def test_collects_non_empty_definitions_only(self):
        m = PluginManager()
        m.add_definitions_provider(lambda cfg, mod: "import foo")
        m.add_definitions_provider(lambda cfg, mod: None)  # skipped
        m.add_definitions_provider(lambda cfg, mod: "")  # falsy -> skipped
        m.add_definitions_provider(lambda cfg, mod: f"# {mod}")
        self.assertEqual(m.get_definitions(None, "sqlite3"), ["import foo", "# sqlite3"])

    def test_empty_manager_returns_empty_list(self):
        self.assertEqual(PluginManager().get_definitions(None, "mod"), [])


class TestFuzzingModes(unittest.TestCase):
    def test_duplicate_mode_name_raises(self):
        m = PluginManager()
        m.add_fuzzing_mode("oom", lambda cfg: True, lambda w: None)
        with self.assertRaises(ValueError):
            m.add_fuzzing_mode("oom", lambda cfg: False, lambda w: None)

    def test_get_active_mode_none_active(self):
        m = PluginManager()
        m.add_fuzzing_mode("oom", lambda cfg: False, lambda w: None)
        self.assertIsNone(m.get_active_mode(config=object()))

    def test_get_active_mode_single_active(self):
        m = PluginManager()
        m.add_fuzzing_mode("jit", lambda cfg: False, lambda w: None)
        m.add_fuzzing_mode("oom", lambda cfg: True, lambda w: None)
        mode = m.get_active_mode(config=object())
        self.assertEqual(mode.name, "oom")

    def test_get_active_mode_multiple_active_raises(self):
        m = PluginManager()
        m.add_fuzzing_mode("a", lambda cfg: True, lambda w: None)
        m.add_fuzzing_mode("b", lambda cfg: True, lambda w: None)
        with self.assertRaises(ValueError):
            m.get_active_mode(config=object())

    def test_no_modes_returns_none(self):
        self.assertIsNone(PluginManager().get_active_mode(config=object()))


class TestHooks(unittest.TestCase):
    def test_unknown_hook_name_raises_on_add(self):
        m = PluginManager()
        with self.assertRaises(ValueError):
            m.add_hook("midflight", lambda: None)

    def test_run_hooks_invokes_in_order_with_args(self):
        m = PluginManager()
        calls = []
        m.add_hook("startup", lambda *a, **k: calls.append(("first", a, k)))
        m.add_hook("startup", lambda *a, **k: calls.append(("second", a, k)))
        m.run_hooks("startup", 1, key="v")
        self.assertEqual(
            calls,
            [("first", (1,), {"key": "v"}), ("second", (1,), {"key": "v"})],
        )

    def test_run_hooks_unknown_name_is_noop(self):
        m = PluginManager()
        # Must not raise even though 'nope' is not a registered hook bucket.
        m.run_hooks("nope")

    def test_run_hooks_isolates_failing_hook(self):
        m = PluginManager()
        ran = []
        m.add_hook("shutdown", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        m.add_hook("shutdown", lambda: ran.append("after"))
        with _quiet_stderr() as buf:
            m.run_hooks("shutdown")
        # The failing hook is caught and the next hook still runs.
        self.assertEqual(ran, ["after"])
        self.assertIn("ERROR in hook shutdown", buf.getvalue())


class TestDependencies(unittest.TestCase):
    def test_declare_dependency_attaches_to_last_plugin(self):
        m = PluginManager()
        m.plugins["foo"] = PluginMetadata(name="foo", entry_point=None)
        m.declare_dependency("bar", "1.2")
        m.declare_dependency("baz")  # no version
        self.assertEqual(m.plugins["foo"].dependencies, ["bar@1.2", "baz"])

    def test_declare_dependency_without_plugins_is_noop(self):
        m = PluginManager()
        m.declare_dependency("bar")  # nothing loaded -> silently ignored
        self.assertEqual(m.plugins, {})

    def test_declare_incompatibility_attaches_to_last_plugin(self):
        m = PluginManager()
        m.plugins["foo"] = PluginMetadata(name="foo", entry_point=None)
        m.declare_incompatibility("rival")
        self.assertEqual(m.plugins["foo"].incompatibilities, ["rival"])

    def test_check_dependencies_reports_missing(self):
        m = PluginManager()
        m.plugins["a"] = PluginMetadata("a", None, dependencies=["missing@9.9"])
        errors = m.check_dependencies()
        self.assertEqual(len(errors), 1)
        self.assertIn("requires 'missing'", errors[0])

    def test_check_dependencies_satisfied(self):
        m = PluginManager()
        m.plugins["dep"] = PluginMetadata("dep", None)
        m.plugins["a"] = PluginMetadata("a", None, dependencies=["dep@1.0"])
        self.assertEqual(m.check_dependencies(), [])

    def test_check_dependencies_reports_incompatibility(self):
        m = PluginManager()
        m.plugins["a"] = PluginMetadata("a", None, incompatibilities=["b"])
        m.plugins["b"] = PluginMetadata("b", None)
        errors = m.check_dependencies()
        self.assertEqual(len(errors), 1)
        self.assertIn("incompatible with 'b'", errors[0])


class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        self._saved = pm_module._plugin_manager
        pm_module._plugin_manager = None

    def tearDown(self):
        pm_module._plugin_manager = self._saved

    def test_returns_same_instance(self):
        a = get_plugin_manager()
        b = get_plugin_manager()
        self.assertIs(a, b)
        self.assertIsInstance(a, PluginManager)


if __name__ == "__main__":
    unittest.main()
