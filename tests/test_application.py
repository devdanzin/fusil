"""Unit tests for fusil.application.Application — the top application agent.

Application parses the CLI/config, sets up logging + the MAS, and drives the project
lifecycle. Its ``__init__`` has heavy side effects (plugin discovery, argv parsing, MAS
construction), so these tests exercise the individual methods on a bare instance
(``Application.__new__``) with just the attributes each method touches, mocking the
OS/identity calls (getuid/getpwnam/input/...) and the MAS classes. Runtime-free apart from
the python-ptrace import guard (the module imports ptrace.error at load).
"""

import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

try:
    from fusil.application import Application, formatLimit
    from fusil.config import ConfigError, FusilConfig
    from fusil.mas.agent_list import AgentList

    HAVE_APP = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_APP = False

if HAVE_APP:
    from tests.mas_harness import StubLogger


def _bare_app(**attrs):
    """An Application with no __init__ side effects; error/warning route to a StubLogger."""
    app = Application.__new__(Application)
    app.logger = StubLogger()
    app.exitcode = 0
    app.interrupted = False
    for key, value in attrs.items():
        setattr(app, key, value)
    return app


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestInit(unittest.TestCase):
    def test_init_loads_plugins_and_runs_startup_hook(self):
        def fake_setup(self):
            self.options = SimpleNamespace()

        pm = mock.Mock()
        pm.check_dependencies.return_value = []
        with (
            mock.patch("fusil.plugin_manager.get_plugin_manager", return_value=pm),
            mock.patch.object(Application, "setup", fake_setup),
        ):
            app = Application()
        self.assertIs(app.plugin_manager, pm)
        pm.discover_and_load_plugins.assert_called_once()
        pm.run_hooks.assert_called_once_with("startup", app.options)

    def test_init_reports_plugin_dependency_errors(self):
        def fake_setup(self):
            self.options = SimpleNamespace()

        pm = mock.Mock()
        pm.check_dependencies.return_value = ["plugin X needs Y"]
        with (
            mock.patch("fusil.plugin_manager.get_plugin_manager", return_value=pm),
            mock.patch.object(Application, "setup", fake_setup),
            redirect_stdout(io.StringIO()),
        ):
            # The dependency errors are printed to stderr but must not abort construction.
            app = Application()
        self.assertIs(app.plugin_manager, pm)


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestFormatLimit(unittest.TestCase):
    def test_positive_is_str(self):
        self.assertEqual(formatLimit(5), "5")

    def test_zero_or_negative_is_unlimited(self):
        self.assertEqual(formatLimit(0), "unlimited")
        self.assertEqual(formatLimit(-1), "unlimited")


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestAgentRegistration(unittest.TestCase):
    def test_register_and_unregister(self):
        app = _bare_app(agents=AgentList())
        agent = SimpleNamespace(deactivate=lambda: None, unregister=lambda destroy=True: None)
        app.registerAgent(agent)
        self.assertIn(agent, app.agents)
        app.unregisterAgent(agent)
        self.assertNotIn(agent, app.agents)

    def test_unregister_unknown_is_noop(self):
        app = _bare_app(agents=AgentList())
        app.unregisterAgent(SimpleNamespace())  # not registered -> silently ignored


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestProcessOptions(unittest.TestCase):
    def _app(self, nb_arguments):
        app = _bare_app()
        app.NB_ARGUMENTS = nb_arguments
        return app

    def test_fixed_count_ok(self):
        # Correct count -> no exit.
        self._app(0).processOptions(mock.Mock(), SimpleNamespace(), [])

    def test_fixed_count_wrong_exits(self):
        app = self._app(2)
        parser = mock.Mock()
        with self.assertRaises(SystemExit):
            app.processOptions(parser, SimpleNamespace(), ["only-one"])
        parser.print_help.assert_called_once()

    def test_range_within_bounds_ok(self):
        self._app((1, 3)).processOptions(mock.Mock(), SimpleNamespace(), ["a", "b"])

    def test_range_below_min_exits(self):
        with self.assertRaises(SystemExit):
            self._app((2, 4)).processOptions(mock.Mock(), SimpleNamespace(), ["a"])

    def test_range_open_max_ok(self):
        # (min, None) only checks the minimum.
        self._app((1, None)).processOptions(mock.Mock(), SimpleNamespace(), ["a"] * 9)


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestParseOptions(unittest.TestCase):
    def _run(self, argv, **opt_overrides):
        opts = SimpleNamespace(
            version=False,
            quiet=False,
            debug=False,
            verbose=False,
            force_unsafe=False,
            unsafe=False,
        )
        for k, v in opt_overrides.items():
            setattr(opts, k, v)
        parser = mock.Mock()
        parser.parse_args.return_value = (opts, argv)
        app = _bare_app()
        app.NB_ARGUMENTS = (0, None)
        app.createOptionParser = lambda: parser
        with redirect_stdout(io.StringIO()):
            app.parseOptions()
        return app

    def test_version_prints_and_exits(self):
        parser = mock.Mock()
        parser.parse_args.return_value = (SimpleNamespace(version=True), [])
        app = _bare_app()
        app.createOptionParser = lambda: parser
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()):
            app.parseOptions()

    def test_quiet_disables_debug_and_verbose(self):
        app = self._run([], quiet=True, debug=True, verbose=True)
        self.assertFalse(app.options.debug)
        self.assertFalse(app.options.verbose)

    def test_debug_implies_verbose(self):
        app = self._run([], debug=True)
        self.assertTrue(app.options.verbose)

    def test_force_unsafe_enables_unsafe(self):
        app = self._run([], force_unsafe=True)
        self.assertTrue(app.options.unsafe)


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestProcessConfig(unittest.TestCase):
    def _app(self, *, unsafe=False, force_unsafe=False, user=None, group=None):
        config = FusilConfig()
        config.process_user = user
        config.process_group = group
        app = _bare_app(
            config=config,
            options=SimpleNamespace(unsafe=unsafe, force_unsafe=force_unsafe),
        )
        app.safetyWarning = lambda: None  # exercised separately
        return app

    def test_unsafe_clears_user_and_group(self):
        app = self._app(unsafe=True, user="fusil", group="fusil")
        app.processConfig()
        self.assertIsNone(app.config.process_user)
        self.assertIsNone(app.config.process_group)

    def test_numeric_user_and_group_resolved(self):
        app = self._app(user="123", group="456")
        with (
            mock.patch("fusil.application.getpwuid", return_value=SimpleNamespace(pw_name="bob")),
            mock.patch("fusil.application.getgrgid", return_value=SimpleNamespace(gr_name="grp")),
        ):
            app.processConfig()
        self.assertEqual(app.config.process_uid, 123)
        self.assertEqual(app.config.process_gid, 456)

    def test_named_user_resolved(self):
        app = self._app(user="alice")
        with mock.patch("fusil.application.getpwnam", return_value=SimpleNamespace(pw_uid=1001)):
            app.processConfig()
        self.assertEqual(app.config.process_uid, 1001)

    def test_unknown_user_raises_config_error(self):
        app = self._app(user="ghost")
        with mock.patch("fusil.application.getpwnam", side_effect=KeyError):
            with self.assertRaises(ConfigError):
                app.processConfig()

    def test_unknown_group_raises_config_error(self):
        app = self._app(group="ghost")
        with mock.patch("fusil.application.getgrnam", side_effect=KeyError):
            with self.assertRaises(ConfigError):
                app.processConfig()

    def test_force_unsafe_emits_second_warning(self):
        app = self._app(force_unsafe=True)
        app.processConfig()
        self.assertTrue(any("force-unsafe" in msg for _lvl, msg in app.logger.records))


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestSetup(unittest.TestCase):
    def test_setup_orchestrates_subsystems(self):
        app = Application.__new__(Application)

        def fake_parse():
            app.options = SimpleNamespace(fast=False)

        app.parseOptions = fake_parse
        app.processConfig = mock.Mock()
        app.createMAS = mock.Mock()
        with (
            mock.patch("fusil.application.ApplicationLogger") as m_log,
            mock.patch(
                "fusil.application.FusilConfig", return_value=SimpleNamespace(fusil_max_memory=0)
            ),
            mock.patch("fusil.application.beNice") as m_nice,
        ):
            app.setup()
        m_log.assert_called_once()
        m_nice.assert_called_once_with(True)  # not --fast -> be nice
        app.processConfig.assert_called_once()
        app.createMAS.assert_called_once()
        self.assertEqual(app.exitcode, 0)


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestSafetyWarning(unittest.TestCase):
    def _app(self, *, uid, gid, unsafe=False, force_unsafe=False):
        config = SimpleNamespace(process_uid=uid, process_gid=gid, filename="/etc/fusil.conf")
        return _bare_app(
            config=config, options=SimpleNamespace(unsafe=unsafe, force_unsafe=force_unsafe)
        )

    def test_returns_immediately_when_uid_and_gid_set(self):
        # No warning, no prompt when both identities are configured.
        app = self._app(uid=1000, gid=1000)
        app.safetyWarning()
        self.assertEqual(app.logger.records, [])

    def test_force_unsafe_non_root_skips(self):
        app = self._app(uid=None, gid=None, force_unsafe=True)
        with mock.patch("fusil.application.getuid", return_value=1000):
            app.safetyWarning()
        self.assertEqual(app.logger.records, [])

    def test_confirm_yes_continues(self):
        app = self._app(uid=None, gid=1000)
        with (
            mock.patch("fusil.application.getuid", return_value=1000),
            mock.patch("fusil.application.getgid", return_value=1000),
            mock.patch("builtins.input", return_value="yes"),
        ):
            app.safetyWarning()  # must not call fatalError

    def test_confirm_no_triggers_fatal_error(self):
        app = self._app(uid=None, gid=1000)
        app.fatalError = mock.Mock()
        with (
            mock.patch("fusil.application.getuid", return_value=1000),
            mock.patch("fusil.application.getgid", return_value=1000),
            mock.patch("builtins.input", return_value="no"),
        ):
            app.safetyWarning()
        app.fatalError.assert_called_once()

    def test_eof_declines(self):
        app = self._app(uid=None, gid=1000)
        app.fatalError = mock.Mock()
        with (
            mock.patch("fusil.application.getuid", return_value=1000),
            mock.patch("fusil.application.getgid", return_value=1000),
            mock.patch("builtins.input", side_effect=EOFError),
            redirect_stdout(io.StringIO()),
        ):
            app.safetyWarning()
        app.fatalError.assert_called_once()


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestCreateMAS(unittest.TestCase):
    def _run(self, *, fast, slow):
        # A plain list stands in for AgentList here (createMAS only calls append) so its
        # __del__ won't later try to deactivate this bare, never-activated app.
        app = _bare_app(agents=[], options=SimpleNamespace(fast=fast, slow=slow))
        app.setupMTA = lambda mta, logger: None
        app.activate = lambda: None
        with (
            mock.patch("fusil.application.MTA"),
            mock.patch("fusil.application.Univers") as m_univ,
        ):
            app.createMAS()
        return m_univ.call_args[0][2]  # step_sleep

    def test_fast_step_sleep(self):
        self.assertEqual(self._run(fast=True, slow=False), 0.001)

    def test_default_step_sleep(self):
        self.assertEqual(self._run(fast=False, slow=False), 0.010)

    def test_slow_step_sleep(self):
        self.assertEqual(self._run(fast=False, slow=True), 0.050)


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestLifecycle(unittest.TestCase):
    def test_interrupt_sets_flag_and_logs(self):
        app = _bare_app()
        app.interrupt("stop!")
        self.assertTrue(app.interrupted)
        self.assertTrue(any("stop!" in msg for _lvl, msg in app.logger.records))

    def test_exit_runs_shutdown_hook_and_drops_config(self):
        pm = mock.Mock()
        app = _bare_app(
            plugin_manager=pm,
            agents=AgentList(),
            mta=object(),
            univers=object(),
            config=object(),
            logger=mock.Mock(filename=None),
        )
        app.exit(keep_log=True)
        pm.run_hooks.assert_called_once_with("shutdown")
        self.assertIsNone(app.config)

    def test_exit_without_keep_log_unlinks(self):
        logger = mock.Mock(filename="/tmp/x.log")
        app = _bare_app(plugin_manager=None, agents=AgentList(), config=object(), logger=logger)
        app.exit(keep_log=False)
        logger.unlinkFile.assert_called_once()

    def test_fatal_error_sets_exitcode_and_exits(self):
        app = _bare_app()
        app.exit = mock.Mock()
        with self.assertRaises(SystemExit):
            app.fatalError("boom")
        self.assertEqual(app.exitcode, 1)
        app.exit.assert_called_once_with(keep_log=False)

    def test_setup_project_is_abstract(self):
        with self.assertRaises(NotImplementedError):
            _bare_app().setupProject()

    def test_on_application_interrupt_sends_univers_stop(self):
        app = _bare_app()
        app.send = mock.Mock()
        app.on_application_interrupt()
        app.send.assert_called_once_with("univers_stop")


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestRunProjectAndMain(unittest.TestCase):
    def test_run_project_destroys_even_on_error(self):
        app = _bare_app(agents=AgentList())
        project = mock.Mock()
        app.setupProject = mock.Mock(side_effect=RuntimeError("bad wiring"))
        with mock.patch("fusil.application.Project", return_value=project):
            with self.assertRaises(RuntimeError):
                app.runProject()
        project.destroy.assert_called_once()
        self.assertIsNone(app.project)

    def test_main_without_exit_swallows_keyboard_interrupt(self):
        app = _bare_app()
        app.runProject = mock.Mock(side_effect=KeyboardInterrupt)
        app.main(exit_at_end=False)
        self.assertTrue(app.interrupted)

    def test_execute_project_activates_and_deactivates(self):
        app = _bare_app(options=SimpleNamespace(profiler=False))
        project = mock.Mock()
        app.project = project
        app.univers = mock.Mock()
        app.executeProject()
        project.activate.assert_called_once()
        app.univers.execute.assert_called_once_with(project)
        project.deactivate.assert_called_once()

    def test_execute_project_handles_keyboard_interrupt(self):
        app = _bare_app(options=SimpleNamespace(profiler=False))
        app.project = mock.Mock()
        app.univers = mock.Mock()
        app.univers.execute.side_effect = KeyboardInterrupt
        app.executeProject()
        self.assertTrue(app.interrupted)
        app.project.deactivate.assert_called_once()  # still deactivated

    def test_run_project_success_path(self):
        app = _bare_app(agents=AgentList())
        project = mock.Mock()
        app.setupProject = mock.Mock()
        app.executeProject = mock.Mock()
        with mock.patch("fusil.application.Project", return_value=project):
            app.runProject()
        app.setupProject.assert_called_once()
        app.executeProject.assert_called_once()
        project.destroy.assert_called_once()
        self.assertIsNone(app.project)

    def test_run_project_destroy_error_is_swallowed(self):
        app = _bare_app(agents=AgentList())
        project = mock.Mock()
        project.destroy.side_effect = RuntimeError("boom")
        app.setupProject = mock.Mock()
        app.executeProject = mock.Mock()
        with (
            mock.patch("fusil.application.Project", return_value=project),
            mock.patch("fusil.application.writeError") as m_we,
        ):
            app.runProject()  # the destroy error must not escape
        m_we.assert_called()
        self.assertIsNone(app.project)

    def test_main_with_exit_calls_exit_and_raises_systemexit(self):
        app = _bare_app()
        app.runProject = mock.Mock()
        app.exit = mock.Mock()
        with self.assertRaises(SystemExit):
            app.main(exit_at_end=True)
        app.exit.assert_called_once()


@unittest.skipUnless(HAVE_APP, "fusil runtime stack (python-ptrace) not importable")
class TestCreateOptionParser(unittest.TestCase):
    def test_parser_has_core_options(self):
        app = _bare_app(config=FusilConfig())
        app.createFuzzerOptions = lambda parser: None
        parser = app.createOptionParser()
        opt_strings = {
            opt.get_opt_string() for group in parser.option_groups for opt in group.option_list
        }
        opt_strings |= {opt.get_opt_string() for opt in parser.option_list}
        for expected in ("--version", "--success", "--sessions", "--fast", "--unsafe", "--debug"):
            self.assertIn(expected, opt_strings)


if __name__ == "__main__":
    unittest.main()
