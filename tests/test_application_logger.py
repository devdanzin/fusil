"""Unit tests for fusil.application_logger.ApplicationLogger — the dual-sink logger.

ApplicationLogger drives two sinks off the root logger: a terse stdout stream and a verbose
``fusil.log`` file. Its interesting, testable core is ``formatMessage``, which prefixes each
line with ``[nb_success][session][step][agent]`` context assembled from a weakref'd
Application, plus the level-selection logic in ``applyOptions`` and the handler add/remove
bookkeeping. These tests exercise that pure logic directly.

Because the logger mutates the *global* root logger (adds handlers, sets its level) in
``__init__``, every test snapshots the root logger's handlers/level in ``setUp`` and restores
them in ``tearDown`` so the suite has no global side effects. Sinks use ``io.StringIO`` / temp
files; the Application is a minimal weakref-able fake (``types.SimpleNamespace`` is *not*
weakref-able here, so a plain class is used — only the Application is weakref'd, nested
options/project/session stay ``SimpleNamespace``). Runtime-free.
"""

import io
import os
import shutil
import tempfile
import unittest
from logging import (
    CRITICAL,
    DEBUG,
    ERROR,
    INFO,
    WARNING,
    Formatter,
    LogRecord,
    StreamHandler,
    getLogger,
)
from types import SimpleNamespace

from fusil.application_logger import LOG_FILENAME, ApplicationLogger


class _FakeApp:
    """Weakref-able Application stand-in (ApplicationLogger stores ``weakref(application)``).

    A plain class is required because ``types.SimpleNamespace`` instances are not
    weakref-able on this interpreter.
    """

    def __init__(self, options=None, project=None):
        self.options = options
        self.project = project


def _opts(debug=False, verbose=False, quiet=False):
    return SimpleNamespace(debug=debug, verbose=verbose, quiet=quiet)


def _project(session_index=1, nb_success=0, session=None, step=0):
    return SimpleNamespace(
        session_index=session_index,
        nb_success=nb_success,
        session=session,
        step=step,
    )


def _session(name="session-1"):
    return SimpleNamespace(name=name)


def _sender(name="agent"):
    return SimpleNamespace(name=name)


class LoggerTestCase(unittest.TestCase):
    """Base class that snapshots/restores global root-logger state around each test."""

    def setUp(self):
        self._root = getLogger()
        self._orig_handlers = self._root.handlers[:]
        self._orig_level = self._root.level
        self._apps = []  # strong refs so the loggers' weakrefs stay alive

    def tearDown(self):
        # Remove only the handlers this test added; leave any pre-existing ones intact.
        for handler in self._root.handlers[:]:
            if handler not in self._orig_handlers:
                self._root.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    pass
        self._root.setLevel(self._orig_level)

    def make_logger(self, application=None):
        if application is None:
            application = _FakeApp()
        self._apps.append(application)
        return ApplicationLogger(application)

    # -- helpers ---------------------------------------------------------------

    def _tmpfile(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def _enter_tempdir(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        cwd = os.getcwd()
        os.chdir(tmp)
        self.addCleanup(os.chdir, cwd)
        return tmp

    def _close_file_handler(self, logger):
        fh = logger.file_handler
        if fh is not None and not fh.stream.closed:
            fh.stream.close()


class TestInit(LoggerTestCase):
    def test_defaults(self):
        logger = self.make_logger()
        self.assertIsNone(logger.filename)
        self.assertIsNone(logger.file_handler)
        self.assertEqual(logger.timestamp_format, "%(asctime)s: %(message)s")

    def test_stdout_handler_registered_at_error(self):
        logger = self.make_logger()
        self.assertEqual(logger.stdout.level, ERROR)
        self.assertEqual(logger.logger.level, ERROR)
        self.assertIn(logger.stdout, logger.logger.handlers)

    def test_application_stored_as_weakref(self):
        app = _FakeApp()
        logger = self.make_logger(app)
        self.assertIs(logger.application(), app)


class TestFormatMessage(LoggerTestCase):
    def test_no_prefix_without_project(self):
        logger = self.make_logger(_FakeApp(options=_opts(debug=False), project=None))
        self.assertEqual(logger.formatMessage("hello", None), "hello")

    def test_str_coercion_without_prefix(self):
        logger = self.make_logger(_FakeApp(options=_opts(debug=False), project=None))
        self.assertEqual(logger.formatMessage(12345, None), "12345")

    def test_options_none_disables_debug(self):
        # options is falsey -> debug=False, so no [step] and no [agent] even with a project.
        proj = _project(session_index=1, nb_success=4, session=_session("s"), step=9)
        logger = self.make_logger(_FakeApp(options=None, project=proj))
        self.assertEqual(logger.formatMessage("hello", _sender("a")), "[4][s] hello")

    def test_session_prefix_without_debug(self):
        proj = _project(session_index=1, nb_success=7, session=_session("sess"), step=3)
        logger = self.make_logger(_FakeApp(options=_opts(debug=False), project=proj))
        self.assertEqual(logger.formatMessage("hi", None), "[7][sess] hi")

    def test_session_index_zero_skips_project_block(self):
        # session_index falsey -> no [nb][session][step], but debug+sender still adds [agent].
        proj = _project(session_index=0, nb_success=5, session=_session("x"), step=3)
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=proj))
        self.assertEqual(logger.formatMessage("msg", _sender("agent")), "[agent] msg")

    def test_project_without_session_omits_session_name(self):
        proj = _project(session_index=2, nb_success=7, session=None, step=0)
        logger = self.make_logger(_FakeApp(options=_opts(debug=False), project=proj))
        self.assertEqual(logger.formatMessage("hello", None), "[7] hello")

    def test_full_debug_prefix_order(self):
        proj = _project(session_index=1, nb_success=2, session=_session("s1"), step=7)
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=proj))
        self.assertEqual(
            logger.formatMessage("payload", _sender("worker")),
            "[2][s1][step 7][worker] payload",
        )

    def test_step_omitted_when_step_zero(self):
        proj = _project(session_index=1, nb_success=2, session=_session("s1"), step=0)
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=proj))
        self.assertEqual(
            logger.formatMessage("payload", _sender("agent")),
            "[2][s1][agent] payload",
        )

    def test_step_omitted_without_debug_even_when_set(self):
        proj = _project(session_index=1, nb_success=2, session=_session("s1"), step=9)
        logger = self.make_logger(_FakeApp(options=_opts(debug=False), project=proj))
        # debug False -> no [step] and no [agent].
        self.assertEqual(logger.formatMessage("payload", _sender("agent")), "[2][s1] payload")

    def test_sender_prefix_requires_debug(self):
        logger = self.make_logger(_FakeApp(options=_opts(debug=False), project=None))
        self.assertEqual(logger.formatMessage("hi", _sender("agent")), "hi")

    def test_sender_prefix_added_with_debug_and_no_project(self):
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=None))
        self.assertEqual(logger.formatMessage("hi", _sender("agent")), "[agent] hi")

    def test_sender_none_with_debug_adds_nothing(self):
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=None))
        self.assertEqual(logger.formatMessage("hi", None), "hi")

    def test_str_coercion_with_prefix(self):
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=None))
        self.assertEqual(logger.formatMessage(999, _sender("a")), "[a] 999")

    def test_dead_application_returns_plain_message(self):
        # Do NOT keep a strong ref: the weakref should die and formatMessage must degrade
        # gracefully (no prefix, just str-coercion).
        import gc

        app = _FakeApp(options=_opts(debug=True), project=None)
        logger = ApplicationLogger(app)
        del app
        gc.collect()
        self.assertIsNone(logger.application())
        self.assertEqual(logger.formatMessage(42, _sender("agent")), "42")


class TestApplyOptions(LoggerTestCase):
    """applyOptions selects stdout/file/logger levels from debug/verbose/quiet flags."""

    def _apply(self, **flags):
        self._enter_tempdir()  # applyOptions writes ./fusil.log
        logger = self.make_logger(_FakeApp(options=_opts()))
        logger.applyOptions(_opts(**flags))
        self.addCleanup(self._close_file_handler, logger)
        return logger

    def test_debug_levels(self):
        logger = self._apply(debug=True)
        self.assertEqual(logger.stdout.level, INFO)
        self.assertEqual(logger.file_handler.level, DEBUG)
        self.assertEqual(logger.logger.level, DEBUG)  # min(INFO, INFO, DEBUG)

    def test_verbose_levels(self):
        logger = self._apply(verbose=True)
        self.assertEqual(logger.stdout.level, WARNING)
        self.assertEqual(logger.file_handler.level, INFO)
        self.assertEqual(logger.logger.level, INFO)  # min(INFO, WARNING, INFO)

    def test_default_levels(self):
        logger = self._apply()  # not debug/verbose/quiet
        self.assertEqual(logger.stdout.level, ERROR)
        self.assertEqual(logger.file_handler.level, WARNING)
        self.assertEqual(logger.logger.level, INFO)  # min(INFO, ERROR, WARNING)

    def test_quiet_levels(self):
        logger = self._apply(quiet=True)
        self.assertEqual(logger.stdout.level, ERROR)
        self.assertEqual(logger.file_handler.level, INFO)
        self.assertEqual(logger.logger.level, INFO)  # min(INFO, ERROR, INFO)

    def test_creates_log_file(self):
        logger = self._apply(verbose=True)
        self.assertEqual(logger.filename, LOG_FILENAME)
        self.assertTrue(os.path.exists(LOG_FILENAME))


class TestFileHandlers(LoggerTestCase):
    def test_level_none_uses_debug_when_verbose(self):
        logger = self.make_logger(_FakeApp(options=SimpleNamespace(verbose=True)))
        path = self._tmpfile()
        fh = logger.addFileHandler(path)  # level=None -> consults options.verbose
        self.addCleanup(fh.stream.close)
        self.assertEqual(fh.level, DEBUG)
        self.assertIn(fh, logger.logger.handlers)

    def test_level_none_uses_info_when_not_verbose(self):
        logger = self.make_logger(_FakeApp(options=SimpleNamespace(verbose=False)))
        path = self._tmpfile()
        fh = logger.addFileHandler(path)
        self.addCleanup(fh.stream.close)
        self.assertEqual(fh.level, INFO)

    def test_explicit_level_and_registration(self):
        logger = self.make_logger()
        path = self._tmpfile()
        fh = logger.addFileHandler(path, WARNING)
        self.addCleanup(fh.stream.close)
        self.assertEqual(fh.level, WARNING)
        self.assertIn(fh, logger.logger.handlers)

    def test_formatter_uses_timestamp_format(self):
        logger = self.make_logger()
        path = self._tmpfile()
        fh = logger.addFileHandler(path, INFO)
        self.addCleanup(fh.stream.close)
        record = LogRecord("root", INFO, path, 1, "hi", None, None)
        rendered = fh.format(record)
        # timestamp_format == "%(asctime)s: %(message)s" -> "<ts>: hi"
        self.assertTrue(rendered.endswith("hi"))
        self.assertIn(": ", rendered)

    def test_add_handler_returns_sets_level_and_registers(self):
        logger = self.make_logger()
        handler = StreamHandler(io.StringIO())
        returned = logger.addHandler(handler, WARNING)
        self.assertIs(returned, handler)
        self.assertEqual(handler.level, WARNING)
        self.assertIn(handler, logger.logger.handlers)

    def test_remove_file_handler_closes_stream_and_unregisters(self):
        logger = self.make_logger(_FakeApp(options=SimpleNamespace(verbose=False)))
        path = self._tmpfile()
        fh = logger.addFileHandler(path, INFO)
        logger.removeFileHandler(fh)
        self.assertNotIn(fh, logger.logger.handlers)
        self.assertTrue(fh.stream.closed)

    def test_remove_handler_unregisters(self):
        logger = self.make_logger()
        handler = StreamHandler(io.StringIO())
        logger.addHandler(handler, INFO)
        logger.removeHandler(handler)
        self.assertNotIn(handler, logger.logger.handlers)


class TestUnlinkFile(LoggerTestCase):
    def test_unlink_removes_handler_and_file(self):
        self._enter_tempdir()
        logger = self.make_logger(_FakeApp(options=_opts()))
        logger.applyOptions(_opts())  # creates ./fusil.log + file_handler
        self.assertTrue(os.path.exists(LOG_FILENAME))
        logger.unlinkFile()
        self.assertIsNone(logger.file_handler)
        self.assertIsNone(logger.filename)
        self.assertFalse(os.path.exists(LOG_FILENAME))

    def test_unlink_is_noop_when_nothing_configured(self):
        logger = self.make_logger()  # fresh: filename/file_handler are None
        logger.unlinkFile()  # must not raise
        self.assertIsNone(logger.file_handler)
        self.assertIsNone(logger.filename)


class TestLevelMethods(LoggerTestCase):
    def test_log_formats_then_calls_func(self):
        proj = _project(session_index=1, nb_success=3, session=_session("s"), step=0)
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=proj))
        recorded = []
        logger.log(recorded.append, "boom", _sender("w"))
        self.assertEqual(recorded, ["[3][s][w] boom"])

    def test_level_methods_route_to_matching_logger_method(self):
        logger = self.make_logger()  # default app -> no prefix
        calls = []
        logger.logger = SimpleNamespace(
            debug=lambda m: calls.append(("debug", m)),
            info=lambda m: calls.append(("info", m)),
            warning=lambda m: calls.append(("warning", m)),
            error=lambda m: calls.append(("error", m)),
        )
        logger.debug("d", None)
        logger.info("i", None)
        logger.warning("w", None)
        logger.error("e", None)
        self.assertEqual(
            calls,
            [("debug", "d"), ("info", "i"), ("warning", "w"), ("error", "e")],
        )

    def test_end_to_end_error_is_prefixed_and_written(self):
        proj = _project(session_index=1, nb_success=1, session=_session("sess"), step=4)
        logger = self.make_logger(_FakeApp(options=_opts(debug=True), project=proj))
        # Silence the real-stdout sink so the test is quiet; capture via our own StringIO sink.
        logger.stdout.setLevel(CRITICAL)
        sink = io.StringIO()
        handler = StreamHandler(sink)
        handler.setFormatter(Formatter("%(message)s"))
        logger.addHandler(handler, DEBUG)
        logger.logger.setLevel(DEBUG)
        logger.error("kaboom", _sender("worker"))
        self.assertEqual(sink.getvalue().strip(), "[1][sess][step 4][worker] kaboom")


if __name__ == "__main__":
    unittest.main()
