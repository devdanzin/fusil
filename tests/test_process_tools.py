"""Unit tests for fusil.process.tools — process-related utility helpers.

This module holds the small building blocks the fuzzer uses to launch and constrain
child processes: resource-limit setters (``limitMemory``/``limitCpuTime``/...),
process-status formatting (``displayProcessStatus``), command running/locating
(``runCommand``/``locateProgram``), the ASan-target probe (``target_is_asan``), and the
``splitCommand`` tokenizer. It had ~38% coverage, most of it from the ``splitCommand``
doctests wired via ``tests/python/test_doctests.py``.

These tests COMPLEMENT those doctests: they cover the functions and branches the doctests
don't touch (error paths, resource-limit clamping logic, PATH lookup, status formatting)
and add error/edge cases for ``splitCommand`` (antislash, unclosed quotes) rather than
repeating its normal-case doctests.

Mostly runtime-free: the resource/``nice`` primitives are patched at the module level so
no real process limits are changed, and a ``StubLogger`` captures log calls. The handful of
tests that genuinely need a real subprocess (``runCommand``, ``target_is_asan`` against a
real interpreter) are ``@unittest.skipUnless``-guarded on the availability of the required
binary, so they skip gracefully in constrained environments.
"""

import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from fusil.process import tools
from tests.mas_harness import StubLogger

# Guards for the few tests that spawn a real subprocess.
_SH = shutil.which("sh")
_TRUE = shutil.which("true")


class TestSetrlimitLogic(unittest.TestCase):
    """_setrlimit clamps the soft limit to the hard limit and optionally lowers the hard
    limit. getrlimit/setrlimit are patched so no real process limit is touched."""

    def _run(self, getrlimit_return, value, change_hard):
        recorded = {}

        def fake_setrlimit(key, limits):
            recorded["key"] = key
            recorded["limits"] = limits

        with (
            mock.patch.object(tools, "getrlimit", return_value=getrlimit_return),
            mock.patch.object(tools, "setrlimit", side_effect=fake_setrlimit),
        ):
            ret = tools._setrlimit(tools.RLIMIT_CPU, value, change_hard)
        return ret, recorded

    def test_soft_clamped_to_hard_when_value_exceeds_hard(self):
        ret, rec = self._run((100, 200), value=500, change_hard=False)
        self.assertEqual(ret, 200)  # min(500, 200)
        self.assertEqual(rec["limits"], (200, 200))

    def test_soft_used_directly_when_below_hard(self):
        ret, rec = self._run((100, 200), value=50, change_hard=False)
        self.assertEqual(ret, 50)
        self.assertEqual(rec["limits"], (50, 200))  # hard untouched

    def test_unlimited_hard_lets_value_pass_through(self):
        # hard == -1 (RLIM_INFINITY) => value is used verbatim, no clamping.
        ret, rec = self._run((100, -1), value=300, change_hard=False)
        self.assertEqual(ret, 300)
        self.assertEqual(rec["limits"], (300, -1))

    def test_change_hard_lowers_hard_to_new_soft(self):
        ret, rec = self._run((100, 200), value=50, change_hard=True)
        self.assertEqual(ret, 50)
        self.assertEqual(rec["limits"], (50, 50))

    def test_valueerror_from_getrlimit_hits_buggy_except_branch(self):
        # Characterization test (documents a latent bug, see testability notes):
        # when getrlimit raises ValueError, `soft` is never bound, so the final
        # setrlimit((soft, hard)) raises UnboundLocalError rather than degrading
        # gracefully. Pinned here so the behaviour can't change silently.
        with (
            mock.patch.object(tools, "getrlimit", side_effect=ValueError("bad key")),
            mock.patch.object(tools, "setrlimit"),
        ):
            with self.assertRaises((UnboundLocalError, NameError)):
                tools._setrlimit(tools.RLIMIT_CPU, 10, False)


class TestResourceLimitWrappers(unittest.TestCase):
    """The thin wrappers forward the right RLIMIT_* key/value/hard to _setrlimit."""

    def _capture_setrlimit_call(self, call):
        calls = []

        def fake(key, value, change_hard):
            calls.append((key, value, change_hard))
            return value

        with mock.patch.object(tools, "_setrlimit", side_effect=fake):
            ret = call()
        return ret, calls

    def test_limit_memory_targets_rlimit_as(self):
        ret, calls = self._capture_setrlimit_call(lambda: tools.limitMemory(1234, hard=True))
        self.assertEqual(calls, [(tools.RLIMIT_AS, 1234, True)])
        self.assertEqual(ret, 1234)

    def test_limit_memory_defaults_hard_false(self):
        _, calls = self._capture_setrlimit_call(lambda: tools.limitMemory(1234))
        self.assertEqual(calls[0][2], False)

    def test_limit_user_process_targets_rlimit_nproc(self):
        _, calls = self._capture_setrlimit_call(lambda: tools.limitUserProcess(16))
        self.assertEqual(calls[0][0], tools.RLIMIT_NPROC)
        self.assertEqual(calls[0][1], 16)

    def test_limit_cpu_time_rounds_float_up(self):
        _, calls = self._capture_setrlimit_call(lambda: tools.limitCpuTime(2.6))
        self.assertEqual(calls[0], (tools.RLIMIT_CPU, 3, False))  # int(2.6 + 0.5)

    def test_limit_cpu_time_rounds_float_down(self):
        _, calls = self._capture_setrlimit_call(lambda: tools.limitCpuTime(2.4))
        self.assertEqual(calls[0][1], 2)  # int(2.4 + 0.5) == 2

    def test_limit_cpu_time_leaves_int_unchanged(self):
        _, calls = self._capture_setrlimit_call(lambda: tools.limitCpuTime(7))
        self.assertEqual(calls[0][1], 7)

    def test_allow_core_dump_returns_setrlimit_result(self):
        ret, calls = self._capture_setrlimit_call(lambda: tools.allowCoreDump(hard=True))
        self.assertEqual(calls, [(tools.RLIMIT_CORE, -1, True)])
        self.assertEqual(ret, -1)

    def test_allow_core_dump_swallows_exception_and_prints(self):
        with mock.patch.object(tools, "_setrlimit", side_effect=ValueError("boom")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ret = tools.allowCoreDump()
        self.assertIsNone(ret)
        self.assertIn("ValueError: boom", buf.getvalue())


class TestBeNice(unittest.TestCase):
    """beNice passes the right niceness increment to os.nice (patched, not applied)."""

    def test_default_is_moderate(self):
        with mock.patch.object(tools, "nice") as m_nice:
            tools.beNice()
        m_nice.assert_called_once_with(5)

    def test_very_nice_is_higher(self):
        with mock.patch.object(tools, "nice") as m_nice:
            tools.beNice(very_nice=True)
        m_nice.assert_called_once_with(10)


class TestDisplayProcessStatus(unittest.TestCase):
    """Maps an exit status onto the correct log level/message."""

    def test_zero_status_logs_info(self):
        logger = StubLogger()
        tools.displayProcessStatus(logger, 0)
        self.assertEqual(logger.records, [("info", "Process exited normally")])

    def test_negative_status_logs_error_with_signal(self):
        logger = StubLogger()
        tools.displayProcessStatus(logger, -9)
        self.assertEqual(logger.records, [("error", "Process killed by signal 9")])

    def test_positive_status_logs_warning_with_code(self):
        logger = StubLogger()
        tools.displayProcessStatus(logger, 3)
        self.assertEqual(logger.records, [("warning", "Process exited with error code: 3")])

    def test_custom_prefix_is_used(self):
        logger = StubLogger()
        tools.displayProcessStatus(logger, 0, prefix="Child")
        self.assertEqual(logger.records, [("info", "Child exited normally")])


class TestLocateProgram(unittest.TestCase):
    """PATH resolution: absolute/relative shortcuts, PATH scan, and not-found policy."""

    def test_absolute_path_returned_unchanged(self):
        self.assertEqual(tools.locateProgram("/usr/bin/whatever"), "/usr/bin/whatever")

    def test_relative_with_dirname_is_made_absolute(self):
        result = tools.locateProgram("./sub/prog")
        self.assertTrue(os.path.isabs(result))
        self.assertTrue(result.endswith("/sub/prog"))
        self.assertEqual(result, os.path.normpath(os.path.join(os.getcwd(), "./sub/prog")))

    def test_found_in_path(self):
        with tempfile.TemporaryDirectory() as d:
            prog = os.path.join(d, "myprog")
            with open(prog, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(prog, 0o755)
            with mock.patch.dict(os.environ, {"PATH": d}):
                self.assertEqual(tools.locateProgram("myprog"), prog)

    def test_non_executable_in_path_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            prog = os.path.join(d, "myprog")
            with open(prog, "w") as f:
                f.write("data\n")
            os.chmod(prog, stat.S_IRUSR | stat.S_IWUSR)  # readable but not executable
            with mock.patch.dict(os.environ, {"PATH": d}):
                # use_none=False => the bare program name is returned as the default.
                self.assertEqual(tools.locateProgram("myprog"), "myprog")

    def test_not_found_returns_program_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"PATH": d}):
                self.assertEqual(tools.locateProgram("nope_xyz"), "nope_xyz")

    def test_not_found_returns_none_with_use_none(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"PATH": d}):
                self.assertIsNone(tools.locateProgram("nope_xyz", use_none=True))

    def test_not_found_raises_with_raise_error(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"PATH": d}):
                with self.assertRaises(ValueError):
                    tools.locateProgram("nope_xyz", raise_error=True)

    def test_missing_path_env_returns_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(tools.locateProgram("prog"), "prog")
            self.assertIsNone(tools.locateProgram("prog", use_none=True))

    def test_missing_path_env_raises_when_requested(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                tools.locateProgram("prog", raise_error=True)


class TestSplitCommandErrorPaths(unittest.TestCase):
    """Error/edge cases for splitCommand not covered by its doctests."""

    def test_antislash_is_rejected(self):
        with self.assertRaises(SyntaxError):
            tools.splitCommand(r"echo a\b")

    def test_unclosed_quote_is_rejected(self):
        with self.assertRaises(SyntaxError):
            tools.splitCommand("echo 'unterminated")

    def test_empty_command_yields_empty_list(self):
        self.assertEqual(tools.splitCommand(""), [])

    def test_trailing_space_does_not_add_empty_arg(self):
        self.assertEqual(tools.splitCommand("ls "), ["ls"])

    def test_consecutive_spaces_produce_empty_arg(self):
        # Characterization: back-to-back separators emit an empty token.
        self.assertEqual(tools.splitCommand("a  b"), ["a", "", "b"])

    def test_tab_is_treated_as_a_quote_char(self):
        # Characterization (documents a quirk, see testability notes): a tab is in the
        # separator set but only ' ' is handled as whitespace, so a lone tab is parsed
        # as an *opening quote* and left unclosed -> SyntaxError.
        with self.assertRaises(SyntaxError):
            tools.splitCommand("a\tb")


@unittest.skipUnless(_TRUE and _SH, "needs real 'true'/'sh' binaries")
class TestRunCommand(unittest.TestCase):
    """runCommand against trivial real subprocesses (skipped if the binaries are absent)."""

    def test_success_returns_none(self):
        logger = StubLogger()
        self.assertIsNone(tools.runCommand(logger, [_TRUE]))
        # It logs the command it ran.
        self.assertTrue(any(level == "info" for level, _ in logger.records))

    def test_string_command_is_accepted(self):
        # Exercises the isinstance(command, str) repr branch.
        self.assertIsNone(tools.runCommand(StubLogger(), "true"))

    def test_nonzero_exit_raises_runtime_error(self):
        with self.assertRaises(RuntimeError) as cm:
            tools.runCommand(StubLogger(), [_SH, "-c", "exit 3"])
        self.assertIn("exit code 3", str(cm.exception))

    def test_nonzero_exit_returned_when_not_raising(self):
        status = tools.runCommand(StubLogger(), [_SH, "-c", "exit 5"], raise_error=False)
        self.assertEqual(status, 5)

    def test_signal_death_raises_with_signal_message(self):
        with self.assertRaises(RuntimeError) as cm:
            tools.runCommand(StubLogger(), [_SH, "-c", "kill -9 $$"])
        self.assertIn("killed by signal 9", str(cm.exception))

    def test_stdout_false_suppresses_output(self):
        # stdout=False routes stdout/stderr to the null device; command still succeeds.
        self.assertIsNone(tools.runCommand(StubLogger(), [_SH, "-c", "echo hi"], stdout=False))

    def test_stdout_redirected_to_file_object(self):
        # The `stdout is not True` branch: caller supplies a file to write to.
        with tempfile.TemporaryFile() as out:
            tools.runCommand(StubLogger(), [_SH, "-c", "echo captured"], stdout=out)
            out.seek(0)
            self.assertIn(b"captured", out.read())


class TestTargetIsAsan(unittest.TestCase):
    """target_is_asan best-effort probe. lru_cache is cleared between cases."""

    def setUp(self):
        tools.target_is_asan.cache_clear()

    def test_empty_program_is_not_asan(self):
        # The `if not program` short-circuit — no subprocess spawned.
        self.assertFalse(tools.target_is_asan(""))

    def test_bogus_program_is_not_asan(self):
        # Both the CONFIG_ARGS probe and the ldd fallback fail -> False.
        self.assertFalse(tools.target_is_asan("/nonexistent/interpreter/xyz"))

    def test_config_args_reporting_sanitizer_is_detected(self):
        # Patch subprocess.run so the first probe reports a sanitizer build.
        fake = mock.Mock(stdout="--with-address-sanitizer\n")
        with mock.patch.object(tools, "run", return_value=fake) as m_run:
            self.assertTrue(tools.target_is_asan("/some/python"))
        m_run.assert_called_once()  # ldd fallback not reached

    def test_ldd_fallback_detects_asan(self):
        # First probe returns clean config; ldd fallback mentions asan.
        outputs = [mock.Mock(stdout=""), mock.Mock(stdout="libasan.so.6 => ...")]
        with mock.patch.object(tools, "run", side_effect=outputs):
            self.assertTrue(tools.target_is_asan("/some/python"))

    @unittest.skipUnless(os.path.exists(sys.executable), "needs a real interpreter")
    def test_real_interpreter_is_not_asan(self):
        # The dev interpreter is a normal (non-ASan) build; exercises both real probes.
        self.assertFalse(tools.target_is_asan(sys.executable))


if __name__ == "__main__":
    unittest.main()
