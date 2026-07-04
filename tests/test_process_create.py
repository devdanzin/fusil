"""Unit tests for fusil.process.create -- CreateProcess, the ProjectAgent that builds,
launches and monitors the fuzzed child.

CreateProcess owns the whole child lifecycle: assemble the command line + environment,
validate arguments, spawn via Popen (with the prepareProcess preexec_fn), poll for exit,
enforce the wall-clock timeout, and SIGKILL + reap on teardown. Almost none of this was
covered directly.

Runtime-free: a real MTA-backed FakeProject constructs the agent; ``send`` is intercepted
so emitted events (``process_create`` / ``process_exit`` / ``session_rename``) are captured;
and every OS-level call (Popen, os.kill, time.sleep/time, locateProgram, the replay-script
writer) is mocked, so nothing is forked, killed, or slept on. CreateProcess imports
python-ptrace (``ptrace.signames``), so the tests skip-guard on that import.
"""

import os
import tempfile
import unittest
from errno import EACCES, ENOENT
from types import SimpleNamespace
from unittest.mock import patch

from tests.mas_harness import FakeProject

try:
    from fusil.process import create
    from fusil.process.create import (
        DEFAULT_TIMEOUT,
        ChildError,
        CommandLine,
        CreateProcess,
        Environment,
        ProcessError,
        ProjectProcess,
        terminateProcess,
    )

    HAVE_CREATE = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_CREATE = False


# --------------------------------------------------------------------------- helpers
def _config(**kw):
    defaults = dict(
        process_max_memory=1000,
        process_max_user_process=0,
        process_core_dump=False,
        process_uid=None,
        process_gid=None,
        process_user=None,
        fusil_max_memory=0,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _options(**kw):
    defaults = dict(no_memory_limit=False, stdout_path=None, unsafe=True, fast=True)
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class _FakePopen:
    """Popen stand-in exposing pid + a scriptable poll()."""

    def __init__(self, pid=999, poll_status=None):
        self.pid = pid
        self._poll_status = poll_status
        self.poll_calls = 0

    def poll(self):
        self.poll_calls += 1
        return self._poll_status


def _make(
    *,
    arguments=None,
    options=None,
    config=None,
    stdout="file",
    stdin=False,
    timeout=DEFAULT_TIMEOUT,
    name=None,
    with_session=True,
    asan=False,
    cls=CreateProcess,
):
    """Build an initialized CreateProcess (or subclass) with a stubbed project/session.

    ``send`` is captured into ``.sent`` (list of (event, args)); target_is_asan is patched
    off so the constructor never shells out to probe the interpreter. Returns (agent, project);
    the project is returned so its weakref stays alive for the test.
    """
    project = FakeProject()
    project.config = config if config is not None else _config()
    opts = options if options is not None else _options()

    if with_session:
        tmpdir = tempfile.mkdtemp()

        def _rm():
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

        project._tmpdir = tmpdir
        project.session = SimpleNamespace(
            directory=SimpleNamespace(directory=tmpdir),
            createFilename=lambda name: os.path.join(tmpdir, name),
        )

    with patch.object(create, "target_is_asan", return_value=asan):
        agent = cls(
            project,
            opts,
            arguments=arguments,
            stdout=stdout,
            stdin=stdin,
            timeout=timeout,
            name=name,
        )
    agent.init()
    agent.sent = []
    agent.send = lambda event, *args: agent.sent.append((event, args))
    return agent, project


# =========================================================================== module-level
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestTerminateProcess(unittest.TestCase):
    def test_sends_sigkill_to_pid(self):
        with patch.object(create, "kill") as kill:
            terminateProcess(SimpleNamespace(pid=4242))
        kill.assert_called_once_with(4242, create.SIGKILL)


# =========================================================================== construction
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestConstruction(unittest.TestCase):
    def test_name_derived_from_argument_basename(self):
        agent, _ = _make(arguments=["/usr/bin/python3", "-c", "pass"])
        self.assertEqual(agent.name, "process:python3")

    def test_explicit_name_used(self):
        agent, _ = _make(arguments=["/usr/bin/python3"], name="myproc")
        self.assertEqual(agent.name, "myproc")

    def test_string_arguments_are_split(self):
        agent, _ = _make(arguments="python -c pass", name="p")
        self.assertEqual(agent.createArguments(), ["python", "-c", "pass"])

    def test_none_arguments_with_name_gives_empty_cmdline(self):
        agent, _ = _make(arguments=None, name="p")
        self.assertEqual(agent.createArguments(), [])

    def test_env_and_cmdline_agents_created(self):
        agent, _ = _make(arguments=["python"], name="p")
        self.assertIsInstance(agent.env, Environment)
        self.assertIsInstance(agent.cmdline, CommandLine)

    def test_popen_args_defaults(self):
        agent, _ = _make(arguments=["python"], name="p")
        self.assertEqual(agent.popen_args["stderr"], create.STDOUT)
        self.assertTrue(agent.popen_args["close_fds"])

    def test_timeout_and_stdout_stored(self):
        agent, _ = _make(arguments=["python"], name="p", timeout=3.5, stdout="null")
        self.assertEqual(agent.timeout, 3.5)
        self.assertEqual(agent.stdout, "null")

    def test_max_memory_from_config(self):
        agent, _ = _make(arguments=["python"], name="p", config=_config(process_max_memory=777))
        self.assertEqual(agent.max_memory, 777)

    def test_max_memory_zeroed_with_no_memory_limit(self):
        agent, _ = _make(
            arguments=["python"],
            name="p",
            options=_options(no_memory_limit=True),
            config=_config(process_max_memory=777),
        )
        self.assertEqual(agent.max_memory, 0)

    def test_max_memory_zeroed_for_asan_target(self):
        agent, _ = _make(
            arguments=["python"], name="p", asan=True, config=_config(process_max_memory=777)
        )
        self.assertEqual(agent.max_memory, 0)

    def test_max_memory_kept_for_normal_target(self):
        agent, _ = _make(
            arguments=["python"], name="p", asan=False, config=_config(process_max_memory=777)
        )
        self.assertEqual(agent.max_memory, 777)


# =========================================================================== init
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestWorkingDirectory(unittest.TestCase):
    def test_working_directory_from_session(self):
        agent, project = _make(arguments=["python"], name="p")
        self.assertEqual(agent.getWorkingDirectory(), project._tmpdir)

    def test_prepare_process_delegates_to_module_function(self):
        # The preexec_fn wrapper forwards self to prepare.prepareProcess.
        agent, _ = _make(arguments=["python"], name="p")
        with patch.object(create, "prepareProcess") as pp:
            agent.prepareProcess()
        pp.assert_called_once_with(agent)


@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestInit(unittest.TestCase):
    def test_init_resets_state(self):
        agent, _ = _make(arguments=["python"], name="p", options=_options(stdout_path="/tmp/out"))
        agent.score = 0.9
        agent.process = object()
        agent.timeout_reached = True
        agent.init()
        self.assertIsNone(agent.score)
        self.assertIsNone(agent.process)
        self.assertFalse(agent.timeout_reached)
        self.assertIsNone(agent.status)
        self.assertTrue(agent.show_exit)
        self.assertFalse(agent.wrote_replay)
        # stdout_file seeds from options.stdout_path.
        self.assertEqual(agent.stdout_file, "/tmp/out")


# =========================================================================== checkArguments
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCheckArguments(unittest.TestCase):
    def test_valid_str_and_bytes_pass(self):
        # Should not raise.
        CreateProcess.checkArguments(["python", b"-c", "pass"])

    def test_nul_byte_in_str_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            CreateProcess.checkArguments(["python", "a\0b"])
        self.assertIn("nul byte", str(ctx.exception))

    def test_nul_byte_in_bytes_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            CreateProcess.checkArguments([b"a\0b"])
        self.assertIn("nul byte", str(ctx.exception))

    def test_non_string_argument_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            CreateProcess.checkArguments(["python", 123])
        self.assertIn("not a byte or unicode string", str(ctx.exception))

    def test_index_reported_in_error(self):
        with self.assertRaises(ValueError) as ctx:
            CreateProcess.checkArguments(["ok", "ok2", "bad\0"])
        self.assertIn("argument 2", str(ctx.exception))


# =========================================================================== createArguments
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCreateArguments(unittest.TestCase):
    def test_returns_fresh_copy(self):
        agent, _ = _make(arguments=["python", "-c"], name="p")
        first = agent.createArguments()
        first.append("mutated")
        # Mutating the returned list must not affect subsequent calls.
        self.assertEqual(agent.createArguments(), ["python", "-c"])


# =========================================================================== createStdin/out
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCreateStdin(unittest.TestCase):
    def test_stdin_true_returns_none(self):
        agent, _ = _make(arguments=["python"], name="p", stdin=True)
        self.assertIsNone(agent.createStdin())

    def test_stdin_false_opens_devnull(self):
        agent, _ = _make(arguments=["python"], name="p", stdin=False)
        f = agent.createStdin()
        self.addCleanup(f.close)
        self.assertFalse(f.closed)


@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCreateStdout(unittest.TestCase):
    def test_invalid_stdout_type_rejected(self):
        agent, _ = _make(arguments=["python"], name="p", stdout="pipe")
        with self.assertRaises(ValueError):
            agent.createStdout()

    def test_null_stdout_opens_devnull_no_event(self):
        agent, _ = _make(arguments=["python"], name="p", stdout="null")
        f = agent.createStdout()
        self.addCleanup(f.close)
        # "null" mode does not announce a stdout filename.
        self.assertEqual(agent.sent, [])

    def test_file_stdout_uses_session_filename_and_emits_event(self):
        agent, project = _make(arguments=["python"], name="p", stdout="file")
        f = agent.createStdout()
        self.addCleanup(f.close)
        expected = os.path.join(project._tmpdir, "stdout")
        self.assertTrue(os.path.exists(expected))
        self.assertIn(("process_stdout", (agent, expected)), agent.sent)

    def test_file_stdout_honours_preset_stdout_file(self):
        preset = os.path.join(tempfile.mkdtemp(), "custom_out")
        self.addCleanup(lambda: os.path.exists(preset) and os.unlink(preset))
        agent, _ = _make(
            arguments=["python"], name="p", stdout="file", options=_options(stdout_path=preset)
        )
        f = agent.createStdout()
        self.addCleanup(f.close)
        self.assertIn(("process_stdout", (agent, preset)), agent.sent)


# =========================================================================== createPopenArguments
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCreatePopenArguments(unittest.TestCase):
    def test_builds_env_stdout_and_preexec(self):
        agent, _ = _make(arguments=["python"], name="p", stdin=True)
        popen_args = agent.createPopenArguments()
        self.addCleanup(agent.closeStreams)
        self.assertIsInstance(popen_args["env"], dict)
        self.assertIsInstance(popen_args["stdout"], int)  # a real fileno
        self.assertEqual(popen_args["preexec_fn"], agent.prepareProcess)
        # stdin=True -> no stdin redirect key.
        self.assertNotIn("stdin", popen_args)

    def test_stdin_redirect_added_when_stdin_false(self):
        agent, _ = _make(arguments=["python"], name="p", stdin=False)
        popen_args = agent.createPopenArguments()
        self.addCleanup(agent.closeStreams)
        self.assertIn("stdin", popen_args)

    def test_home_rewritten_for_fuzzer_uid(self):
        agent, _ = _make(
            arguments=["python"], name="p", stdin=True, config=_config(process_uid=1234)
        )
        agent.env.copy("HOME")
        with (
            patch.dict(os.environ, {"HOME": "/root"}),
            patch.object(create, "getpwuid", return_value=SimpleNamespace(pw_dir="/home/fuzz")),
        ):
            popen_args = agent.createPopenArguments()
        self.addCleanup(agent.closeStreams)
        self.assertEqual(popen_args["env"]["HOME"], "/home/fuzz")

    def test_home_not_rewritten_without_uid(self):
        agent, _ = _make(
            arguments=["python"], name="p", stdin=True, config=_config(process_uid=None)
        )
        agent.env.copy("HOME")
        with patch.dict(os.environ, {"HOME": "/root"}):
            popen_args = agent.createPopenArguments()
        self.addCleanup(agent.closeStreams)
        self.assertEqual(popen_args["env"]["HOME"], "/root")


# =========================================================================== writeReplayScripts
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestWriteReplayScripts(unittest.TestCase):
    def test_writes_once_only(self):
        agent, _ = _make(arguments=["python"], name="p")
        with patch.object(create, "createReplayPythonScript") as writer:
            agent.writeReplayScripts(["python"], {})
            agent.writeReplayScripts(["python"], {})
        writer.assert_called_once()
        self.assertTrue(agent.wrote_replay)


# =========================================================================== createProcess
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCreateProcess(unittest.TestCase):
    def _prep(self, agent, popen):
        """Stub out the heavy collaborators of createProcess, leaving its own logic live."""
        agent.createArguments = lambda: ["python", "-c", "pass"]
        agent.createPopenArguments = lambda: {"env": {}}
        agent.writeReplayScripts = lambda a, p: None
        agent._closed = []
        agent.closeStreams = lambda: agent._closed.append(True)

    def test_success_spawns_and_emits_process_create(self):
        agent, _ = _make(arguments=["python"], name="p")
        fake = _FakePopen(pid=555)
        self._prep(agent, fake)
        with (
            patch.object(create, "locateProgram", return_value="/usr/bin/python") as locate,
            patch.object(create, "Popen", return_value=fake) as popen,
            patch.object(create, "time", return_value=100.0),
        ):
            agent.createProcess()
        locate.assert_called_once_with("python", raise_error=True)
        popen.assert_called_once()
        self.assertIs(agent.process, fake)
        self.assertEqual(agent.current_arguments[0], "/usr/bin/python")
        self.assertIn(("process_create", (agent,)), agent.sent)
        self.assertEqual(agent._closed, [True])

    def test_nul_byte_argument_raises_before_spawn(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.createArguments = lambda: ["python", "bad\0arg"]
        with patch.object(create, "Popen") as popen:
            with self.assertRaises(ValueError):
                agent.createProcess()
        popen.assert_not_called()

    def test_enoent_becomes_process_error(self):
        agent, _ = _make(arguments=["python"], name="p")
        self._prep(agent, None)
        with (
            patch.object(create, "locateProgram", return_value="/usr/bin/python"),
            patch.object(create, "Popen", side_effect=OSError(ENOENT, "missing")),
            patch.object(create, "time", return_value=1.0),
        ):
            with self.assertRaises(ProcessError) as ctx:
                agent.createProcess()
        self.assertIn("doesn't exist", str(ctx.exception))

    def test_other_oserror_is_reraised(self):
        agent, _ = _make(arguments=["python"], name="p")
        self._prep(agent, None)
        with (
            patch.object(create, "locateProgram", return_value="/usr/bin/python"),
            patch.object(create, "Popen", side_effect=OSError(EACCES, "denied")),
            patch.object(create, "time", return_value=1.0),
        ):
            with self.assertRaises(OSError) as ctx:
                agent.createProcess()
        self.assertNotIsInstance(ctx.exception, ProcessError)
        self.assertEqual(ctx.exception.errno, EACCES)

    def test_child_error_becomes_process_error(self):
        agent, _ = _make(arguments=["python"], name="p")
        self._prep(agent, None)
        with (
            patch.object(create, "locateProgram", return_value="/usr/bin/python"),
            patch.object(create, "Popen", side_effect=ChildError("drop failed")),
            patch.object(create, "time", return_value=1.0),
        ):
            with self.assertRaises(ProcessError):
                agent.createProcess()


# =========================================================================== renameSession
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestRenameSession(unittest.TestCase):
    def test_zero_status_does_not_rename(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.renameSession(0)
        self.assertEqual(agent.sent, [])

    def test_positive_status_renames_exitcode(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.renameSession(42)
        self.assertEqual(agent.sent, [("session_rename", ("exitcode42",))])

    def test_negative_status_renames_signal(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.renameSession(-11)
        expected = create.signalName(11).lower()
        self.assertEqual(agent.sent, [("session_rename", (expected,))])


# =========================================================================== poll / processExited
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestPoll(unittest.TestCase):
    def test_no_process_returns_stored_status(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = None
        agent.status = 7
        self.assertEqual(agent.poll(), 7)

    def test_still_running_returns_none(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=1, poll_status=None)
        self.assertIsNone(agent.poll())

    def test_exit_triggers_processExited(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=1, poll_status=3)
        status = agent.poll()
        self.assertEqual(status, 3)
        self.assertEqual(agent.status, 3)
        # process cleared and process_exit emitted.
        self.assertIsNone(agent.process)
        events = [e for e, _ in agent.sent]
        self.assertIn("process_exit", events)

    def test_signal_death_emits_signal_rename(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=1, poll_status=-9)
        agent.poll()
        expected = create.signalName(9).lower()
        self.assertIn(("session_rename", (expected,)), agent.sent)

    def test_processExited_suppressed_when_show_exit_false(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=1, poll_status=5)
        agent.show_exit = False
        agent.poll()
        # No exit/rename events, but status recorded and process cleared.
        self.assertEqual(agent.sent, [])
        self.assertEqual(agent.status, 5)
        self.assertIsNone(agent.process)


# =========================================================================== closeStreams
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestCloseStreams(unittest.TestCase):
    def test_closes_and_nulls_both_streams(self):
        agent, _ = _make(arguments=["python"], name="p")

        class _F:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        so, si = _F(), _F()
        agent.stdout_file = so
        agent.stdin_file = si
        agent.closeStreams()
        self.assertTrue(so.closed and si.closed)
        self.assertIsNone(agent.stdout_file)
        self.assertIsNone(agent.stdin_file)

    def test_closeStreams_safe_right_after_init(self):
        # Regression: init() must seed stdin_file (not only stdout_file) so closeStreams()
        # -- reachable via poll()/terminate()/clearProcess() before a process is spawned --
        # never raises AttributeError.
        agent, _ = _make(arguments=["python"], name="p")
        agent.stdout_file = None
        agent.closeStreams()  # must not raise
        self.assertIsNone(agent.stdin_file)


# =========================================================================== live (timeout)
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestLive(unittest.TestCase):
    def test_no_process_is_noop(self):
        agent, _ = _make(arguments=["python"], name="p", timeout=5.0)
        agent.process = None
        agent.live()
        self.assertEqual(agent.sent, [])

    def test_zero_timeout_is_noop(self):
        agent, _ = _make(arguments=["python"], name="p", timeout=0)
        agent.process = _FakePopen()
        agent.live()
        self.assertEqual(agent.sent, [])

    def test_within_timeout_does_not_terminate(self):
        agent, _ = _make(arguments=["python"], name="p", timeout=10.0)
        agent.process = _FakePopen()
        agent.time0 = 100.0
        agent._terminated = False
        agent.terminate = lambda: setattr(agent, "_terminated", True)
        with patch.object(create, "time", return_value=105.0):  # 5s < 10s
            agent.live()
        self.assertFalse(agent._terminated)
        self.assertFalse(agent.timeout_reached)

    def test_timeout_exceeded_terminates_and_renames(self):
        agent, _ = _make(arguments=["python"], name="p", timeout=10.0)
        agent.process = _FakePopen()
        agent.time0 = 100.0
        agent._terminated = False
        agent.terminate = lambda: setattr(agent, "_terminated", True)
        with patch.object(create, "time", return_value=120.0):  # 20s > 10s
            agent.live()
        self.assertTrue(agent._terminated)
        self.assertTrue(agent.timeout_reached)
        self.assertIn(("session_rename", ("timeout",)), agent.sent)


# =========================================================================== terminate
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestTerminate(unittest.TestCase):
    def test_no_process_only_clears_show_exit(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = None
        agent.terminate()
        self.assertFalse(agent.show_exit)

    def test_already_exited_returns_after_poll(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(poll_status=0)  # poll() -> 0, not None
        agent._killed = False
        agent._terminate = lambda: setattr(agent, "_killed", True)
        agent.waitExit = lambda: None
        agent.terminate()
        self.assertFalse(agent._killed)  # never reached the kill

    def test_running_process_is_killed_and_waited(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(poll_status=None)  # still running
        agent._killed = False
        agent._waited = False
        agent._terminate = lambda: setattr(agent, "_killed", True)
        agent.waitExit = lambda: setattr(agent, "_waited", True)
        agent.terminate()
        self.assertTrue(agent._killed)
        self.assertTrue(agent._waited)

    def test_underscore_terminate_calls_terminateProcess(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=321)
        with patch.object(create, "terminateProcess") as tp:
            agent._terminate()
        tp.assert_called_once_with(agent.process)


# =========================================================================== waitExit
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestWaitExit(unittest.TestCase):
    def test_returns_once_process_exits(self):
        agent, _ = _make(arguments=["python"], name="p")
        # poll() returns a status immediately -> loop breaks, no sleep.
        agent.poll = lambda: 5
        with (
            patch.object(create, "time", side_effect=[0.0, 0.01, 0.01]),
            patch.object(create, "sleep") as slp,
        ):
            agent.waitExit()
        slp.assert_not_called()

    def test_fast_retry_sleeps_short(self):
        agent, _ = _make(arguments=["python"], name="p")
        statuses = iter([None, 5])
        agent.poll = lambda: next(statuses)
        with (
            patch.object(create, "time", side_effect=[0.0, 0.01, 0.01, 0.02, 0.02]),
            patch.object(create, "sleep") as slp,
        ):
            agent.waitExit()
        slp.assert_called_once_with(0.010)

    def test_mid_retry_sleeps_quarter_second(self):
        agent, _ = _make(arguments=["python"], name="p")
        statuses = iter([None, 5])
        agent.poll = lambda: next(statuses)
        # diff=0.1 falls in the 50ms..1s window -> sleep(0.250).
        with (
            patch.object(create, "time", side_effect=[0.0, 0.1, 0.1, 0.2, 0.2]),
            patch.object(create, "sleep") as slp,
        ):
            agent.waitExit()
        slp.assert_called_once_with(0.250)

    def test_slow_wait_resends_kill_and_logs(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=1)
        statuses = iter([None, 5])
        agent.poll = lambda: next(statuses)
        agent._kills = 0
        agent._terminate = lambda: setattr(agent, "_kills", agent._kills + 1)
        errs = []
        agent.error = lambda msg: errs.append(msg)
        # diff=2.0 (> 1s) -> re-KILL + sleep(0.500); next_msg elapsed -> error() logged.
        with (
            patch.object(create, "time", side_effect=[0.0, 2.0, 2.0, 2.0, 2.1, 2.1]),
            patch.object(create, "sleep") as slp,
        ):
            agent.waitExit()
        self.assertEqual(agent._kills, 1)
        slp.assert_called_once_with(0.500)
        self.assertEqual(len(errs), 1)

    def test_timeout_raises_value_error(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen(pid=1)
        agent.poll = lambda: None
        # start=0, then diff=100 > 60 -> ValueError immediately.
        with (
            patch.object(create, "time", side_effect=[0.0, 100.0]),
            patch.object(create, "sleep"),
        ):
            with self.assertRaises(ValueError):
                agent.waitExit()


# =========================================================================== deinit / getScore
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestDeinitAndScore(unittest.TestCase):
    def test_deinit_terminates_and_clears_process(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = _FakePopen()
        agent._terminated = False
        agent.terminate = lambda: setattr(agent, "_terminated", True)
        agent.deinit()
        self.assertTrue(agent._terminated)
        self.assertIsNone(agent.process)

    def test_deinit_without_process_is_noop(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.process = None
        agent.terminate = lambda: self.fail("terminate must not run without a process")
        agent.deinit()  # must not raise

    def test_getscore_returns_score(self):
        agent, _ = _make(arguments=["python"], name="p")
        agent.score = 0.75
        self.assertEqual(agent.getScore(), 0.75)


# =========================================================================== ProjectProcess
@unittest.skipUnless(HAVE_CREATE, "fusil runtime stack (python-ptrace) not importable")
class TestProjectProcess(unittest.TestCase):
    def test_on_session_start_creates_process(self):
        agent, _ = _make(arguments=["python"], name="p", cls=ProjectProcess)
        agent._created = False
        agent.createProcess = lambda: setattr(agent, "_created", True)
        agent.on_session_start()
        self.assertTrue(agent._created)


if __name__ == "__main__":
    unittest.main()
