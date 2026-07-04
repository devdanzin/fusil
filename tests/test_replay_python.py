"""Unit tests for fusil.process.replay_python — the replay-script generator.

`createReplayPythonScript` writes a standalone `replay.py` that re-runs a crashing session's
command (optionally under gdb/valgrind/ptrace, with the same env/limits/uid). The module is
pure code generation over the WriteCode primitives, so it tests without the runtime stack: we
drive each emitter into an in-memory stream and assert on the produced source, and the
end-to-end test compiles the full generated script to prove it is syntactically valid Python.
Runtime-free.
"""

import io
import os
import tempfile
import unittest
from types import SimpleNamespace

from fusil.process import replay_python
from fusil.process.replay_python import (
    WriteReplayScript,
    createReplayPythonScript,
    formatPath,
    formatValue,
)


class TestFormatValue(unittest.TestCase):
    def test_run_of_five_or_more_identical_is_collapsed(self):
        self.assertEqual(formatValue("aaaaa"), "'a' * 5")
        self.assertEqual(formatValue("a" * 20), "'a' * 20")

    def test_short_run_is_plain_repr(self):
        self.assertEqual(formatValue("aaaa"), repr("aaaa"))  # len 4 < 5

    def test_mixed_content_is_plain_repr(self):
        self.assertEqual(formatValue("abcde"), repr("abcde"))

    def test_bytes_run_collapsed(self):
        self.assertEqual(formatValue(b"\x00\x00\x00\x00\x00"), repr(b"\x00") + " * 5")

    def test_bytes_mixed_repr(self):
        self.assertEqual(formatValue(b"ab\x00"), repr(b"ab\x00"))


class TestFormatPath(unittest.TestCase):
    def test_str_prefixed_by_cwd(self):
        self.assertEqual(formatPath("<path>b", "<path>", b"<path>"), "cwd + 'b'")

    def test_str_exactly_cwd(self):
        self.assertEqual(formatPath("<path>", "<path>", b"<path>"), "cwd")

    def test_bytes_cwd_in_middle(self):
        self.assertEqual(
            formatPath(b"a<path>b", "<path>", b"<path>"),
            "b'a' + cwd_bytes + b'b'",
        )

    def test_no_match_returns_plain_value(self):
        self.assertEqual(formatPath("nothing", "<path>", b"<path>"), repr("nothing"))

    def test_bytes_suffix_is_cwd(self):
        self.assertEqual(formatPath(b"a<path>", "<path>", b"<path>"), "b'a' + cwd_bytes")


def _writer():
    w = WriteReplayScript()
    w.useStream(io.StringIO())
    return w


class TestEmitters(unittest.TestCase):
    """Each fixed-content emitter produces non-empty, representative source."""

    def test_python_imports(self):
        w = _writer()
        w.pythonImports()
        out = w.output.getvalue()
        self.assertIn("from os import", out)
        self.assertIn("execvpe", out)
        self.assertTrue(out.startswith("#!"))

    def test_set_sys_path_lists_entries(self):
        w = _writer()
        w.setSysPath()
        out = w.output.getvalue()
        self.assertIn("sys.path = [", out)

    def test_limit_resources_guards(self):
        w = _writer()
        w.limitResources()
        out = w.output.getvalue()
        self.assertIn("if options.limit:", out)
        self.assertIn("limitMemory", out)
        self.assertIn("limitCpuTime", out)

    def test_parse_options_defines_all_flags(self):
        w = _writer()
        w.parseOptions()
        out = w.output.getvalue()
        for flag in (
            "--quiet",
            "--user",
            "--limit",
            "--environ",
            "--gdb",
            "--valgrind",
            "--ptrace",
        ):
            self.assertIn(flag, out)

    def test_gdb_commands_and_run(self):
        w = _writer()
        w.writeGdbCommands()
        w.runGdb()
        out = w.output.getvalue()
        self.assertIn("gdb.cmds", out)
        self.assertIn("execvpe", out)

    def test_run_command_handles_modes(self):
        w = _writer()
        w.runCommand()
        out = w.output.getvalue()
        self.assertIn("options.gdb", out)
        self.assertIn("options.valgrind", out)
        self.assertIn("options.ptrace", out)

    def test_write_main(self):
        w = _writer()
        w.writeMain()
        out = w.output.getvalue()
        self.assertIn("parseOptions()", out)
        self.assertIn("changeUserGroup", out)
        self.assertIn("runCommand", out)

    def test_safety_confirmation(self):
        w = _writer()
        w.safetyConfirmation()
        out = w.output.getvalue()
        self.assertIn("!!!WARNING!!!", out)
        self.assertIn("yes", out)

    def test_call_main(self):
        w = _writer()
        w.callMain()
        self.assertIn("__main__", w.output.getvalue())

    def test_debug_function(self):
        w = _writer()
        w.writeDebugFunction()
        self.assertIn("stderr", w.output.getvalue())


class TestDebugAndPrintHelpers(unittest.TestCase):
    def test_debug_no_args(self):
        w = _writer()
        w.debug(0, "hello")
        self.assertEqual(w.output.getvalue(), 'debug("hello")\n')

    def test_debug_single_arg(self):
        w = _writer()
        w.debug(0, "value %s", "x")
        self.assertEqual(w.output.getvalue(), 'debug("value %s" % x)\n')

    def test_debug_multiple_args_tupled(self):
        w = _writer()
        w.debug(0, "%s and %s", "a", "b")
        self.assertEqual(w.output.getvalue(), 'debug("%s and %s" % (a, b))\n')

    def test_write_print_plain(self):
        w = _writer()
        w.writePrint(0, "hi")
        self.assertEqual(w.output.getvalue(), 'print ("hi")\n')

    def test_write_print_with_arguments_and_file(self):
        w = _writer()
        w.writePrint(0, "x=%s", "x", file="stderr")
        self.assertEqual(w.output.getvalue(), 'print ("x=%s" % (x), file=stderr)\n')

    def test_write_function_wraps_def_and_indents_body(self):
        w = _writer()
        w.writeFunction("foo()", lambda: w.write(0, "body"))
        self.assertEqual(w.output.getvalue(), "def foo():\n    body\n\n")


class TestGlobalVariables(unittest.TestCase):
    def _emit(self, *, arguments, env, **process_kw):
        w = _writer()
        process = SimpleNamespace(
            stdin=process_kw.get("stdin", True),
            core_dump=process_kw.get("core_dump", False),
            max_user_process=process_kw.get("max_user_process", 0),
            max_memory=process_kw.get("max_memory", 0),
            timeout=process_kw.get("timeout", 0.0),
        )
        config = SimpleNamespace(
            process_uid=process_kw.get("uid", 1000),
            process_gid=process_kw.get("gid", 1000),
            process_user=process_kw.get("process_user", False),
        )
        w.globalVariables(process, config, "/work", arguments, env)
        return w.output.getvalue()

    def test_emits_uid_gid_and_limits(self):
        out = self._emit(arguments=["prog"], env={}, uid=1000, gid=42, max_memory=2048)
        self.assertIn("uid = 1000", out)
        self.assertIn("gid = 42", out)
        self.assertIn("max_memory = 2048", out)
        self.assertIn("env = {}", out)

    def test_timeout_and_user_process_none_when_unset(self):
        out = self._emit(arguments=["prog"], env={})
        self.assertIn("timeout = None", out)
        self.assertIn("max_user_process = None", out)

    def test_env_dict_rendered(self):
        out = self._emit(arguments=["prog"], env={"KEY": "value"})
        self.assertIn('"KEY":', out)

    def test_need_cwd_bytes_when_argument_contains_cwd(self):
        # A bytes argument containing the cwd triggers the cwd_bytes helper line.
        out = self._emit(arguments=[b"/work/sub"], env={})
        self.assertIn("cwd_bytes = cwd.encode(getfilesystemencoding())", out)


class TestWriteCodeIntegration(unittest.TestCase):
    def _generate(self, *, arguments, env, **process_kw):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: _rmtree(tmpdir))
        config = SimpleNamespace(
            process_uid=process_kw.get("uid", 1000),
            process_gid=process_kw.get("gid", 1000),
            process_user=process_kw.get("process_user", False),
        )
        session = SimpleNamespace(createFilename=lambda name: os.path.join(tmpdir, name))
        project = SimpleNamespace(session=session, config=config)
        process = SimpleNamespace(
            project=lambda: project,
            getWorkingDirectory=lambda: tmpdir,
            stdin=process_kw.get("stdin", True),
            core_dump=process_kw.get("core_dump", False),
            max_user_process=process_kw.get("max_user_process", 0),
            max_memory=process_kw.get("max_memory", 0),
            timeout=process_kw.get("timeout", 0.0),
        )
        createReplayPythonScript(process, arguments, {"env": env})
        path = os.path.join(tmpdir, "replay.py")
        with open(path) as fh:
            return path, fh.read()

    def test_generated_script_is_valid_python(self):
        path, source = self._generate(arguments=["/bin/true", "arg"], env={"PATH": "/usr/bin"})
        # The whole point: the emitted replay script must be syntactically valid.
        compile(source, path, "exec")
        self.assertIn("def main():", source)
        self.assertIn("if __name__ == '__main__':", source)

    def test_generated_script_is_executable_file(self):
        path, _ = self._generate(arguments=["/bin/true"], env={})
        self.assertTrue(os.access(path, os.X_OK))

    def test_generated_script_valid_with_limits_and_bytes_args(self):
        path, source = self._generate(
            arguments=[b"/bin/true", b"data"],
            env={"HOME": "/root"},
            max_memory=4096,
            timeout=30.0,
            core_dump=True,
            process_user=True,
            max_user_process=64,
        )
        compile(source, path, "exec")
        self.assertIn("max_memory = 4096", source)
        self.assertIn("timeout = 30", source)

    def test_module_level_wrapper_exists(self):
        self.assertTrue(callable(replay_python.createReplayPythonScript))


def _rmtree(path):
    import shutil

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
