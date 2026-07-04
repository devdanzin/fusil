"""Unit tests for fusil.process.cmdline.CommandLine — the argv assembler.

CommandLine is the tiny ProjectAgent that owns a process's argument vector and hands out a
*fresh copy* of it via ``create()`` each time the process is (re)launched. WHY the copy
matters: CreateProcess mutates the returned list in place (it rewrites ``argv[0]`` to the
resolved program path), so ``create()`` must not leak those edits back into the stored
template. Runtime-free: no python-ptrace needed (cmdline only imports ProjectAgent), so a
real MTA-backed FakeProject constructs the agent directly.
"""

import unittest

from fusil.process.cmdline import CommandLine
from tests.mas_harness import FakeProject


class _FakeProcess:
    """Minimal process stand-in exposing the ``project()`` / ``name`` that
    ``CommandLine.__init__`` reads."""

    def __init__(self, project, name="target"):
        self._project = project
        self.name = name

    def project(self):
        return self._project


def _cmdline(arguments, name="target"):
    project = FakeProject()
    proc = _FakeProcess(project, name=name)
    return CommandLine(proc, arguments), project


class TestConstruction(unittest.TestCase):
    def test_name_derived_from_process(self):
        cmd, _ = _cmdline(["python", "-c", "pass"], name="python")
        self.assertEqual(cmd.name, "python:cmdline")

    def test_arguments_stored_by_reference(self):
        args = ["python", "-c", "pass"]
        cmd, _ = _cmdline(args)
        self.assertIs(cmd.arguments, args)

    def test_registers_with_project(self):
        cmd, project = _cmdline(["python"])
        self.assertIn(cmd, project.registered)


class TestCreate(unittest.TestCase):
    def test_create_returns_equal_list(self):
        cmd, _ = _cmdline(["python", "-c", "pass"])
        self.assertEqual(cmd.create(), ["python", "-c", "pass"])

    def test_create_returns_a_copy_not_the_stored_list(self):
        args = ["python", "-c", "pass"]
        cmd, _ = _cmdline(args)
        result = cmd.create()
        self.assertIsNot(result, args)
        # Mutating the returned list (as CreateProcess does to argv[0]) must not touch the
        # stored template.
        result[0] = "/usr/bin/python3"
        self.assertEqual(cmd.arguments, ["python", "-c", "pass"])

    def test_each_create_is_an_independent_copy(self):
        cmd, _ = _cmdline(["python"])
        first = cmd.create()
        second = cmd.create()
        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_create_from_tuple_returns_list(self):
        cmd, _ = _cmdline(("python", "-c", "pass"))
        result = cmd.create()
        self.assertIsInstance(result, list)
        self.assertEqual(result, ["python", "-c", "pass"])

    def test_create_empty_arguments(self):
        cmd, _ = _cmdline([])
        self.assertEqual(cmd.create(), [])

    def test_create_preserves_order_and_mixed_types(self):
        # CommandLine does no validation (CreateProcess does); create() is a pure passthrough
        # copy that preserves element order and type (bytes/str mix here).
        args = [b"python", "-c", b"print(1)"]
        cmd, _ = _cmdline(args)
        self.assertEqual(cmd.create(), [b"python", "-c", b"print(1)"])

    def test_create_reflects_later_mutation_of_stored_arguments(self):
        # arguments is stored by reference, so edits made before create() are visible — this
        # is what lets a caller build up argv on the CommandLine and have it take effect.
        args = ["python"]
        cmd, _ = _cmdline(args)
        args.append("-v")
        self.assertEqual(cmd.create(), ["python", "-v"])


if __name__ == "__main__":
    unittest.main()
