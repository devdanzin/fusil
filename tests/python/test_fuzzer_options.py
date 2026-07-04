"""Unit tests for fusil.python.Fuzzer.createFuzzerOptions — the CLI option surface.

The Python fuzzer defines its (large) set of ``--*`` options in ``createFuzzerOptions``.
This drives that method on a bare Fuzzer (no __init__ side effects) with a stub plugin
manager and asserts the full option surface is wired up across the Input/Running/Fuzzing/OOM
groups. Skips where the runtime stack (python-ptrace) is unavailable.
"""

import unittest
from optparse import OptionParser
from unittest import mock

try:
    from fusil.python import Fuzzer

    HAVE_FUZZER = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_FUZZER = False


def _all_option_strings(parser):
    strings = {opt.get_opt_string() for opt in parser.option_list}
    for group in parser.option_groups:
        strings |= {opt.get_opt_string() for opt in group.option_list}
    return strings


@unittest.skipUnless(HAVE_FUZZER, "fusil runtime stack (python-ptrace) not importable")
class TestCreateFuzzerOptions(unittest.TestCase):
    def _options(self, plugin_cli=None):
        fuzzer = Fuzzer.__new__(Fuzzer)
        fuzzer.plugin_manager = mock.Mock()
        fuzzer.plugin_manager.get_cli_options.return_value = plugin_cli or []
        parser = OptionParser()
        fuzzer.createFuzzerOptions(parser)
        return parser, _all_option_strings(parser)

    def test_core_input_and_running_options(self):
        _parser, opts = self._options()
        for expected in (
            "--modules",
            "--packages",
            "--only-c",
            "--timeout",
            "--python",
            "--suppress-hit-regex",
            "--suppress-hit-file",
            "--suppress-hit-ignore-case",
        ):
            self.assertIn(expected, opts)

    def test_fuzzing_and_oom_options(self):
        _parser, opts = self._options()
        for expected in (
            "--functions-number",
            "--deep-dive",
            "--oom-fuzz",
            "--oom-seq",
            "--oom-window",
            "--oom-dedup-catalog",
            "--oom-foreign",
        ):
            self.assertIn(expected, opts)

    def test_plugin_cli_options_are_added(self):
        # A plugin-contributed option is appended under its own group.
        plugin_cli = [(("--my-plugin-flag",), {"action": "store_true", "help": "x"})]
        _parser, opts = self._options(plugin_cli=plugin_cli)
        self.assertIn("--my-plugin-flag", opts)

    def test_no_plugin_group_when_no_plugin_options(self):
        parser, _ = self._options(plugin_cli=[])
        group_titles = [g.title for g in parser.option_groups]
        self.assertNotIn("Plugin Options", group_titles)


if __name__ == "__main__":
    unittest.main()
