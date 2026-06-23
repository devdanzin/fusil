"""Characterization tests for the fuzzed-child resource limits (fusil.process).

Pins the behavior re-enabled in Phase 0: the per-child memory cap is applied again,
but skipped for AddressSanitizer targets (whose huge address-space reservation is
incompatible with RLIMIT_AS) and when --no-memory-limit is set. Runtime-free: the
subprocess probe and the rlimit helpers are mocked, so no real limits are set.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fusil.process import prepare, tools


class TestTargetIsAsan(unittest.TestCase):
    def setUp(self):
        tools.target_is_asan.cache_clear()
        self.addCleanup(tools.target_is_asan.cache_clear)

    def _run_returning(self, config_args="", ldd=""):
        """Return a fake subprocess.run that answers the CONFIG_ARGS probe then ldd."""
        def fake_run(cmd, **kwargs):
            if cmd[0] == "ldd":
                return SimpleNamespace(stdout=ldd)
            return SimpleNamespace(stdout=config_args)
        return fake_run

    def test_detects_asan_from_config_args(self):
        with patch.object(tools, "run",
                          self._run_returning(config_args="'--with-address-sanitizer'")):
            self.assertTrue(tools.target_is_asan("/builds/asan/python"))

    def test_non_asan_build_from_config_args(self):
        with patch.object(tools, "run",
                          self._run_returning(config_args="'--with-pydebug' 'CC=clang'")):
            self.assertFalse(tools.target_is_asan("/builds/plain/python"))

    def test_ldd_fallback_when_config_args_silent(self):
        # CONFIG_ARGS has no sanitizer hint, but ldd reveals libasan.
        with patch.object(tools, "run",
                          self._run_returning(config_args="", ldd="libasan.so.8 => ...")):
            self.assertTrue(tools.target_is_asan("/builds/ldd-asan/python"))

    def test_none_program_is_not_asan(self):
        self.assertFalse(tools.target_is_asan(None))

    def test_probe_failure_is_not_asan(self):
        def boom(cmd, **kwargs):
            raise OSError("no such program")
        with patch.object(tools, "run", boom):
            self.assertFalse(tools.target_is_asan("/nonexistent"))


class TestLimitResourcesGating(unittest.TestCase):
    """limitResources should not apply a hard memory cap when max_memory is 0 (the value
    CreateProcess uses for ASan / --no-memory-limit), but should otherwise."""

    def _call(self, max_memory, fusil_max_memory=0):
        process = SimpleNamespace(max_memory=max_memory, core_dump=False,
                                  max_user_process=0)
        config = SimpleNamespace(fusil_max_memory=fusil_max_memory, process_user=None)
        options = SimpleNamespace(fast=True)  # fast => skip beNice
        with patch.object(prepare, "limitMemory") as lm, \
                patch.object(prepare, "allowCoreDump"), \
                patch.object(prepare, "limitUserProcess"), \
                patch.object(prepare, "beNice"):
            prepare.limitResources(process, config, options)
        return lm

    def test_no_hard_cap_when_max_memory_zero(self):
        lm = self._call(max_memory=0, fusil_max_memory=0)
        lm.assert_not_called()

    def test_hard_cap_applied_when_max_memory_positive(self):
        cap = 2000 * 1024 * 1024
        lm = self._call(max_memory=cap)
        lm.assert_called_once_with(cap, hard=True)


if __name__ == "__main__":
    unittest.main()
