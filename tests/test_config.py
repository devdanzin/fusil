"""Unit tests for fusil.config — the config-path resolver and the non-CLI defaults holder.

``createFilename`` resolves where ``fusil.conf`` would live (XDG_CONFIG_HOME, else
``$HOME/.config``, else error); ``FusilConfig`` is the single source of truth for the handful
of settings that have no ``--*`` CLI flag (scoring thresholds, memory caps, sandbox user/group).
The old ``fusil.conf`` read/write round-trip was removed, so the surface to test is the path
resolution branches and that the defaults are the exact, correctly-typed constants the rest of
the fuzzer relies on. Runtime-free: environment is exercised with ``patch.dict``, no I/O.
"""

import os
import unittest
from os.path import join as path_join
from unittest import mock

from fusil.config import ConfigError, FusilConfig, createFilename


class TestCreateFilename(unittest.TestCase):
    def test_default_name_and_xdg_config_home(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg/cfg"}, clear=True):
            self.assertEqual(createFilename(), path_join("/xdg/cfg", "fusil.conf"))

    def test_custom_name_uses_xdg(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg/cfg"}, clear=True):
            self.assertEqual(createFilename("other.ini"), path_join("/xdg/cfg", "other.ini"))

    def test_falls_back_to_home_config_when_xdg_unset(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/joe"}, clear=True):
            self.assertEqual(createFilename(), path_join("/home/joe", ".config", "fusil.conf"))

    def test_empty_xdg_is_treated_as_unset(self):
        # `if not configdir` means an empty XDG_CONFIG_HOME falls through to HOME.
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "", "HOME": "/home/joe"}, clear=True):
            self.assertEqual(createFilename(), path_join("/home/joe", ".config", "fusil.conf"))

    def test_explicit_configdir_bypasses_environment(self):
        # An explicit configdir must not consult XDG/HOME at all.
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                createFilename(name="x.conf", configdir="/etc/fusil"),
                path_join("/etc/fusil", "x.conf"),
            )

    def test_explicit_configdir_with_default_name(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                createFilename(configdir="/etc/fusil"),
                path_join("/etc/fusil", "fusil.conf"),
            )

    def test_missing_home_raises_config_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigError):
                createFilename()

    def test_empty_home_raises_config_error(self):
        with mock.patch.dict(os.environ, {"HOME": ""}, clear=True):
            with self.assertRaises(ConfigError) as ctx:
                createFilename()
        self.assertIn("HOME", str(ctx.exception))

    def test_config_error_is_an_exception(self):
        self.assertTrue(issubclass(ConfigError, Exception))


class TestFusilConfigDefaults(unittest.TestCase):
    def setUp(self):
        # Keep filename resolution deterministic and I/O-free for the whole class.
        patcher = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg/cfg"}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.config = FusilConfig()

    def test_filename_resolved_from_environment(self):
        self.assertEqual(self.config.filename, path_join("/xdg/cfg", "fusil.conf"))

    def test_application_scoring_and_limits(self):
        self.assertEqual(self.config.fusil_max_memory, 500 * 1024 * 1024)
        self.assertEqual(self.config.fusil_success_score, 0.50)
        self.assertEqual(self.config.fusil_error_score, -0.50)
        self.assertEqual(self.config.fusil_success, 1)
        self.assertEqual(self.config.fusil_session, 0)
        self.assertEqual(self.config.fusil_normal_calm_load, 0.50)
        self.assertEqual(self.config.fusil_normal_calm_sleep, 0.5)

    def test_subprocess_defaults(self):
        self.assertEqual(self.config.process_max_memory, 2000 * 1024 * 1024)
        self.assertIs(self.config.process_core_dump, True)
        self.assertEqual(self.config.process_max_user_process, 5000)
        self.assertEqual(self.config.process_user, "fusil")
        self.assertIsNone(self.config.process_uid)
        self.assertEqual(self.config.process_group, "fusil")
        self.assertIsNone(self.config.process_gid)

    def test_default_types(self):
        # The consumers rely on these types (int memory caps, float scores/thresholds, bool).
        self.assertIsInstance(self.config.fusil_max_memory, int)
        self.assertIsInstance(self.config.process_max_memory, int)
        self.assertIsInstance(self.config.fusil_success_score, float)
        self.assertIsInstance(self.config.fusil_error_score, float)
        self.assertIsInstance(self.config.fusil_normal_calm_load, float)
        self.assertIsInstance(self.config.fusil_normal_calm_sleep, float)
        self.assertIsInstance(self.config.process_core_dump, bool)
        self.assertIsInstance(self.config.process_user, str)

    def test_error_score_is_below_success_score(self):
        # Sanity invariant the session scorer depends on.
        self.assertLess(self.config.fusil_error_score, self.config.fusil_success_score)


class TestFusilConfigInstances(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg/cfg"}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_overrides_do_not_leak_across_instances(self):
        # Defaults live on the instance, so overriding one config must not touch another.
        a = FusilConfig()
        b = FusilConfig()
        a.fusil_success = 99
        a.process_user = "someoneelse"
        self.assertEqual(b.fusil_success, 1)
        self.assertEqual(b.process_user, "fusil")

    def test_filename_follows_current_environment(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/zoe"}, clear=True):
            config = FusilConfig()
        self.assertEqual(config.filename, path_join("/home/zoe", ".config", "fusil.conf"))


if __name__ == "__main__":
    unittest.main()
