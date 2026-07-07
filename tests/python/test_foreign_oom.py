"""Tests for the foreign-allocator OOM shim (fusil/python/fusil_malloc_shim.c + foreign_oom.py).

Verifies the shim compiles/caches and that, once LD_PRELOADed, ``fusil_malloc_arm(start, stop)``
injects malloc failures deterministically (the drop-in set_nomemory semantics) and recovers.
"""

import os
import shutil
import stat
import subprocess
import sys
import textwrap
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

from fusil.python.foreign_oom import (
    _cache_dir,
    _parse_probe_count,
    get_shim_path,
    probe_shim_effective,
)

_HAVE_CC = bool(shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))


@unittest.skipUnless(_HAVE_CC, "needs a C compiler to build the malloc shim")
class TestForeignOOMShim(unittest.TestCase):
    def test_get_shim_path_compiles_and_caches(self):
        path = get_shim_path()
        self.assertTrue(os.path.exists(path))
        self.assertTrue(path.endswith(".so"))
        self.assertEqual(get_shim_path(), path)  # second call hits the cache

    def test_shim_and_cache_dir_are_child_readable(self):
        # Regression (2026-07-02): the parent builds the shim (often as root), but the fuzzed
        # child runs as the dropped-privilege `fusil` user and LD_PRELOADs it. When the shim
        # lived in root's 0700 ~/.cache, ld.so reported "cannot be preloaded". The cache dir
        # must be world-traversable (+x) and the .so world-readable (+r).
        path = get_shim_path()
        so_mode = os.stat(path).st_mode
        self.assertTrue(so_mode & stat.S_IROTH, f"shim .so not world-readable: {oct(so_mode)}")
        dir_mode = os.stat(_cache_dir()).st_mode
        self.assertTrue(
            dir_mode & stat.S_IXOTH, f"cache dir not world-traversable: {oct(dir_mode)}"
        )

    def test_shim_injects_and_recovers(self):
        shim = get_shim_path()
        # Under LD_PRELOAD, malloc resolved via CDLL(None) is the interposed shim malloc.
        # arm a window covering ctypes call overhead, then a malloc must return NULL; after
        # disarm it must succeed again. Windowed => deterministic (set_nomemory semantics).
        snippet = textwrap.dedent(
            """
            import ctypes
            me = ctypes.CDLL(None)
            me.malloc.restype = ctypes.c_void_p
            me.malloc.argtypes = [ctypes.c_size_t]
            me.free.argtypes = [ctypes.c_void_p]
            arm = me.fusil_malloc_arm
            arm.argtypes = [ctypes.c_long, ctypes.c_long]
            disarm = me.fusil_malloc_disarm

            arm(0, 200)              # fail allocations [0, 200)
            p = me.malloc(4096)
            disarm()
            armed_failed = not p
            if p:
                me.free(p)

            q = me.malloc(4096)      # disarmed: succeeds
            disarmed_ok = bool(q)
            if q:
                me.free(q)

            print("PASS" if (armed_failed and disarmed_ok) else "FAIL")
            """
        )
        env = dict(os.environ, LD_PRELOAD=shim)
        proc = subprocess.run(
            [sys.executable, "-c", snippet],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "PASS", proc.stdout + proc.stderr)


class TestParseProbeCount(unittest.TestCase):
    """Pure parse of the shim-effectiveness probe's stdout (no compiler/subprocess)."""

    def test_intercepted(self):
        self.assertEqual(_parse_probe_count("noise\nFUSIL_SHIM_COUNT=8\nmore"), 8)

    def test_shadowed(self):
        self.assertEqual(_parse_probe_count("FUSIL_SHIM_COUNT=0"), 0)

    def test_absent_marker_is_none(self):
        self.assertIsNone(_parse_probe_count("Traceback ...\nAttributeError"))
        self.assertIsNone(_parse_probe_count(""))
        self.assertIsNone(_parse_probe_count(None))


@unittest.skipUnless(_HAVE_CC, "needs a C compiler to build the malloc shim")
class TestProbeShimEffective(unittest.TestCase):
    def test_intercepts_on_non_asan_python(self):
        # The test runner is a normal (non-ASan) interpreter, so the preloaded shim is on the
        # allocation path -> the probe must report interception. (A statically-linked ASan
        # target would return False; that path is exercised by the wiring, not portably here.)
        shim = get_shim_path()
        self.assertIs(probe_shim_effective(sys.executable, shim), True)

    def test_missing_python_is_inconclusive_not_fatal(self):
        # A probe that can't run at all is inconclusive (None), never a false "shadowed" verdict.
        shim = get_shim_path()
        self.assertIsNone(probe_shim_effective("/nonexistent/python-xyz", shim))


if __name__ == "__main__":
    unittest.main()
