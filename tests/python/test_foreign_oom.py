"""Tests for the foreign-allocator OOM shim (fusil/python/fusil_malloc_shim.c + foreign_oom.py).

Verifies the shim compiles/caches and that, once LD_PRELOADed, ``fusil_malloc_arm(start, stop)``
injects malloc failures deterministically (the drop-in set_nomemory semantics) and recovers.
"""

import os
import shutil
import subprocess
import sys
import textwrap
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

from fusil.python.foreign_oom import get_shim_path

_HAVE_CC = bool(shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))


@unittest.skipUnless(_HAVE_CC, "needs a C compiler to build the malloc shim")
class TestForeignOOMShim(unittest.TestCase):
    def test_get_shim_path_compiles_and_caches(self):
        path = get_shim_path()
        self.assertTrue(os.path.exists(path))
        self.assertTrue(path.endswith(".so"))
        self.assertEqual(get_shim_path(), path)  # second call hits the cache

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


if __name__ == "__main__":
    unittest.main()
