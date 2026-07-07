"""Foreign-allocator OOM: compile + locate the LD_PRELOAD malloc-failure shim.

The shim (``fusil_malloc_shim.c``) interposes ``malloc``/``calloc``/``realloc``/... so
allocation failures can be injected at the C ``malloc`` layer, reaching foreign C-library
allocations (HDF5, zstd, libxml2, openssl, ...) that ``_testcapi.set_nomemory`` -- which only
hooks CPython's PyMem allocators -- structurally cannot. It exports
``fusil_malloc_arm(start, stop)`` (a drop-in for ``set_nomemory``) callable from the generated
harness via ``ctypes.CDLL(None)``. See ``doc/python-fuzzer.md`` (OOM section).

This module compiles the shim once (cached, keyed by the source hash) and returns the ``.so``
path for the launcher to put in the child's ``LD_PRELOAD``.
"""

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_SHIM_SOURCE = Path(__file__).with_name("fusil_malloc_shim.c")


def _cache_dir() -> Path:
    # A world-readable shared dir, NOT ~/.cache: the parent compiles the shim (typically as
    # root), but the fuzzed child runs as the dropped-privilege ``fusil`` user and must be able
    # to traverse the dir and open the .so to LD_PRELOAD it. ~/.cache is 0700 (root's home is
    # untraversable by the child), which made ld.so report "cannot be preloaded".
    return Path(tempfile.gettempdir()) / "fusil-shim"


def _make_child_readable(cache_dir: Path, so_path: Path) -> None:
    """Best-effort: let the dropped-privilege child traverse the cache dir and read the .so.

    The parent (often root) builds the shim; the child (``fusil`` user) LD_PRELOADs it, so both
    the directory (needs +x to traverse) and the .so (needs +r) must be world-accessible.
    """
    for path, mode in ((cache_dir, 0o755), (so_path, 0o644)):
        try:
            os.chmod(path, mode)
        except OSError:  # pragma: no cover - perms are best-effort (e.g. not owner)
            pass


class ForeignOOMError(Exception):
    """Raised when the foreign-OOM shim cannot be built or is ineffective.

    Covers both "no compiler / compile failure" (see ``get_shim_path``) and "the shim loads but
    does not actually intercept ``malloc`` in the target" (see ``probe_shim_effective`` /
    ``ShimShadowedError``) -- either way ``--oom-foreign`` cannot inject anything.
    """


class ShimShadowedError(ForeignOOMError):
    """The shim is preloaded but the target's ``malloc`` bypasses it, so no failure is injected.

    The usual cause is a **statically-linked AddressSanitizer** target: ASan defines/exports its
    own ``malloc`` in the executable, which sits ahead of ``LD_PRELOAD`` in the global symbol
    scope and shadows the shim. ``--oom-foreign`` then silently injects *nothing*. Remedy: use a
    non-ASan target, or rebuild the target (and its C libs) with ``-shared-libasan`` and set
    ``ASAN_OPTIONS=verify_asan_link_order=0`` so the preloaded shim wins over the shared runtime.
    """


# A tiny program run in the *target* interpreter (with the shim LD_PRELOAD'd) to check that the
# shim's malloc is actually on the allocation path. ``fusil_malloc_count`` only increments while
# armed and only from *inside the shim's own malloc*, so a nonzero count after some allocations
# proves interposition; zero means the shim is shadowed. Armed with an unreachable failure window
# (fail nothing) so the probe itself can't be killed by an injected failure.
_PROBE_SRC = (
    "import ctypes\n"
    "l = ctypes.CDLL(None)\n"
    "l.fusil_malloc_count.restype = ctypes.c_long\n"
    "l.malloc.restype = ctypes.c_void_p\n"
    "l.malloc.argtypes = [ctypes.c_size_t]\n"
    "l.free.argtypes = [ctypes.c_void_p]\n"
    "l.fusil_malloc_arm(ctypes.c_long(1 << 40), ctypes.c_long((1 << 40) + 1))\n"
    "ps = [l.malloc(1 << 20) for _ in range(8)]\n"
    "n = l.fusil_malloc_count()\n"
    "l.fusil_malloc_disarm()\n"
    "[l.free(ctypes.c_void_p(p)) for p in ps if p]\n"
    "print('FUSIL_SHIM_COUNT=%d' % n)\n"
)

_PROBE_MARKER = "FUSIL_SHIM_COUNT="


def _parse_probe_count(stdout):
    """Extract the shim allocation counter from probe stdout; None if the marker is absent.

    Returns the integer count (>0 means the shim intercepted, 0 means it was shadowed), or None
    when the probe did not report a count at all (e.g. the control symbol wasn't found, so the
    shim isn't preloaded -- an inconclusive result, not a definitive shadow).
    """
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith(_PROBE_MARKER):
            try:
                return int(line[len(_PROBE_MARKER) :])
            except ValueError:  # pragma: no cover - malformed marker line
                return None
    return None


def probe_shim_effective(python_exe, shim_path, timeout=30):
    """Return whether the malloc shim actually intercepts allocations in ``python_exe``.

    Runs a short probe in the target interpreter with the shim ``LD_PRELOAD``'d. Returns:

    * ``True``  -- the shim intercepts (nonzero allocation count): ``--oom-foreign`` will work;
    * ``False`` -- the shim is shadowed (count 0): injection is a **no-op** (see
      ``ShimShadowedError``);
    * ``None``  -- inconclusive: the probe couldn't run or reported no count (don't block on it).

    This never raises: the caller decides what to do with each verdict.
    """
    env = dict(os.environ)
    # Prepend the shim; keep any existing LD_PRELOAD (e.g. the shared ASan runtime) after it.
    existing = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = shim_path + ((" " + existing) if existing else "")
    # Leak detection would fire on the probe's tiny leaks and muddy stderr on ASan targets.
    env["ASAN_OPTIONS"] = (env.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")
    try:
        proc = subprocess.run(
            [python_exe, "-c", _PROBE_SRC],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as err:  # pragma: no cover - env-dependent
        logger.warning(
            "foreign-OOM shim probe could not run (%s); skipping effectiveness check", err
        )
        return None
    count = _parse_probe_count(proc.stdout)
    if count is None:
        logger.warning(
            "foreign-OOM shim probe reported no count (rc=%s, stderr=%r); skipping check",
            proc.returncode,
            (proc.stderr or "")[-200:],
        )
        return None
    return count > 0


def get_shim_path() -> str:
    """Return the path to the compiled malloc-failure shim, building it (cached) if needed.

    The cache key is the shim source hash, so a changed shim rebuilds automatically and stale
    copies are never reused. Raises ForeignOOMError if no C compiler is available or the
    compile fails -- the caller (``--oom-foreign`` setup) surfaces that to the user.
    """
    if not _SHIM_SOURCE.exists():  # pragma: no cover - shipped with the package
        raise ForeignOOMError("shim source missing: %s" % _SHIM_SOURCE)

    source = _SHIM_SOURCE.read_bytes()
    digest = hashlib.sha256(source).hexdigest()[:16]
    cache_dir = _cache_dir()
    so_path = cache_dir / ("fusil_malloc_shim_%s.so" % digest)
    if so_path.exists():
        _make_child_readable(cache_dir, so_path)
        return str(so_path)

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        raise ForeignOOMError(
            "--oom-foreign needs a C compiler (cc/gcc/clang) to build the malloc shim; none found"
        )

    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp_so = cache_dir / ("fusil_malloc_shim_%s.so.tmp%d" % (digest, os.getpid()))
    cmd = [compiler, "-shared", "-fPIC", "-O2", "-o", str(tmp_so), str(_SHIM_SOURCE), "-ldl"]
    logger.info("Building foreign-OOM malloc shim: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as err:
        raise ForeignOOMError("failed to build malloc shim: %s" % (err.stderr or err)) from err
    os.replace(tmp_so, so_path)  # atomic publish
    _make_child_readable(cache_dir, so_path)
    return str(so_path)
