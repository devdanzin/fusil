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
    """Raised when the foreign-OOM shim cannot be built (no compiler / compile failure)."""


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
