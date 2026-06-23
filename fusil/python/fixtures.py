"""Safe, throwaway fixture files used as ``--filenames`` fuzzing inputs.

The Python fuzzer feeds the ``--filenames`` paths as arguments to randomly chosen
functions/methods. Some fuzzed call *will* eventually open one of those paths for
writing/truncation, so the files must be **expendable**: never point ``--filenames`` at
real, valuable files. The historical default (``/etc/machine-id,/bin/sh``) did exactly
that, and clobbered both when a fuzzed call wrote to them while the child ran with write
permission (e.g. as root under ``--unsafe``).

This module creates a small set of valueless fixture files and returns their paths. They
are made read-only (so a child running as the unprivileged ``fusil`` user cannot clobber
them — the write just fails and exercises the error path), and they are regenerated every
run, so even if a privileged child does truncate one, only a throwaway file is lost and it
comes back next session.
"""

from __future__ import annotations

import os
import tempfile

# Candidate directories, in preference order. The first that exists or can be created is
# used. /var/lib/fusil is the natural home when running as root (the fleet); the tempdir
# fallback keeps unprivileged/dev runs working. Override with $FUSIL_FIXTURE_DIR.
_CANDIDATE_DIRS = [
    "/var/lib/fusil/fixtures",
    os.path.join(tempfile.gettempdir(), "fusil-fixtures"),
]

# Valueless fixture content: a small text file and a small binary file, enough to be
# realistic inputs for file-reading code without containing anything worth keeping.
_FIXTURES: dict[str, bytes] = {
    "fusil_fixture.txt": b"fusil fuzzing fixture - safe to clobber, regenerated each run\n" * 4,
    "fusil_fixture.bin": bytes(range(256)) * 8,
}


def _select_dir() -> str:
    """Return the fixture directory to use (creating nothing yet)."""
    override = os.environ.get("FUSIL_FIXTURE_DIR")
    if override:
        return override
    for d in _CANDIDATE_DIRS:
        if os.path.isdir(d) or os.access(os.path.dirname(d) or "/", os.W_OK):
            return d
    return _CANDIDATE_DIRS[-1]


def fixture_dir() -> str:
    return _select_dir()


def ensure_fixture_files() -> list[str]:
    """Create the throwaway fixture files (idempotent) and return their absolute paths.

    Restores any file that is missing or has been clobbered (zero-sized). Files are left
    read-only; the directory is left traversable so an unprivileged child can read them.
    """
    directory = _select_dir()
    os.makedirs(directory, exist_ok=True)
    try:
        os.chmod(directory, 0o755)
    except OSError:
        pass

    paths: list[str] = []
    for name, content in _FIXTURES.items():
        path = os.path.join(directory, name)
        try:
            need = (not os.path.exists(path)) or os.path.getsize(path) != len(content)
        except OSError:
            need = True
        if need:
            # Make writable first in case a stale read-only copy exists.
            try:
                os.chmod(path, 0o644)
            except OSError:
                pass
            with open(path, "wb") as fp:
                fp.write(content)
        try:
            os.chmod(path, 0o444)  # read-only: an unprivileged child cannot clobber it
        except OSError:
            pass
        paths.append(path)
    return paths
