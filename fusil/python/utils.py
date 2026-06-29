"""Utility functions for the fusil Python fuzzer."""

from __future__ import annotations

import datetime
import importlib
import logging
import pathlib
import resource
import time


def remove_logging_pycache() -> None:
    """Best-effort removal of stale logging ``__pycache__`` that can cause logging errors.

    Runs at startup against the *installed* stdlib, so it must never abort startup: a
    missing ``__pycache__`` (the common case -- e.g. ``PYTHONDONTWRITEBYTECODE``) or any
    unlink/rmdir failure is reported and ignored. (The ``reload(logging)`` is a workaround
    of unverified necessity -- kept conservatively, but wrapped so it can't crash startup.)
    """
    pycache = pathlib.Path(logging.__file__).parent / "__pycache__"
    if pycache.is_dir():
        for entry in pycache.iterdir():
            try:
                entry.unlink()
            except OSError as e:
                print(f"Error deleting file {entry.name}: {e}")
        try:
            pycache.rmdir()
        except OSError as e:
            print(f"Error removing directory {pycache.name}: {e}")
    try:
        importlib.reload(logging)
    except Exception as e:
        print(f"Error reloading logging: {e}")


def print_running_time(time_start: float) -> str:
    """Calculate and return a string with total and user running times."""
    raw_utime = resource.getrusage(resource.RUSAGE_SELF).ru_utime
    user_time = str(datetime.timedelta(0, round(raw_utime, 2)))
    total_time = str(datetime.timedelta(0, round(time.time() - time_start, 2)))
    return f"\nRunning time: {total_time[:-4]}\nUser time:    {user_time[:-4]}"
