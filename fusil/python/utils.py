"""Utility functions for the fusil Python fuzzer."""

from __future__ import annotations

import datetime
import importlib
import logging
import pathlib
import resource
import time


def remove_logging_pycache() -> None:
    """Remove stale logging __pycache__ that causes logging errors."""

    pycache = pathlib.Path(logging.__file__).parent / "__pycache__"
    for entry in pycache.iterdir():
        try:
            entry.unlink()
        except Exception as e:
            print(f"Error deleting file {entry.name}: {e}")
    try:
        pycache.rmdir()
    except Exception as e:
        print(f"Error removing directory {pycache.name}: {e}")
    importlib.reload(logging)


def print_running_time(time_start: float) -> str:
    """Calculate and return a string with total and user running times."""
    raw_utime = resource.getrusage(resource.RUSAGE_SELF).ru_utime
    user_time = str(datetime.timedelta(0, round(raw_utime, 2)))
    total_time = str(datetime.timedelta(0, round(time.time() - time_start, 2)))
    return f"\nRunning time: {total_time[:-4]}\nUser time:    {user_time[:-4]}"
