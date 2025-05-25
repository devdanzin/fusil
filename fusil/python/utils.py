"""Utility functions for the fusil Python fuzzer."""

from __future__ import annotations

import datetime
import importlib
import logging
import pathlib
import resource
import sys
import time

from fusil.python.blacklists import MODULE_BLACKLIST


def import_all() -> None:
    """Import all standard library C modules before running the fuzzer."""
    # Currently we have to import all C modules before running the fuzzer.
    # TODO: figure out why and fix it properly.
    for name in sys.stdlib_module_names:
        if name not in MODULE_BLACKLIST and "test" not in name:
            try:
                sys.modules[name] = __import__(name)
            except ImportError as e:
                print("Failed to import module %s\n" % name, e)


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
