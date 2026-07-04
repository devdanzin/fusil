"""Utility functions for the fusil Python fuzzer."""

from __future__ import annotations

import datetime
import resource
import time


def format_duration(seconds: float) -> str:
    """Format a duration as ``H:MM:SS.ss`` (two fractional digits).

    Robust to whole-second durations: ``datetime.timedelta``'s ``str`` omits the fractional
    part for integral seconds, so a naive "slice off microseconds" corrupts e.g. ``0:01:30``
    into ``0:0``. This always renders exactly two fractional digits.
    """
    text = str(datetime.timedelta(seconds=round(seconds, 2)))
    if "." in text:
        head, frac = text.split(".", 1)
        return f"{head}.{frac[:2]}"
    return f"{text}.00"


def print_running_time(time_start: float) -> str:
    """Return a summary of total (wall-clock) and user CPU time since ``time_start``."""
    user_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
    total_time = time.time() - time_start
    return (
        f"\nRunning time: {format_duration(total_time)}\nUser time:    {format_duration(user_time)}"
    )
