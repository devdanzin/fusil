"""Small, dependency-free text-formatting helpers for the fleet reporter.

Adapted from lafleur's observability layer (``lafleur/utils.py``, ``lafleur/report.py``) --
copied rather than imported so fusil takes no dependency on lafleur. Pure stdlib.
"""

from __future__ import annotations

import os


def human_bytes(n: float | None) -> str:
    """1536 -> '1.5K', 1234567890 -> '1.1G'. None/negative -> '-'."""
    if n is None or n < 0:
        return "-"
    n = float(n)
    for unit in ("B", "K", "M", "G", "T", "P"):
        if n < 1024 or unit == "P":
            if unit == "B":
                return "%dB" % int(n)
            return "%.1f%s" % (n, unit)
        n /= 1024
    return "%.1fP" % n


def format_duration(seconds: float | None) -> str:
    """90061 -> '1d 1h', 305 -> '5m 5s', None -> '-'. Two most-significant units."""
    if seconds is None or seconds < 0:
        return "-"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts += ["%dd" % days, "%dh" % hours]
    elif hours:
        parts += ["%dh" % hours, "%dm" % minutes]
    elif minutes:
        parts += ["%dm" % minutes, "%ds" % secs]
    else:
        parts = ["%ds" % secs]
    return " ".join(parts[:2])


def format_rate(count: int, seconds: float | None) -> str:
    """Per-minute rate, e.g. 3092 sessions over 2h -> '25.8/m'. '-' if no elapsed time."""
    if not seconds or seconds <= 0:
        return "-"
    return "%.1f/m" % (count / (seconds / 60.0))


def dir_size_bytes(path: str) -> int:
    """Total size of a directory tree in bytes (best-effort; unreadable entries skipped)."""
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total
