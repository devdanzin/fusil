"""Per-run fuzzing statistics: a small, pure-Python accumulator + its JSON sidecar.

This is the write side of fleet observability. ``StatsAgent`` (stats_agent.py) feeds a
``SessionStats`` one call per finished session; the reporter (fleet_report.py) reads the
emitted ``fusil_stats.json`` sidecars back and aggregates them across a fleet.

Kept deliberately free of the ``python-ptrace`` runtime stack (only stdlib) so it unit-tests
in isolation -- same split as ``oom_dedup.py``. The MAS wiring lives in ``stats_agent.py``.

Sidecar schema (v1)::

    {
      "schema": 1,
      "gil_mode": "0",            # PYTHON_GIL for this instance ("0"/"1"/None)
      "pid": 12345,               # the fusil parent pid
      "run_dir": "python-2",      # basename of the project run directory
      "started_at": 1751450700.0, # epoch seconds, run start
      "updated_at": 1751467000.0, # epoch seconds, last flush (heartbeat/liveness)
      "sessions": 3092,           # sessions finished
      "crashes": 112,             # sessions scored as a success/finding
      "timeouts": 70,             # sessions the target-process timeout fired on
      "cpu_load_kills": 5,        # sessions the CPU-load watcher killed
      "modules": {                # per-target-module breakdown
        "_blake2": {"hits": 15, "crashes": 3, "timeouts": 0},
        ...
      }
    }
"""

from __future__ import annotations

import json
import os
import time
from typing import Callable

SCHEMA_VERSION = 1


class SessionStats:
    """In-memory per-run counters, serialisable to the ``fusil_stats.json`` sidecar.

    ``clock`` is injectable so tests can pin ``updated_at`` deterministically.
    """

    def __init__(
        self,
        *,
        gil_mode: str | None = None,
        pid: int | None = None,
        run_dir: str | None = None,
        started_at: float | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self.gil_mode = gil_mode
        self.pid = pid
        self.run_dir = run_dir
        self.started_at = started_at if started_at is not None else clock()
        self.updated_at = self.started_at
        self.sessions = 0
        self.crashes = 0
        self.timeouts = 0
        self.cpu_load_kills = 0
        # module name -> {"hits": int, "crashes": int, "timeouts": int}
        self.modules: dict[str, dict[str, int]] = {}

    def record(
        self,
        module: str | None,
        *,
        crash: bool = False,
        timeout: bool = False,
        cpu_load: bool = False,
    ) -> None:
        """Fold one finished session into the counters."""
        self.sessions += 1
        if crash:
            self.crashes += 1
        if timeout:
            self.timeouts += 1
        if cpu_load:
            self.cpu_load_kills += 1
        # ``module`` can legitimately be None very early (before the first module loads);
        # bucket those under "?" rather than dropping the session from the module view.
        key = module or "?"
        bucket = self.modules.get(key)
        if bucket is None:
            bucket = {"hits": 0, "crashes": 0, "timeouts": 0}
            self.modules[key] = bucket
        bucket["hits"] += 1
        if crash:
            bucket["crashes"] += 1
        if timeout:
            bucket["timeouts"] += 1
        self.updated_at = self._clock()

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA_VERSION,
            "gil_mode": self.gil_mode,
            "pid": self.pid,
            "run_dir": self.run_dir,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "sessions": self.sessions,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "cpu_load_kills": self.cpu_load_kills,
            "modules": self.modules,
        }

    def write(self, path: str) -> None:
        """Atomically write the sidecar (tmp + os.replace) so a reader never sees a partial file."""
        tmp = "%s.tmp%d" % (path, os.getpid())
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> dict:
        """Read a sidecar file back to a plain dict (reporter side). Raises on bad JSON/IO."""
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def merge(dicts: list[dict]) -> dict:
        """Aggregate several sidecar dicts (e.g. an instance's python-*/ run dirs) into one.

        Scalar counters sum; per-module counters sum; ``started_at`` is the earliest and
        ``updated_at`` the latest seen. Used by the reporter for campaign/instance rollups.
        """
        out = {
            "schema": SCHEMA_VERSION,
            "sessions": 0,
            "crashes": 0,
            "timeouts": 0,
            "cpu_load_kills": 0,
            "modules": {},
            "started_at": None,
            "updated_at": None,
            "runs": 0,
        }
        for d in dicts:
            if not d:
                continue
            out["runs"] += 1
            for key in ("sessions", "crashes", "timeouts", "cpu_load_kills"):
                out[key] += int(d.get(key, 0) or 0)
            for name, bucket in (d.get("modules") or {}).items():
                acc = out["modules"].setdefault(name, {"hits": 0, "crashes": 0, "timeouts": 0})
                for field in ("hits", "crashes", "timeouts"):
                    acc[field] += int(bucket.get(field, 0) or 0)
            started = d.get("started_at")
            if started is not None and (out["started_at"] is None or started < out["started_at"]):
                out["started_at"] = started
            updated = d.get("updated_at")
            if updated is not None and (out["updated_at"] is None or updated > out["updated_at"]):
                out["updated_at"] = updated
        return out
