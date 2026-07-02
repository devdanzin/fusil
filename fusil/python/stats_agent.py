"""StatsAgent: a score-neutral ProjectAgent that accumulates per-session fuzzing stats
and flushes them to the ``fusil_stats.json`` sidecar for the fleet reporter to read.

It observes the session event stream in the parent fusil process -- one increment per
finished session -- and never influences scoring (it does not override ``getScore()``, so
``Session.computeScore`` skips it). The pure counter/serialisation logic lives in
``session_stats.py``; this file is only the MAS glue.

Wiring: constructed in ``Fuzzer.setupProject`` as ``StatsAgent(project, self.source)`` --
``ProjectAgent.__init__`` auto-registers it, and it is activated with every session.
"""

from __future__ import annotations

import os
import time

from fusil.project_agent import ProjectAgent
from fusil.python.session_stats import SessionStats

SIDECAR_NAME = "fusil_stats.json"
_FLUSH_INTERVAL = 1.0  # seconds; the sidecar lags in-memory counters by at most this


class StatsAgent(ProjectAgent):
    """Fold each finished session into a ``SessionStats`` and periodically write the sidecar.

    Counters live on the instance (``__init__``), NOT in ``init()``, because a ProjectAgent's
    ``init()``/``deinit()`` run once per *session* -- putting them in ``init()`` would reset
    them every session.
    """

    def __init__(self, project, source):
        ProjectAgent.__init__(self, project, "stats")
        self.source = source  # the PythonSource agent -- read .module_name per session
        run_dir = None
        try:
            run_dir = os.path.basename(project.directory.directory)
        except Exception:
            pass
        self.stats = SessionStats(
            gil_mode=os.environ.get("PYTHON_GIL"),
            pid=os.getpid(),
            run_dir=run_dir,
        )
        self._path = None  # resolved lazily on first flush
        self._rename_parts: list[str] = []
        self._last_flush = 0.0

    # --- session event stream ---------------------------------------------------------

    def on_session_start(self):
        # Fresh per-session label accumulator; the rename parts (module, signal, "timeout",
        # "cpu_load", oom bug-id, ...) all arrive on the shared session_rename channel.
        self._rename_parts = []

    def on_session_rename(self, part):
        self._rename_parts.append(part)

    def on_session_done(self, score):
        project = self.project()
        success = getattr(project, "success_score", 0.5) if project else 0.5
        crash = score is not None and score >= success
        module = getattr(self.source, "module_name", None)
        self.stats.record(
            module,
            crash=crash,
            timeout="timeout" in self._rename_parts,
            cpu_load="cpu_load" in self._rename_parts,
        )
        self._maybe_flush()

    def on_univers_stop(self):
        # Best-effort final flush at shutdown (may be a no-op if already deactivated).
        self._maybe_flush(force=True)

    # --- sidecar io -------------------------------------------------------------------

    def _sidecar_path(self):
        if self._path is None:
            project = self.project()
            if project is None:
                return None
            # createFilename registers the name in the run dir's tracked-files set, so the
            # sidecar is well-defined w.r.t. ProjectDirectory retention rather than looking
            # like a stray foreign file.
            self._path = project.createFilename(SIDECAR_NAME)
        return self._path

    def _maybe_flush(self, force=False):
        now = time.monotonic()
        if not force and (now - self._last_flush) < _FLUSH_INTERVAL:
            return
        path = self._sidecar_path()
        if not path:
            return
        try:
            self.stats.write(path)
            self._last_flush = now
        except Exception as err:
            # Observability must never break fuzzing; log and carry on.
            self.error("StatsAgent: failed to write %s: %s" % (path, err))
