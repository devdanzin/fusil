"""`fleet report` -- a text (and JSON) observability report for a fusil fuzzing fleet.

Reads the per-run ``fusil_stats.json`` sidecars written by ``StatsAgent`` and enriches them
with post-hoc data (kept-crash-dir taxonomy, disk usage, systemd state, current-run
``fusil.out``) into a per-instance or whole-campaign report. Pure-Python + stdlib +
best-effort ``systemctl``/``/proc`` -- no runtime stack, so the collection/aggregation logic
unit-tests on a fixture directory.

Usage::

    python -m fusil.python.fleet_report --fleet-dir DIR            # campaign report
    python -m fusil.python.fleet_report --fleet-dir DIR 1          # instance 1 only
    python -m fusil.python.fleet_report --fleet-dir DIR --watch    # live-refresh
    python -m fusil.python.fleet_report --fleet-dir DIR --json     # machine-readable

Instance/campaign convention (borrowed from lafleur): a "campaign" is a directory whose
immediate children are ``inst-NN`` instance dirs; a single instance is one ``inst-NN`` dir.
"""

from __future__ import annotations

import argparse
import html as _html
import json
import os
import re
import subprocess
import sys
import time

from fusil.python._report_format import (
    dir_size_bytes,
    format_duration,
    format_rate,
    human_bytes,
)
from fusil.python.session_stats import SessionStats

# Crash-dir label parsing. A kept crash dir is named "<module>-<kind>-<dedup-label>[-N]",
# e.g. "_blake2-fatal_python_error-OOM-0043-2". We token-search rather than split so a
# trailing "-N" collision suffix and multi-part kinds don't confuse attribution.
#
# Mode-agnostic: every dedup engine (oom_dedup / tsan_dedup / rustpython_dedup, and any future
# one) shares a labelling convention -- a known bug is "<PREFIX>-NNN" (OOM-/TSAN-/RUSTPY-), a
# new-bug candidate is "<prefix>NEW" (oomNEW/tsanNEW/rustpyNEW), and an unresolved segv/frame is
# "<prefix>SEGV"/"tsanFRAME". Case matters: the labels use UPPERCASE NEW/SEGV while a signal
# kind is lowercase ("sigsegv"), so "[a-z]+SEGV" never matches the kind field.
_LABEL_RE = re.compile(
    r"([A-Z]+-\d{3,}"  # known dedup id: OOM-0043 / TSAN-0012 / RUSTPY-0024
    r"|[a-z]+NEW"  # new-bug candidate: oomNEW / tsanNEW / rustpyNEW
    r"|[a-z]+SEGV"  # unresolved segv: oomSEGV / rustpySEGV / tsanSEGV
    r"|[a-z]+FRAME"  # tsan non-race frame bucket: tsanFRAME
    r"|oomclean|oomimport)"  # OOM-only extra buckets
)


def new_candidate_count(by_label: dict) -> int:
    """Sum of all new-bug-candidate labels (any "<prefix>NEW"), mode-agnostic."""
    return sum(v for k, v in by_label.items() if k.endswith("NEW"))


_KIND_RE = re.compile(
    r"(fatal_python_error|systemerror|assertion|sig[a-z]{2,}|exitcode\d+|cpu_load|timeout|bug)"
)
_IMPORT_FAIL_RE = re.compile(r"target module (\S+) not importable")

STALE_HEARTBEAT_S = 180  # updated_at older than this on a running instance => "stuck?"
CHURN_RESTARTS = 5  # this many run dirs (restarts) => flag possible churn
MEM_CAP_FRACTION = 0.9  # MemoryPeak/MemoryMax above this => flag near-cap


# --------------------------------------------------------------------------- collection


def classify_crash_dir(name: str) -> tuple[str, str, str]:
    """(module, kind, dedup_label) for a kept-crash-dir basename; 'other' where unknown."""
    module = name.split("-", 1)[0]
    kind = _KIND_RE.search(name)
    label = _LABEL_RE.search(name)
    return module, (kind.group(1) if kind else "other"), (label.group(1) if label else "other")


_RUNNING_SESSION_RE = re.compile(r"^session-\d+$")


def iter_crash_dirs(inst_dir: str) -> list[str]:
    """Basenames of kept crash dirs (those holding a source.py) under inst-NN/python*/ .

    A kept crash dir is *renamed* by ``session_rename`` to ``<module>-<kind>-<label>``. A dir
    still named ``session-<N>`` is a **live running session** -- its ``source.py`` is written
    at session start, before the session is kept-as-a-crash or ``rmtree``'d -- so exclude those.
    Otherwise, on a run with few or no real crashes, the ~1 in-flight session per instance is
    miscounted as a kept crash dir (both here and in the shell ``list_crashes``).
    """
    out = []
    for run in sorted(_run_dirs(inst_dir)):
        try:
            entries = list(os.scandir(run))
        except OSError:
            continue
        for entry in entries:
            if _RUNNING_SESSION_RE.match(entry.name):
                continue  # live session, not a kept crash
            if entry.is_dir() and os.path.exists(os.path.join(entry.path, "source.py")):
                out.append(entry.name)
    return out


def _run_dirs(inst_dir: str) -> list[str]:
    """Absolute paths of the project run dirs (python, python-2, ...) = restart evidence."""
    try:
        return [
            os.path.join(inst_dir, e.name)
            for e in os.scandir(inst_dir)
            if e.is_dir() and (e.name == "python" or e.name.startswith("python-"))
        ]
    except OSError:
        return []


def load_sidecars(inst_dir: str) -> tuple[dict, dict | None]:
    """(merged across all run dirs, newest single run dict) from python*/fusil_stats.json."""
    dicts = []
    for run in _run_dirs(inst_dir):
        path = os.path.join(run, "fusil_stats.json")
        try:
            dicts.append(SessionStats.load(path))
        except (OSError, ValueError):
            continue
    if not dicts:
        return SessionStats.merge([]), None
    newest = max(dicts, key=lambda d: d.get("updated_at") or 0)
    return SessionStats.merge(dicts), newest


def systemd_info(instance_num: int, *, runner=None) -> dict:
    """Best-effort `systemctl show fusil@N` snapshot; {} if systemd/unit unavailable."""
    props = "ActiveState,SubState,NRestarts,MemoryCurrent,MemoryPeak,MemoryMax,ActiveEnterTimestamp"
    runner = runner or (
        lambda args: subprocess.run(args, capture_output=True, text=True, timeout=5)
    )
    try:
        cp = runner(["systemctl", "show", "fusil@%d" % instance_num, "--property=%s" % props])
    except Exception:
        return {}
    if getattr(cp, "returncode", 1) != 0 and not getattr(cp, "stdout", ""):
        return {}
    info = {}
    for line in (cp.stdout or "").splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            info[key] = val
    return info


def _proc_cmdline(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    return " ".join(p for p in raw.decode("utf-8", "replace").split("\0") if p) or None


def parse_fusil_out(inst_dir: str) -> tuple[dict, str | None]:
    """(failed-import module -> count, fleet-run header line) from the current-run fusil.out."""
    path = os.path.join(inst_dir, "fusil.out")
    failed: dict[str, int] = {}
    header = None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if header is None and line.startswith("# fleet-run "):
                    header = line.rstrip("\n")
                m = _IMPORT_FAIL_RE.search(line)
                if m:
                    failed[m.group(1)] = failed.get(m.group(1), 0) + 1
    except OSError:
        pass
    return failed, header


def instance_number(inst_dir: str) -> int:
    m = re.search(r"(\d+)", os.path.basename(inst_dir))
    return int(m.group(1)) if m else 0


def collect_instance(inst_dir: str, *, now=None, systemd=True) -> dict:
    """Assemble the full per-instance report dict (all metrics, pre-rendering)."""
    now = now if now is not None else time.time()
    num = instance_number(inst_dir)
    merged, current = load_sidecars(inst_dir)
    run_dirs = _run_dirs(inst_dir)

    # crash taxonomy
    by_label: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_module_crash: dict[str, int] = {}
    crash_total = 0
    for name in iter_crash_dirs(inst_dir):
        crash_total += 1
        module, kind, label = classify_crash_dir(name)
        by_label[label] = by_label.get(label, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_module_crash[module] = by_module_crash.get(module, 0) + 1

    sysd = systemd_info(num) if systemd else {}
    failed_imports, header = parse_fusil_out(inst_dir)
    pid = (current or {}).get("pid")
    cmdline = _proc_cmdline(pid) or header

    started = merged.get("started_at")
    updated = (current or {}).get("updated_at")
    elapsed = (now - started) if started else None
    hb_age = (now - updated) if updated else None
    active = sysd.get("ActiveState") == "active"
    # "running" if systemd says active, else infer from a fresh heartbeat
    running = active or (hb_age is not None and hb_age < STALE_HEARTBEAT_S)

    return {
        "instance": num,
        "dir": inst_dir,
        "gil_mode": (current or {}).get("gil_mode"),
        "pid": pid,
        "running": running,
        "systemd_state": sysd.get("ActiveState") or "?",
        "restarts": len(run_dirs),
        "nrestarts_systemd": _int_or_none(sysd.get("NRestarts")),
        "uptime_s": elapsed,
        "heartbeat_age_s": hb_age,
        "sessions": merged.get("sessions", 0),
        "kept_crashes": crash_total,
        "sidecar_crashes": merged.get("crashes", 0),
        "timeouts": merged.get("timeouts", 0),
        "cpu_load_kills": merged.get("cpu_load_kills", 0),
        "new": new_candidate_count(by_label),
        "mode": merged.get("mode") or (current or {}).get("mode"),
        "plugins": merged.get("plugins") or (current or {}).get("plugins") or [],
        "by_label": by_label,
        "by_kind": by_kind,
        "by_module_crash": by_module_crash,
        "modules": merged.get("modules", {}),
        "tsan_kinds": merged.get("tsan_kinds", {}),
        "failed_imports": failed_imports,
        "mem_current": _int_or_none(sysd.get("MemoryCurrent")),
        "mem_peak": _int_or_none(sysd.get("MemoryPeak")),
        "mem_max": _int_or_none(sysd.get("MemoryMax")),
        "disk_bytes": dir_size_bytes(inst_dir),
        "cmdline": cmdline,
    }


def _int_or_none(val):
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    # systemd reports unset/unlimited as a huge sentinel or the literal "infinity"
    if n < 0 or n >= 2**63 - 1:
        return None
    return n


def discover_instances(fleet_dir: str) -> list[str]:
    """Immediate inst-* subdirs; if fleet_dir is itself an inst-* dir, just that one."""
    base = os.path.basename(fleet_dir.rstrip("/"))
    if base.startswith("inst-"):
        return [fleet_dir]
    try:
        subs = [
            os.path.join(fleet_dir, e.name)
            for e in os.scandir(fleet_dir)
            if e.is_dir() and e.name.startswith("inst-")
        ]
    except OSError:
        return []
    return sorted(subs, key=instance_number)


def aggregate_campaign(reports: list[dict], *, now=None) -> dict:
    now = now if now is not None else time.time()
    # mode/plugins are constant across a fleet; take the first non-"normal" mode and the union
    # of plugin names, so the campaign header reports what the fleet is running.
    modes = [r.get("mode") for r in reports if r.get("mode") and r.get("mode") != "normal"]
    plugins: set[str] = set()
    for r in reports:
        plugins.update(r.get("plugins") or [])
    agg = {
        "instances": len(reports),
        "running": sum(1 for r in reports if r["running"]),
        "sessions": sum(r["sessions"] for r in reports),
        "kept_crashes": sum(r["kept_crashes"] for r in reports),
        "timeouts": sum(r["timeouts"] for r in reports),
        "new": sum(r["new"] for r in reports),
        "mode": modes[0] if modes else (reports[0].get("mode") if reports else None),
        "plugins": sorted(plugins),
        "disk_bytes": sum(r["disk_bytes"] for r in reports),
        "by_label": {},
        "by_kind": {},
        "by_module_crash": {},
        "modules": {},  # summed per-module {hits,crashes,timeouts} across instances
        "tsan_kinds": {},  # summed --tsan shared-object composition across instances
        "started_at": None,
    }
    for r in reports:
        for src, dst in (
            (r["by_label"], agg["by_label"]),
            (r["by_kind"], agg["by_kind"]),
            (r["by_module_crash"], agg["by_module_crash"]),
            (r.get("tsan_kinds", {}), agg["tsan_kinds"]),
        ):
            for key, val in src.items():
                dst[key] = dst.get(key, 0) + val
        for name, bucket in (r["modules"] or {}).items():
            acc = agg["modules"].setdefault(name, {"hits": 0, "crashes": 0, "timeouts": 0})
            for field in ("hits", "crashes", "timeouts"):
                acc[field] += int(bucket.get(field, 0) or 0)
        started = r["uptime_s"]
        if started is not None:
            start_epoch = now - started
            if agg["started_at"] is None or start_epoch < agg["started_at"]:
                agg["started_at"] = start_epoch
    agg["elapsed_s"] = (now - agg["started_at"]) if agg["started_at"] else None
    return agg


def anomalies(reports: list[dict]) -> list[tuple[int, str]]:
    """(instance_num, reason) flags -- the health section."""
    out = []
    for r in reports:
        if r["systemd_state"] not in ("active", "?"):
            out.append((r["instance"], "systemd state=%s (down/failed)" % r["systemd_state"]))
        elif r["heartbeat_age_s"] is not None and r["heartbeat_age_s"] > STALE_HEARTBEAT_S:
            out.append(
                (
                    r["instance"],
                    "stale heartbeat %s (stuck?)" % format_duration(r["heartbeat_age_s"]),
                )
            )
        if r["restarts"] >= CHURN_RESTARTS:
            out.append((r["instance"], "%d run dirs (churn/restarts?)" % r["restarts"]))
        if r["mem_peak"] and r["mem_max"] and r["mem_peak"] / r["mem_max"] > MEM_CAP_FRACTION:
            out.append(
                (
                    r["instance"],
                    "memory %s near cap %s"
                    % (human_bytes(r["mem_peak"]), human_bytes(r["mem_max"])),
                )
            )
    return out


# ---------------------------------------------------------------------------- rendering


def _top(counter: dict, n: int) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def _taxo(counter: dict) -> str:
    return ", ".join("%s=%d" % (k, v) for k, v in _top(counter, 12)) or "(none)"


def crash_rate_modules(
    modules: dict, *, min_hits: int = 5, n: int = 8
) -> list[tuple[str, float, int]]:
    """(module, crash_rate_pct, hits) for modules with >= min_hits, most-crash-prone first.

    Surfaces which fuzzed modules most reliably produce crashes (crashes/hits) -- the
    productivity signal counts alone miss (a high-hit module with few crashes is quiet;
    a module that crashes on nearly every hit is a hot target)."""
    rows = []
    for name, b in modules.items():
        hits = int(b.get("hits", 0) or 0)
        if hits >= min_hits:
            rows.append((name, 100.0 * int(b.get("crashes", 0) or 0) / hits, hits))
    rows.sort(key=lambda r: (-r[1], -r[2], r[0]))
    return rows[:n]


def _rate_str(modules: dict) -> str:
    rows = crash_rate_modules(modules)
    return ", ".join("%s(%.0f%%/%d)" % (m, rate, hits) for m, rate, hits in rows) or "(none)"


def render_instance(r: dict) -> str:
    L = []
    L.append("=" * 72)
    L.append(
        "fusil instance %-2d  [%s]  gil=%s  pid=%s"
        % (
            r["instance"],
            "running" if r["running"] else "stopped",
            r["gil_mode"] if r["gil_mode"] is not None else "?",
            r["pid"] or "?",
        )
    )
    L.append("=" * 72)
    L.append(
        "mode %s   plugins %s"
        % (r.get("mode") or "?", ", ".join(r.get("plugins") or []) or "(none)")
    )
    L.append(
        "uptime %-10s  restarts %-3d  heartbeat %s ago"
        % (format_duration(r["uptime_s"]), r["restarts"], format_duration(r["heartbeat_age_s"]))
    )
    to_pct = (100.0 * r["timeouts"] / r["sessions"]) if r["sessions"] else 0.0
    find = (1000.0 * r["kept_crashes"] / r["sessions"]) if r["sessions"] else 0.0
    L.append(
        "sessions %-8d (%s)  crashes %-5d (%.1f/1k)  timeouts %d (%.1f%%)  cpu-kills %d"
        % (
            r["sessions"],
            format_rate(r["sessions"], r["uptime_s"]),
            r["kept_crashes"],
            find,
            r["timeouts"],
            to_pct,
            r["cpu_load_kills"],
        )
    )
    L.append("-" * 72)
    L.append("crashes by label: %s" % _taxo(r["by_label"]))
    L.append("crashes by kind : %s" % _taxo(r["by_kind"]))
    L.append("-" * 72)
    hits = {m: b.get("hits", 0) for m, b in r["modules"].items()}
    L.append(
        "top modules (hits): %s"
        % (", ".join("%s(%d)" % (m, h) for m, h in _top(hits, 8)) or "(none)")
    )
    L.append(
        "crash-productive   : %s"
        % (", ".join("%s(%d)" % (m, c) for m, c in _top(r["by_module_crash"], 8)) or "(none)")
    )
    L.append("crash-rate (c/hits): %s" % _rate_str(r["modules"]))
    if r.get("tsan_kinds"):
        L.append("tsan shared-obj    : %s" % _taxo(r["tsan_kinds"]))
    if r["failed_imports"]:
        L.append(
            "failed imports     : %s"
            % ", ".join("%s(%d)" % (m, c) for m, c in _top(r["failed_imports"], 8))
        )
    L.append("-" * 72)
    L.append(
        "memory %s (peak %s / cap %s)   disk %s"
        % (
            human_bytes(r["mem_current"]),
            human_bytes(r["mem_peak"]),
            human_bytes(r["mem_max"]),
            human_bytes(r["disk_bytes"]),
        )
    )
    if r["cmdline"]:
        L.append("cmd: %s" % r["cmdline"])
    return "\n".join(L)


def render_campaign(
    reports: list[dict], agg: dict, flags: list[tuple[int, str]], fleet_dir: str | None = None
) -> str:
    L = []
    L.append("=" * 84)
    L.append(
        "FUSIL FLEET  --  %d instances (%d running)  elapsed %s  disk %s"
        % (
            agg["instances"],
            agg["running"],
            format_duration(agg["elapsed_s"]),
            human_bytes(agg["disk_bytes"]),
        )
    )
    L.append(
        "mode %s   plugins %s%s"
        % (
            agg.get("mode") or "?",
            ", ".join(agg.get("plugins") or []) or "(none)",
            ("   dir %s" % fleet_dir) if fleet_dir else "",
        )
    )
    find = (1000.0 * agg["kept_crashes"] / agg["sessions"]) if agg["sessions"] else 0.0
    L.append(
        "sessions %-9d (%s)  crashes %-6d (%.1f/1k)  NEW %d  timeouts %d"
        % (
            agg["sessions"],
            format_rate(agg["sessions"], agg["elapsed_s"]),
            agg["kept_crashes"],
            find,
            agg["new"],
            agg["timeouts"],
        )
    )
    L.append("=" * 84)
    L.append(
        "%-3s %-4s %-8s %-9s %9s %8s %6s %5s %5s %8s %7s"
        % ("#", "gil", "state", "uptime", "sessions", "s/min", "crash", "NEW", "TO%", "mem", "disk")
    )
    L.append("-" * 84)
    for r in reports:
        to_pct = (100.0 * r["timeouts"] / r["sessions"]) if r["sessions"] else 0.0
        L.append(
            "%-3d %-4s %-8s %-9s %9d %8s %6d %5d %4.0f%% %8s %7s"
            % (
                r["instance"],
                r["gil_mode"] if r["gil_mode"] is not None else "?",
                "run" if r["running"] else "stop",
                format_duration(r["uptime_s"]),
                r["sessions"],
                format_rate(r["sessions"], r["uptime_s"]).replace("/m", ""),
                r["kept_crashes"],
                r["new"],
                to_pct,
                human_bytes(r["mem_current"]),
                human_bytes(r["disk_bytes"]),
            )
        )
    L.append("-" * 84)
    L.append("fleet crashes by label: %s" % _taxo(agg["by_label"]))
    L.append("fleet crashes by kind : %s" % _taxo(agg["by_kind"]))
    L.append(
        "most crash-productive : %s"
        % (", ".join("%s(%d)" % (m, c) for m, c in _top(agg["by_module_crash"], 10)) or "(none)")
    )
    L.append("highest crash-rate    : %s" % _rate_str(agg.get("modules", {})))
    if agg.get("tsan_kinds"):
        L.append("tsan shared-obj       : %s" % _taxo(agg["tsan_kinds"]))
    L.append("-" * 84)
    if flags:
        L.append("HEALTH: %d flag(s)" % len(flags))
        for num, reason in flags:
            L.append("  ! inst-%02d: %s" % (num, reason))
    else:
        L.append("HEALTH: all instances nominal")
    return "\n".join(L)


# ------------------------------------------------------------------------- HTML dashboard
#
# A self-contained (single-file, zero-asset) dashboard -- KPI cards, a click-to-sort instance
# leaderboard, bar-in-cell taxonomy/module panels, and health badges. Embedded CSS+JS in the
# spirit of lafleur's campaign dashboard (imitated, not imported); no coverage/lineage columns.

_CSS = (
    ":root{--bg:#0f1720;--card:#182430;--fg:#dfe7ee;--mut:#8aa0b4;--acc:#4aa3ff;"
    "--ok:#2ecc71;--bad:#ff6b6b;--bar:#2b5a8c}"
    "*{box-sizing:border-box}body{margin:0;padding:20px;background:var(--bg);color:var(--fg);"
    "font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}"
    "h1{font-size:18px;margin:0 0 14px}h1 .sub{font-size:12px;color:var(--mut);font-weight:400}"
    "h2{font-size:14px;margin:22px 0 8px;color:var(--acc)}h3{font-size:12px;margin:0 0 6px;color:var(--mut)}"
    ".kpis{display:flex;flex-wrap:wrap;gap:10px}.kpi{background:var(--card);border-radius:8px;"
    "padding:10px 14px;min-width:96px}.kpi .v{font-size:20px;font-weight:600}.kpi .l{font-size:11px;color:var(--mut)}"
    ".health{margin:14px 0;padding:10px 14px;border-radius:8px;background:var(--card)}"
    ".health.ok{border-left:4px solid var(--ok)}.health.bad{border-left:4px solid var(--bad)}"
    ".health ul{margin:6px 0 0;padding-left:18px}"
    "table{border-collapse:collapse;width:100%;background:var(--card);border-radius:8px;overflow:hidden}"
    "th,td{padding:6px 10px;text-align:right;white-space:nowrap}"
    "th:first-child,td:first-child,td.k{text-align:left}"
    "thead th{background:#0c141c;color:var(--mut);cursor:pointer;user-select:none}"
    "thead th:hover{color:var(--fg)}tbody tr:nth-child(even){background:rgba(255,255,255,.02)}"
    ".badge{padding:2px 7px;border-radius:10px;font-size:11px}"
    ".badge.run{background:rgba(46,204,113,.2);color:var(--ok)}"
    ".badge.stop{background:rgba(255,107,107,.2);color:var(--bad)}"
    ".cols{display:flex;gap:14px;flex-wrap:wrap;margin-top:8px}.panel{flex:1;min-width:320px}"
    "table.bars td.b{width:55%}table.bars td.b span{display:block;height:12px;background:var(--bar);border-radius:3px}"
    "table.bars td.k{max-width:220px;overflow:hidden;text-overflow:ellipsis}"
)

_SORT_JS = (
    "document.querySelectorAll('table.sortable thead th').forEach(function(th,i){var asc=true;"
    "th.addEventListener('click',function(){var tb=th.closest('table').tBodies[0];"
    "var rows=Array.prototype.slice.call(tb.rows);rows.sort(function(a,b){"
    "var x=a.cells[i],y=b.cells[i];var xv=x.getAttribute('data-sort'),yv=y.getAttribute('data-sort');"
    "if(xv!==null&&yv!==null){return (parseFloat(xv)-parseFloat(yv))*(asc?1:-1);}"
    "return x.textContent.localeCompare(y.textContent)*(asc?1:-1);});asc=!asc;"
    "rows.forEach(function(r){tb.appendChild(r);});});});"
)


def _esc(s) -> str:
    return _html.escape(str(s), quote=True)


def _num_td(display, sortval) -> str:
    return "<td data-sort='%s'>%s</td>" % (_esc(sortval), _esc(display))


def _bars_panel(title: str, counter: dict, n: int = 12) -> str:
    rows = _top(counter, n)
    mx = max((v for _, v in rows), default=1) or 1
    out = ["<div class=panel><h3>%s</h3><table class=bars>" % _esc(title)]
    for k, v in rows:
        out.append(
            "<tr><td class=k>%s</td><td class=b><span style='width:%.1f%%'></span></td>"
            "<td>%d</td></tr>" % (_esc(k), 100.0 * v / mx, v)
        )
    if not rows:
        out.append("<tr><td class=k>(none)</td></tr>")
    out.append("</table></div>")
    return "".join(out)


def _rate_panel(title: str, modules: dict) -> str:
    rows = crash_rate_modules(modules, n=12)
    out = ["<div class=panel><h3>%s</h3><table class=bars>" % _esc(title)]
    for m, rate, hits in rows:
        out.append(
            "<tr><td class=k>%s</td><td class=b><span style='width:%.1f%%'></span></td>"
            "<td>%.0f%% /%d</td></tr>" % (_esc(m), rate, rate, hits)
        )
    if not rows:
        out.append("<tr><td class=k>(none)</td></tr>")
    out.append("</table></div>")
    return "".join(out)


def render_html(report: dict, *, generated: str | None = None) -> str:
    reports = report["instances"]
    agg = report["campaign"]
    flags = report["anomalies"]
    gen = generated if generated is not None else time.strftime("%Y-%m-%d %H:%M:%S")
    find = (1000.0 * agg["kept_crashes"] / agg["sessions"]) if agg["sessions"] else 0.0
    p = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        "<title>fusil fleet report</title><style>%s</style></head><body>" % _CSS,
        "<h1>fusil fleet <span class=sub>mode %s &middot; plugins %s &middot; %d instances "
        "&middot; %d running &middot; elapsed %s &middot; generated %s</span></h1>"
        % (
            _esc(agg.get("mode") or "?"),
            _esc(", ".join(agg.get("plugins") or []) or "(none)"),
            agg["instances"],
            agg["running"],
            _esc(format_duration(agg["elapsed_s"])),
            _esc(gen),
        ),
        "<div class=kpis>",
    ]
    for label, value in (
        ("sessions", "{:,}".format(agg["sessions"])),
        ("throughput", format_rate(agg["sessions"], agg["elapsed_s"])),
        ("crashes", "{:,}".format(agg["kept_crashes"])),
        ("find rate", "%.1f/1k" % find),
        ("NEW", agg["new"]),
        ("timeouts", agg["timeouts"]),
        ("disk", human_bytes(agg["disk_bytes"])),
    ):
        p.append(
            "<div class=kpi><div class=v>%s</div><div class=l>%s</div></div>"
            % (_esc(value), _esc(label))
        )
    p.append("</div>")

    if flags:
        p.append("<div class='health bad'><b>HEALTH: %d flag(s)</b><ul>" % len(flags))
        for num, reason in flags:
            p.append("<li>inst-%02d: %s</li>" % (num, _esc(reason)))
        p.append("</ul></div>")
    else:
        p.append("<div class='health ok'><b>HEALTH: all instances nominal</b></div>")

    p.append("<h2>instances</h2><table class=sortable><thead><tr>")
    for label in (
        "#",
        "gil",
        "state",
        "uptime",
        "sessions",
        "s/min",
        "crash",
        "NEW",
        "TO%",
        "mem",
        "disk",
    ):
        p.append("<th>%s</th>" % _esc(label))
    p.append("</tr></thead><tbody>")
    for r in reports:
        to_pct = (100.0 * r["timeouts"] / r["sessions"]) if r["sessions"] else 0.0
        spm = (r["sessions"] / (r["uptime_s"] / 60.0)) if r["uptime_s"] else 0.0
        badge = "run" if r["running"] else "stop"
        p.append("<tr>")
        p.append(_num_td(r["instance"], r["instance"]))
        p.append("<td>%s</td>" % _esc(r["gil_mode"] if r["gil_mode"] is not None else "?"))
        p.append("<td><span class='badge %s'>%s</span></td>" % (badge, badge))
        p.append(_num_td(format_duration(r["uptime_s"]), r["uptime_s"] or 0))
        p.append(_num_td("{:,}".format(r["sessions"]), r["sessions"]))
        p.append(_num_td("%.1f" % spm, spm))
        p.append(_num_td("{:,}".format(r["kept_crashes"]), r["kept_crashes"]))
        p.append(_num_td(r["new"], r["new"]))
        p.append(_num_td("%.0f%%" % to_pct, to_pct))
        p.append(
            _num_td(human_bytes(r["mem_current"]), r["mem_current"] if r["mem_current"] else -1)
        )
        p.append(_num_td(human_bytes(r["disk_bytes"]), r["disk_bytes"]))
        p.append("</tr>")
    p.append("</tbody></table>")

    p.append("<h2>crash taxonomy</h2><div class=cols>")
    p.append(_bars_panel("by dedup label", agg["by_label"]))
    p.append(_bars_panel("by kind", agg["by_kind"]))
    p.append("</div>")
    p.append("<h2>modules</h2><div class=cols>")
    p.append(_bars_panel("most crash-productive (crashes)", agg["by_module_crash"]))
    p.append(_rate_panel("highest crash-rate (crashes/hits, &ge;5 hits)", agg.get("modules", {})))
    p.append("</div>")
    p.append("<script>%s</script></body></html>" % _SORT_JS)
    return "".join(p)


# --------------------------------------------------------------------------------- CLI


def build_report(fleet_dir: str, instance: int | None, *, systemd=True, now=None) -> dict:
    """Collect everything; returns {"instances": [...], "campaign": {...}, "anomalies": [...]}."""
    inst_dirs = discover_instances(fleet_dir)
    if instance is not None:
        inst_dirs = [d for d in inst_dirs if instance_number(d) == instance]
    reports = [collect_instance(d, now=now, systemd=systemd) for d in inst_dirs]
    return {
        "fleet_dir": fleet_dir,
        "instances": reports,
        "campaign": aggregate_campaign(reports, now=now),
        "anomalies": anomalies(reports),
    }


def render(report: dict, instance: int | None) -> str:
    reports = report["instances"]
    if not reports:
        return "no instances found"
    if instance is not None:
        return "\n".join(render_instance(r) for r in reports)
    return render_campaign(
        reports, report["campaign"], report["anomalies"], report.get("fleet_dir")
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="fleet_report", description="fusil fleet observability report"
    )
    ap.add_argument(
        "--fleet-dir", required=True, help="campaign dir (parent of inst-*/) or one inst-* dir"
    )
    ap.add_argument("instance", nargs="?", type=int, help="report only this instance number")
    ap.add_argument("--watch", action="store_true", help="live-refresh the report")
    ap.add_argument(
        "--interval", type=float, default=5.0, help="--watch refresh seconds (default 5)"
    )
    ap.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON instead of text"
    )
    ap.add_argument("--html", metavar="PATH", help="write a self-contained HTML dashboard to PATH")
    ap.add_argument("--no-systemd", action="store_true", help="skip systemctl enrichment")
    args = ap.parse_args(argv)

    def once():
        rep = build_report(args.fleet_dir, args.instance, systemd=not args.no_systemd)
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_html(rep))
            return "wrote HTML dashboard: %s" % args.html
        if args.json:
            return json.dumps(rep, default=str)
        return render(rep, args.instance)

    if not args.watch:
        print(once())
        return 0
    try:
        while True:
            sys.stdout.write("\033[2J\033[H")  # clear + home
            sys.stdout.write(once() + "\n")
            sys.stdout.flush()
            time.sleep(max(1.0, args.interval))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
