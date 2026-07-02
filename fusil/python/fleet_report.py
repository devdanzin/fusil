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
_LABEL_RE = re.compile(r"(OOM-\d{3,}|oomNEW|oomSEGV|oomclean|oomimport)")
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


def iter_crash_dirs(inst_dir: str) -> list[str]:
    """Basenames of kept crash dirs (those holding a source.py) under inst-NN/python*/ ."""
    out = []
    for run in sorted(_run_dirs(inst_dir)):
        try:
            entries = list(os.scandir(run))
        except OSError:
            continue
        for entry in entries:
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
        "oomnew": by_label.get("oomNEW", 0),
        "by_label": by_label,
        "by_kind": by_kind,
        "by_module_crash": by_module_crash,
        "modules": merged.get("modules", {}),
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
    agg = {
        "instances": len(reports),
        "running": sum(1 for r in reports if r["running"]),
        "sessions": sum(r["sessions"] for r in reports),
        "kept_crashes": sum(r["kept_crashes"] for r in reports),
        "timeouts": sum(r["timeouts"] for r in reports),
        "oomnew": sum(r["oomnew"] for r in reports),
        "disk_bytes": sum(r["disk_bytes"] for r in reports),
        "by_label": {},
        "by_kind": {},
        "by_module_crash": {},
        "started_at": None,
    }
    for r in reports:
        for src, dst in (
            (r["by_label"], agg["by_label"]),
            (r["by_kind"], agg["by_kind"]),
            (r["by_module_crash"], agg["by_module_crash"]),
        ):
            for key, val in src.items():
                dst[key] = dst.get(key, 0) + val
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


def render_campaign(reports: list[dict], agg: dict, flags: list[tuple[int, str]]) -> str:
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
    find = (1000.0 * agg["kept_crashes"] / agg["sessions"]) if agg["sessions"] else 0.0
    L.append(
        "sessions %-9d (%s)  crashes %-6d (%.1f/1k)  oomNEW %d  timeouts %d"
        % (
            agg["sessions"],
            format_rate(agg["sessions"], agg["elapsed_s"]),
            agg["kept_crashes"],
            find,
            agg["oomnew"],
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
                r["oomnew"],
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
    L.append("-" * 84)
    if flags:
        L.append("HEALTH: %d flag(s)" % len(flags))
        for num, reason in flags:
            L.append("  ! inst-%02d: %s" % (num, reason))
    else:
        L.append("HEALTH: all instances nominal")
    return "\n".join(L)


# --------------------------------------------------------------------------------- CLI


def build_report(fleet_dir: str, instance: int | None, *, systemd=True, now=None) -> dict:
    """Collect everything; returns {"instances": [...], "campaign": {...}, "anomalies": [...]}."""
    inst_dirs = discover_instances(fleet_dir)
    if instance is not None:
        inst_dirs = [d for d in inst_dirs if instance_number(d) == instance]
    reports = [collect_instance(d, now=now, systemd=systemd) for d in inst_dirs]
    return {
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
    return render_campaign(reports, report["campaign"], report["anomalies"])


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
    ap.add_argument("--no-systemd", action="store_true", help="skip systemctl enrichment")
    args = ap.parse_args(argv)

    def once():
        rep = build_report(args.fleet_dir, args.instance, systemd=not args.no_systemd)
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
