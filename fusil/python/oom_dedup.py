"""In-loop crash dedupe for the OOM Python fuzzer.

Pure-Python and free of any runtime (python-ptrace) dependency, so it unit-tests in
isolation. It loads the known-sites snapshot produced by the cpython-oom-findings
catalog (``gen_known_sites.py`` -> ``known_sites.tsv``) and, given a crash's captured
stdout, decides whether the crash is a *known* bug (and how many we've already kept) so
the fuzzer can prune duplicates in-loop and self-label each crash directory.

Tier-1 resolution only: aborts and fatals carry an exact ``file:line: func(): Assertion``
/ ``Fatal Python error: <msg>`` in stdout and dedupe build-stably for free. Segvs have
no reliable C site in stdout and are returned ``unresolved`` -- never pruned here; a
later phase resolves them via the debugger. The snapshot file format is the contract
shared with the catalog's ``ingest.py``.
"""
import re
import os
import collections
import subprocess

# ---- stdout classification (mirrors catalog ingest.py tier-1) ----
ASSERT = re.compile(r"([\w./+-]+\.(?:c|h)):(\d+):[^\n]*?\b(\w+)\s*\([^)]*\)\s*:\s*Assertion `([^']*)' failed")
ASSERT2 = re.compile(r"([\w./+-]+\.(?:c|h)):(\d+):[^\n]*?Assertion `([^']*)' failed")
FATAL = re.compile(r'Fatal Python error:\s*([^\n]+)')
SEGV = re.compile(r'AddressSanitizer: SEGV|Fatal Python error: Segmentation fault|Segmentation fault')
GENERIC_FATAL = ("_PyObject_AssertFailed", "_Py_NegativeRefcount")


def _nf(f):
    return f.lstrip("./")


def classify(text):
    """Classify a crash from its stdout. Returns a dict with ``kind`` in
    {abort, fatal, segv, import, clean} plus any resolved file/line/func/assert/msg."""
    m = ASSERT.search(text) or ASSERT2.search(text)
    if m:
        g = m.groups()
        f, ln, func, expr = g if len(g) == 4 else (g[0], g[1], None, g[2])
        return dict(kind="abort", file=_nf(f), line=int(ln), func=func,
                    assert_expr=expr.strip(), fatal_msg=None)
    fa = FATAL.search(text)
    if fa and not SEGV.search(text):
        msg = fa.group(1).strip()
        if msg.startswith(GENERIC_FATAL):       # carries no site -> treat like segv
            return dict(kind="segv", file=None, line=None, func=None,
                        assert_expr=None, fatal_msg=None)
        return dict(kind="fatal", file=None, line=None, func=None,
                    assert_expr=None, fatal_msg=msg[:60])
    if SEGV.search(text):
        return dict(kind="segv", file=None, line=None, func=None,
                    assert_expr=None, fatal_msg=None)
    if re.search(r'(ModuleNotFoundError|ImportError):', text):
        return dict(kind="import")
    return dict(kind="clean")


# ---- snapshot loading + matching (mirrors catalog ingest.py) ----
def load_snapshot(lines):
    """Load ``known_sites.tsv`` rows (an iterable of lines) into matcher tables."""
    by_func, by_assert, by_line = {}, {}, {}
    per_file_lines = collections.defaultdict(list)
    by_msg, kind_of = [], {}
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        oid, kind, kt, key = parts
        kind_of[oid] = kind
        if kt == "func":
            by_func.setdefault(key, set()).add(oid)
        elif kt == "assert":
            by_assert.setdefault(key, set()).add(oid)
        elif kt == "msg":
            by_msg.append((key, oid))
        elif kt == "line":
            f, ln = key.rsplit(":", 1)
            by_line.setdefault((f, int(ln)), set()).add(oid)
            per_file_lines[f].append((int(ln), oid))
    return dict(func=by_func, assert_=by_assert, line=by_line,
                fl=per_file_lines, msg=by_msg, kind=kind_of)


def load_snapshot_file(path):
    with open(path) as fh:
        return load_snapshot(fh)


def match(c, snap):
    """Return (oom_ids:set, how:str). Empty set + 'NEW' if unmatched."""
    if c.get("assert_expr") and c.get("file"):
        hit = snap["assert_"].get("%s:%s" % (c["file"], c["assert_expr"]))
        if hit:
            return hit, "assert"
    if c.get("fatal_msg"):
        hit = set(o for k, o in snap["msg"]
                  if c["fatal_msg"].startswith(k) or k.startswith(c["fatal_msg"][:30]))
        if hit:
            return hit, "msg"
    if c.get("file") and c.get("func"):
        hit = snap["func"].get("%s:%s" % (c["file"], c["func"]))
        if hit:
            return hit, "func"
    if c.get("file") and c.get("line"):
        hit = snap["line"].get((c["file"], c["line"]))
        if hit:
            return hit, "line"
        for ln, oid in snap["fl"].get(c["file"], ()):
            if abs(ln - c["line"]) <= 12:
                return {oid}, "near"
    return set(), "NEW"


# ---- Phase B: segv site resolution by re-running source.py under gdb ----
# gdb frame:  "#5  0x.. in func (args) at Objects/foo.c:123"  or  "#0 func (..) at ..."
_BT_FRAME = re.compile(
    r'^#\d+\s+(?:0x[0-9a-fA-F]+ in )?(\w+)\b.*?\bat '
    r'((?:Objects|Python|Modules|Include|Parser)/[\w./+-]+):(\d+)')
# fatal/assert/dump plumbing -- skip so the recorded frame is the real crash/assert site
_BT_SKIP = re.compile(r'^(fatal_error(_exit)?|_Py_FatalError\w*|_PyObject_AssertFailed'
                      r'|_Py_NegativeRefcount|_Py_DumpStack|faulthandler\w*'
                      r'|_Py_DumpExtensionModules)$')
_SITE = re.compile(r'^(\w+)@([\w./+-]+):(\d+)$')


def extract_site_from_bt(bt_text):
    """First real CPython frame in a gdb backtrace -> 'func@file:line' (or None)."""
    for line in bt_text.splitlines():
        m = _BT_FRAME.match(line.strip())
        if m and not _BT_SKIP.match(m.group(1)):
            return "%s@%s:%s" % (m.group(1), m.group(2), m.group(3))
    return None


def gdb_crash_site(python_bin, source_path, timeout=120):
    """Re-run source.py under gdb on ``python_bin`` (deterministic on the same binary)
    and return the resolved crash site 'func@file:line', or None if it can't be found."""
    try:
        out = subprocess.run(
            ["gdb", "-q", "-batch", "-ex", "set pagination off",
             "-ex", "set print frame-arguments none", "-ex", "set debuginfod enabled off",
             "-ex", "run", "-ex", "bt 30", "--args", python_bin, "-u", source_path],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"},
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return extract_site_from_bt(out)


def _site_to_classification(site):
    m = _SITE.match(site)
    if not m:
        return None
    return dict(kind="segv", file=m.group(2), func=m.group(1), line=int(m.group(3)),
                assert_expr=None, fatal_msg=None)


class Deduper:
    """Stateful in-loop deduper: feed each crash's stdout, get a (keep, label) decision.

    keep=False is only ever returned for a *confidently-known* bug already at its sample
    cap, and only when ``prune`` is enabled -- new/unresolved/segv crashes are always kept.

    Phase B: when ``resolve_segv`` is set, a segv (or generic-assert fatal) is resolved to
    its real site by re-running ``source_path`` under gdb on ``python_bin`` -- so segvs
    dedupe/label/prune like aborts. ``segv_resolver`` (source_path -> site|None) is
    injectable for testing; it defaults to :func:`gdb_crash_site`.
    """
    def __init__(self, snapshot_path, keep=5, prune=False, python_bin=None,
                 gdb_timeout=120, resolve_segv=False, segv_resolver=None):
        self.snap = load_snapshot_file(snapshot_path)
        self.keep_cap = keep
        self.prune = prune
        self.python_bin = python_bin
        self.gdb_timeout = gdb_timeout
        self.resolve_segv = resolve_segv
        self._resolver = segv_resolver
        self.seen = collections.Counter()   # bug/new-key -> total crashes seen
        self.kept = collections.Counter()   # bug -> directories kept

    def _resolve(self, source_path):
        if self._resolver is not None:
            return self._resolver(source_path)
        if self.python_bin and source_path:
            return gdb_crash_site(self.python_bin, source_path, self.gdb_timeout)
        return None

    def decide(self, stdout_text, source_path=None):
        """Return (keep: bool, label: str) for one crash."""
        c = classify(stdout_text)
        kind = c.get("kind")
        if kind in ("clean", "import"):
            return True, "oom" + (kind or "")
        if kind == "segv":
            site = self._resolve(source_path) if self.resolve_segv else None
            resolved = _site_to_classification(site) if site else None
            if resolved is None:
                self.seen["segv:unresolved"] += 1
                return True, "oomSEGV"       # can't resolve -> always keep
            c = resolved
        ids, how = match(c, self.snap)
        if not ids:
            key = (c.get("assert_expr") and "%s:%s" % (c["file"], c["assert_expr"])) \
                  or (c.get("func") and "%s:%s" % (c["file"], c["func"])) \
                  or c.get("fatal_msg") or "?"
            self.seen["NEW:" + key] += 1
            return True, "oomNEW"            # never prune a candidate-new site
        oid = sorted(ids)[0]
        self.seen[oid] += 1
        if self.prune and self.kept[oid] >= self.keep_cap:
            return False, oid                # known + over cap -> prune duplicate
        self.kept[oid] += 1
        return True, oid

    def report(self):
        lines = ["OOM dedupe summary (seen / kept):"]
        for key, n in self.seen.most_common():
            lines.append("  %-22s seen=%-5d kept=%d" % (key, n, self.kept.get(key, n)))
        return "\n".join(lines)
