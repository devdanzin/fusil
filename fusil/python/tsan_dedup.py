"""In-loop dedupe for the --tsan (ThreadSanitizer) data-race fuzzer.

Pure-Python and free of any runtime (python-ptrace) dependency, so it unit-tests in
isolation -- the TSan analogue of ``oom_dedup.py``. It parses a ThreadSanitizer
``data race`` report out of a crashing session's captured stdout, reduces it to a stable
**race signature** (the unordered pair of the two racing access sites), and decides whether
that race is already known so the fuzzer can prune duplicates in-loop and self-label each
crash dir.

Signature: TSan prints two racing-access stanzas ("Write of size N at 0x.. by thread T1:" /
"Previous read of size N at 0x.. by thread T4:"), each with a symbolized C stack. For each we
take the *top real site* -- the innermost frame whose source path is in CPython
(Objects/Python/Modules/Include/Parser/Programs) and whose function is not generic call/eval
plumbing (the same over-broad dispatch frames oom_dedup skips). The signature is the two sites
as ``file:func`` sorted into an unordered pair, so ``(A,B)`` and ``(B,A)`` -- i.e. the same
race regardless of which thread won the scheduling race -- dedupe together. Line numbers drift
across builds, so the signature is function-level; the exact lines are kept for the report.

The catalog snapshot (``known_races.tsv``, produced by the sibling cpython-tsan-findings
catalog) maps each known signature to a race id. Matching is exact on the signature.

``parse_report`` optionally takes ``source_roots`` (Slice D): a list of ``--tsan-source-root``
directories. A frame that is NOT CPython source but whose file lives under one of those roots is
normalised to its path relative to the root (``/build/cereggii/src/atomic_dict.c`` ->
``src/atomic_dict.c``), so an out-of-tree extension's own races get a specific, dedupable
signature instead of falling into ``noparse``. CPython frames are always matched first, so the
default (no roots) is byte-for-byte identical to the CPython-only behaviour. This signature
format is a **cross-repo contract** -- the sibling catalog's ``scripts/ingest.py`` imports this
module by path, so a change here must keep every existing CPython signature unchanged (see the
re-ingest guardrail in the Slice D notes).
"""

import collections
import os
import re

# ---- report parsing ----
WARNING = re.compile(r"WARNING: ThreadSanitizer: data race")
# A non-race TSan report: SEGV / heap-use-after-free / lock-order-inversion / deadlock. These
# carry ONE crash stack (not two access stanzas). `SEGV on unknown address 0xADDR (pc 0xPC ...)`
# often can't be unwound (TSan prints "nested bug ... aborting" with no frames), so the fault
# address + pc is the only stable signal; use the symbolized crash site when frames ARE present.
SEGV = re.compile(
    r"ThreadSanitizer:\s*(SEGV|heap-use-after-free|lock-order-inversion|deadlock)"
    r"(?:.*?\baddress 0x0*([0-9a-fA-F]+))?(?:.*?\bpc 0x0*([0-9a-fA-F]+))?"
)
# An access stanza header: "[Previous ][Atomic ](Write|Read) of size N at 0xADDR by thread T#:".
# TSan capitalises the FIRST access ("Write"/"Read"/"Atomic write") but lowercases the second
# ("Previous write"/"Previous read"/"Previous atomic write"), so match either case -- including
# the `atomic` qualifier, which is lowercased on the second access too. Missing "Previous atomic
# write" silently dropped the 2nd stanza, and the len(stanzas)<2 fallback below then duplicated
# the 1st -- fabricating a symmetric "A | A" signature for exactly the non-atomic-reader-vs-
# atomic-writer races this catalog is mostly made of (18% of fleet-03's race dirs). The
# thread-CREATION stanzas ("Thread T1 '...' created by ...") do NOT match, so only the two racing
# data accesses feed the signature.
ACCESS = re.compile(
    r"^\s*(?:Previous\s+)?(?:[Aa]tomic\s+)?(?:[Ww]rite|[Rr]ead) of size \d+ at 0x[0-9a-fA-F]+ by "
)
# A symbolized TSan frame: "#N func /abs/.../<CPythonDir>/file.c:line:col (module+0xoff) ...".
# func or the location may be "<null>" (interceptors / non-CPython .so frames); those simply
# don't yield a CPython source and are skipped by the source match below.
FRAME = re.compile(r"^\s*#\d+\s+(\S+)\s+(.+?)\s+\(")
# The CPython-source-relative part of a frame location (handles the build dir's leading `./`).
CPY_SRC = re.compile(
    r"(?:^|/)((?:Objects|Python|Modules|Include|Parser|Programs)/[\w./+-]+\.(?:c|h)):(\d+)"
)
# Slice D: with `--tsan-source-root` roots, a frame whose source file is NOT in CPython but lives
# under one of those roots is normalised to its path RELATIVE to the root (e.g. root
# `/build/cereggii` + `/build/cereggii/src/atomic_dict.c:12` -> `src/atomic_dict.c`), so an
# extension `.so`'s own races get a specific, dedupable signature instead of dropping to
# `noparse`. Default (no roots) leaves CPython-only behaviour byte-for-byte unchanged -- CPython
# is always matched FIRST, so roots only ever rescue a frame CPY_SRC didn't already claim.
_EXT_SRC = re.compile(r"([\w./+-]+\.(?:c|h|cc|cpp|cxx|hpp|hh|pyx|pxd|pxi)):(\d+)")


def _relative_to_root(path, root):
    """``path`` normalised relative to ``root`` (a --tsan-source-root dir), or None if not under
    it. Matches either an absolute-path prefix or the root's basename as a ``/name/`` anchor (the
    build-time source path baked into the `.so` can differ from the local root path)."""
    root = root.rstrip("/")
    if not root:
        return None
    if path == root:
        return os.path.basename(path)
    if path.startswith(root + "/"):
        return path[len(root) + 1 :]
    anchor = "/" + os.path.basename(root) + "/"
    idx = path.find(anchor)
    if idx != -1:
        return path[idx + len(anchor) :]
    return None


def _ext_frame_site(func, location, source_roots):
    """(relpath, func, line) if this frame's source file is under a source root, else None."""
    m = _EXT_SRC.search(location)
    if not m:
        return None
    path, line = m.group(1), int(m.group(2))
    for root in source_roots:
        rel = _relative_to_root(path, root)
        if rel is not None:
            return (rel, func, line)
    return None


# Generic call/vectorcall/eval dispatch + interpreter-startup frames: always on the stack, never
# the racing DATA site, so skip them to reach the real racing function (mirrors
# oom_dedup._FH_SKIP). If a stanza has ONLY these, we fall back to the innermost CPython frame so
# a signature is still produced.
PLUMBING_SKIP = frozenset(
    {
        "_PyObject_MakeTpCall",
        "_PyObject_VectorcallTstate",
        "_PyObject_VectorcallPrepend",
        "_PyVectorcall_Call",
        "_PyObject_Call",
        "PyObject_Call",
        "PyObject_Vectorcall",
        "PyObject_VectorcallMethod",
        "_PyEval_EvalFrameDefault",
        "_PyEval_EvalFrame",
        "_PyEval_Vector",
        "_PyEval_Frame",
        "_PyFunction_Vectorcall",
        "method_vectorcall",
        "method_vectorcall_FASTCALL_KEYWORDS",
        "cfunction_call",
        "cfunction_vectorcall_FASTCALL",
        "context_run",
        "PyEval_EvalCode",
        "run_eval_code_obj",
        "run_mod",
        "pymain_run_command",
        "pymain_run_python",
        "pymain_main",
        "Py_RunMain",
        "Py_BytesMain",
        "main",
    }
)
# The *StackRef* vectorcall-steal helpers are dispatch too (an object's stolen stackref lands
# here); skip by pattern.
_STACKREF = re.compile(r"\w*StackRef\w*|_PyRun_\w*")

# Thread/frame scaffolding: a race whose BOTH access sites are Python's own thread-lifecycle
# machinery (the harness spinning workers up/down) is framework noise, not a target finding.
# Labeled tsanFRAME (kept, but out of the tsanNEW bucket).
#
# Match the FUNCTION, not just the file. `Modules/_threadmodule.c` also holds the PUBLIC _thread
# API -- RLock/lock methods such as `rlock_repr` (= RLock.__repr__, a tp_repr slot) -- and a race
# between those is a genuine finding. The old file-level `_threadmodule.c` match labeled every
# such race as framework noise, silently burying the real RLock repr race (cf. TSAN-0028 /
# cpython#153292). `thread_pthread.h` is pure platform bootstrap (no public API), so a file-level
# match is still correct there.
FRAMEWORK_FILES = re.compile(r"thread_pthread\.h$")
# Thread-lifecycle entry points in _threadmodule.c: the create/run/bootstrap path the harness
# exercises, never a target's own data.
FRAMEWORK_FUNCS = frozenset(
    {
        "thread_run",
        "do_start_new_thread",
        "do_start_joinable_thread",
        "ThreadHandle_start",
        "thread_PyThread_start_joinable_thread",
        "PyThread_start_joinable_thread",
        "pythread_wrapper",
    }
)


def _is_framework(site):
    """True if this (file, func, line) site is harness thread-lifecycle scaffolding."""
    return bool(FRAMEWORK_FILES.search(site[0])) or site[1] in FRAMEWORK_FUNCS


def _frame_site(func, location, source_roots=None):
    """Return (file, func, line) if this frame resolves to a source site we key on, else None.

    A CPython source frame is matched first (unchanged). With ``source_roots`` (Slice D), a
    non-CPython frame whose file is under one of those roots is normalised relative to it; without
    roots the behaviour is exactly the old CPython-only match."""
    if func == "<null>":
        return None
    m = CPY_SRC.search(location)
    if m:
        return (m.group(1), func, int(m.group(2)))
    if source_roots:
        return _ext_frame_site(func, location, source_roots)
    return None


def _is_plumbing(func):
    return func in PLUMBING_SKIP or bool(_STACKREF.fullmatch(func))


def _top_site(frames, source_roots=None):
    """Given a stanza's frames (innermost first) as (func, location), return the top real
    racing site (file, func, line): the innermost resolved frame whose func isn't plumbing.
    Falls back to the innermost resolved frame if all are plumbing; None if none resolve.
    ``source_roots`` (Slice D) additionally resolves extension frames under those roots."""
    real = []
    for func, location in frames:
        site = _frame_site(func, location, source_roots)
        if site is not None:
            real.append(site)
    if not real:
        return None
    for site in real:
        if not _is_plumbing(site[1]):
            return site
    return real[0]  # all plumbing -> innermost resolved frame anyway


def parse_report(text, source_roots=None):
    """Parse the first ThreadSanitizer report in ``text``.

    Returns a dict {signature, sites, framework, kind} where kind is "race" (a data race, two
    access sites) or "segv" (a SEGV/UAF/deadlock, one crash site), or None if there is no TSan
    report (or it can't be reduced to any signature).

    ``source_roots`` (Slice D, default None) is an optional list of ``--tsan-source-root`` dirs
    that lets non-CPython (extension) frames under those roots contribute a signature instead of
    dropping out. With the default (None) the result is byte-for-byte the CPython-only behaviour.
    """
    if WARNING.search(text):
        return _parse_race(text, source_roots)
    m = SEGV.search(text)
    if m:
        return _parse_segv(text, m, source_roots)
    return None


# The start of one TSan report: `WARNING: ThreadSanitizer: ...` or `==PID==ERROR: ThreadSanitizer:
# ...` at line start. Deliberately NOT `SUMMARY: ThreadSanitizer:` (that ends a report). Used to
# split a report-and-continue (halt_on_error=0) stdout into per-report chunks for parse_all_reports.
_REPORT_START = re.compile(r"^(?:={2,}\d+={2,})?\s*(?:WARNING|ERROR): ThreadSanitizer: ", re.M)


def parse_all_reports(text, source_roots=None):
    """Parse EVERY ThreadSanitizer report in ``text`` (halt_on_error=0 emits many), in order,
    de-duplicated by signature. Returns a list of report dicts of the same shape as
    ``parse_report`` (each carrying an extra ``order`` index = its position in the stream, so a
    caller can flag reports that FOLLOW a UAF/SEGV as possible corruption artifacts).

    ``parse_report`` stays first-report-only -- this is purely additive, so the sibling catalog's
    signature contract (which uses ``parse_report``) is unchanged.
    """
    starts = [m.start() for m in _REPORT_START.finditer(text)]
    if not starts:
        return []
    out = []
    seen = set()
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        rep = parse_report(text[start:end], source_roots)  # each chunk holds exactly one report
        if not rep or not rep.get("signature") or rep["signature"] in seen:
            continue
        seen.add(rep["signature"])
        rep = dict(rep, order=len(out))
        out.append(rep)
    return out


def _parse_segv(text, m, source_roots=None):
    """Parse a non-race TSan report (SEGV/UAF/deadlock): one crash stack. Signature is the top
    real crash site if TSan symbolized it, else the fault address + pc (deterministic under the
    fixed load address `setarch -R` gives; build-specific -- regenerate the catalog per build)."""
    kind_word, addr, pc = m.group(1), m.group(2), m.group(3)
    frames = []
    started = False
    for line in text.splitlines():
        if not started:
            if SEGV.search(line):
                started = True
            continue
        fm = FRAME.match(line)
        if fm:
            frames.append((fm.group(1), fm.group(2)))
        elif frames:
            break  # crash stack ended
    site = _top_site(frames, source_roots)
    if site:
        signature = "%s %s:%s" % (kind_word, site[0], site[1])
        sites = [site]
    else:
        signature = "%s addr=0x%s pc=0x%s" % (kind_word, addr or "?", pc or "?")
        sites = []
    return dict(signature=signature, sites=sites, framework=False, kind="segv")


def _parse_race(text, source_roots=None):
    lines = text.splitlines()
    stanzas = []  # list of frame-lists, one per access stanza (in order)
    i = 0
    n = len(lines)
    while i < n and len(stanzas) < 2:
        if ACCESS.search(lines[i]):
            frames = []
            i += 1
            while i < n:
                fm = FRAME.match(lines[i])
                if fm:
                    frames.append((fm.group(1), fm.group(2)))
                    i += 1
                    continue
                # stanza ends at the first non-frame line (blank / next header)
                if (
                    lines[i].strip() == ""
                    or ACCESS.search(lines[i])
                    or lines[i].lstrip().startswith("Thread T")
                ):
                    break
                i += 1
            stanzas.append(frames)
        else:
            i += 1
    if len(stanzas) < 2:
        # A malformed / single-stanza report: still try to key on whatever we have.
        if not stanzas:
            return None
        stanzas.append(stanzas[0])
    sites = [_top_site(fr, source_roots) for fr in stanzas[:2]]
    if all(s is None for s in sites):
        return None
    # Framework noise: every resolved site is thread/frame scaffolding.
    framework = all(s is not None and _is_framework(s) for s in sites if s)
    keys = sorted("%s:%s" % (s[0], s[1]) if s else "?" for s in sites)
    signature = " | ".join(keys)
    return dict(signature=signature, sites=sites, framework=framework, kind="race")


# ---- catalog snapshot ----
def load_catalog(lines):
    """Load ``known_races.tsv`` rows (iterable of lines) -> {signature: race_id}.

    Row format (tab-separated):  <race_id>\t<signature>   (lines starting with # are comments).
    """
    by_sig = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        rid, sig = parts
        by_sig[sig.strip()] = rid.strip()
    return by_sig


def load_catalog_file(path):
    with open(path) as fh:
        return load_catalog(fh)


# ---- suppressions ----
# A TSan suppressions file (CPython's Tools/tsan/suppressions_free_threading.txt, currently
# empty, or a per-target one) uses lines like `race:func_or_file` / `race_top:func`. We honour
# them post-hoc too (a suppressed race must never score, even if TSan happened to report it):
# the pattern is matched against each racing site's func and file. Plain (non-`kind:`) lines are
# treated as a regex over the whole signature. `#` comments and blanks are ignored.
_SUPP_LINE = re.compile(r"^(?:(race|race_top|thread|mutex|deadlock|called_from_lib)\s*:\s*)?(.*)$")


class Suppressor:
    def __init__(self, patterns):
        # patterns: list of (kind|None, compiled_regex)
        self._pats = patterns

    @classmethod
    def from_lines(cls, lines):
        pats = []
        for raw in lines:
            s = raw.split("#", 1)[0].strip()
            if not s:
                continue
            m = _SUPP_LINE.match(s)
            kind, pat = m.group(1), m.group(2).strip()
            if not pat:
                continue
            try:
                pats.append((kind, re.compile(pat)))
            except re.error:
                pats.append((kind, re.compile(re.escape(pat))))
        return cls(pats)

    @classmethod
    def from_file(cls, path):
        if not path or not os.path.exists(path):
            return cls([])
        with open(path) as fh:
            return cls.from_lines(fh)

    def suppresses(self, report):
        """True if any suppression matches this race (by site func/file, or signature regex)."""
        if not self._pats:
            return False
        site_strs = []
        for s in report["sites"]:
            if s:
                site_strs.extend([s[1], s[0]])  # func, file
        for kind, rx in self._pats:
            if kind in ("race", "race_top", None):
                if any(rx.search(x) for x in site_strs) or rx.search(report["signature"]):
                    return True
        return False


# ---- bounded stdout reader (shared contract with oom_dedup) ----
_STDOUT_HEAD = int(os.environ.get("TSAN_STDOUT_HEAD", 256 * 1024))
_STDOUT_TAIL = int(os.environ.get("TSAN_STDOUT_TAIL", 1024 * 1024))


def read_crash_stdout(path):
    """Read a crash's captured stdout, bounding huge files to head+tail (a TSan report is short
    and lives at the tail). Decoded, errors-replaced. Mirrors oom_dedup.read_crash_stdout."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size <= _STDOUT_HEAD + _STDOUT_TAIL:
            fh.seek(0)
            return fh.read().decode("utf-8", "replace")
        fh.seek(0)
        head = fh.read(_STDOUT_HEAD)
        fh.seek(size - _STDOUT_TAIL)
        tail = fh.read(_STDOUT_TAIL)
    return head.decode("utf-8", "replace") + "\n...[elided]...\n" + tail.decode("utf-8", "replace")


# ---- the deduper ----
class TSanDeduper:
    """Stateful in-loop deduper: feed each crash's stdout, get (keep, label).

    keep=False is only returned for a confidently-known race already at its sample cap (and only
    when ``prune`` is on), or for a suppressed race. New / framework / unparseable races are
    always kept.
    """

    def __init__(
        self,
        catalog_path=None,
        keep=5,
        prune=False,
        suppressions_path=None,
        source_roots=None,
    ):
        self.snap = load_catalog_file(catalog_path) if catalog_path else {}
        self.keep_cap = keep
        self.prune = prune
        self.suppressor = Suppressor.from_file(suppressions_path)
        # Slice D: optional --tsan-source-root dirs so extension-`.so` frames get a signature
        # instead of dropping to noparse. None (the default) -> CPython-only, unchanged.
        self.source_roots = list(source_roots) if source_roots else None
        self.seen = collections.Counter()
        self.kept = collections.Counter()

    def decide(self, stdout_text):
        """Return (keep: bool, label: str) for one crashing session."""
        report = parse_report(stdout_text, source_roots=self.source_roots)
        if report is None:
            # A kept --tsan session with no parseable race: keep it, unlabelled-ish, for a look.
            self.seen["noparse"] += 1
            return True, "tsanNOPARSE"
        if self.suppressor.suppresses(report):
            self.seen["suppressed"] += 1
            return False, None
        if report.get("framework"):
            self.seen["framework"] += 1
            return True, "tsanFRAME"  # kept, but out of the tsanNEW bucket
        rid = self.snap.get(report["signature"])
        if rid:
            self.seen[rid] += 1
            if self.prune and self.kept[rid] >= self.keep_cap:
                return False, rid  # known + over cap -> prune duplicate
            self.kept[rid] += 1
            return True, rid
        # A new (uncatalogued) finding -- label a SEGV/UAF distinctly from a data race.
        is_segv = report.get("kind") == "segv"
        self.seen[("NEW-SEGV:" if is_segv else "NEW:") + report["signature"]] += 1
        return True, "tsanSEGV" if is_segv else "tsanNEW"

    def report(self):
        lines = ["TSan dedupe summary (seen / kept):"]
        for key, n in self.seen.most_common():
            lines.append("  %-40s seen=%-5d kept=%d" % (key, n, self.kept.get(key, n)))
        return "\n".join(lines)
