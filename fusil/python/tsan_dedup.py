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
"""

import collections
import os
import re

# ---- report parsing ----
WARNING = re.compile(r"WARNING: ThreadSanitizer: data race")
# An access stanza header: "[Previous ][Atomic ](Write|Read) of size N at 0xADDR by thread T#:".
# TSan capitalises the FIRST access ("Write"/"Read") but lowercases the second ("Previous
# write"/"Previous read"), so match either case. The thread-CREATION stanzas ("Thread T1 '...'
# created by ...") do NOT match, so only the two racing data accesses feed the signature.
ACCESS = re.compile(
    r"^\s*(?:Previous\s+)?(?:Atomic\s+)?(?:[Ww]rite|[Rr]ead) of size \d+ at 0x[0-9a-fA-F]+ by "
)
# A symbolized TSan frame: "#N func /abs/.../<CPythonDir>/file.c:line:col (module+0xoff) ...".
# func or the location may be "<null>" (interceptors / non-CPython .so frames); those simply
# don't yield a CPython source and are skipped by the source match below.
FRAME = re.compile(r"^\s*#\d+\s+(\S+)\s+(.+?)\s+\(")
# The CPython-source-relative part of a frame location (handles the build dir's leading `./`).
CPY_SRC = re.compile(
    r"(?:^|/)((?:Objects|Python|Modules|Include|Parser|Programs)/[\w./+-]+\.(?:c|h)):(\d+)"
)

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

# Thread/frame scaffolding: a race whose BOTH access sites live only here is Python's own
# thread machinery racing under the harness spinning 8 threads up/down -- framework noise, not
# a target finding. Labeled tsanFRAME (kept, but out of the tsanNEW bucket).
FRAMEWORK_FILES = re.compile(r"(?:_threadmodule\.c|thread_pthread\.h)$")


def _frame_site(func, location):
    """Return (file, func, line) if this frame is a CPython source frame, else None."""
    if func == "<null>":
        return None
    m = CPY_SRC.search(location)
    if not m:
        return None
    return (m.group(1), func, int(m.group(2)))


def _is_plumbing(func):
    return func in PLUMBING_SKIP or bool(_STACKREF.fullmatch(func))


def _top_site(frames):
    """Given a stanza's frames (innermost first) as (func, location), return the top real
    racing site (file, func, line): the innermost CPython frame whose func isn't plumbing.
    Falls back to the innermost CPython frame if all are plumbing; None if no CPython frame."""
    cpython = []
    for func, location in frames:
        site = _frame_site(func, location)
        if site is not None:
            cpython.append(site)
    if not cpython:
        return None
    for site in cpython:
        if not _is_plumbing(site[1]):
            return site
    return cpython[0]  # all plumbing -> innermost CPython frame anyway


def parse_report(text):
    """Parse the first ThreadSanitizer data-race report in ``text``.

    Returns a dict {signature, sites:[(file,func,line)|None, ...], framework:bool} or None if
    there is no data-race report (or it can't be reduced to any site).
    """
    if not WARNING.search(text):
        return None
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
    sites = [_top_site(fr) for fr in stanzas[:2]]
    if all(s is None for s in sites):
        return None
    # Framework noise: every resolved site is thread/frame scaffolding.
    framework = all(s is not None and FRAMEWORK_FILES.search(s[0]) for s in sites if s)
    keys = sorted("%s:%s" % (s[0], s[1]) if s else "?" for s in sites)
    signature = " | ".join(keys)
    return dict(signature=signature, sites=sites, framework=framework)


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

    def __init__(self, catalog_path=None, keep=5, prune=False, suppressions_path=None):
        self.snap = load_catalog_file(catalog_path) if catalog_path else {}
        self.keep_cap = keep
        self.prune = prune
        self.suppressor = Suppressor.from_file(suppressions_path)
        self.seen = collections.Counter()
        self.kept = collections.Counter()

    def decide(self, stdout_text):
        """Return (keep: bool, label: str) for one crashing session."""
        report = parse_report(stdout_text)
        if report is None:
            # A kept --tsan session with no parseable race: keep it, unlabelled-ish, for a look.
            self.seen["noparse"] += 1
            return True, "tsanNOPARSE"
        if self.suppressor.suppresses(report):
            self.seen["suppressed"] += 1
            return False, None
        if report["framework"]:
            self.seen["framework"] += 1
            return True, "tsanFRAME"  # kept, but out of the tsanNEW bucket
        rid = self.snap.get(report["signature"])
        if rid:
            self.seen[rid] += 1
            if self.prune and self.kept[rid] >= self.keep_cap:
                return False, rid  # known + over cap -> prune duplicate
            self.kept[rid] += 1
            return True, rid
        self.seen["NEW:" + report["signature"]] += 1
        return True, "tsanNEW"

    def report(self):
        lines = ["TSan dedupe summary (seen / kept):"]
        for key, n in self.seen.most_common():
            lines.append("  %-40s seen=%-5d kept=%d" % (key, n, self.kept.get(key, n)))
        return "\n".join(lines)
