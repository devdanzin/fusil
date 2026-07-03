"""In-loop crash dedupe for the OOM Python fuzzer.

Pure-Python and free of any runtime (python-ptrace) dependency, so it unit-tests in
isolation. It loads the known-sites snapshot produced by the cpython-oom-findings
catalog (``gen_known_sites.py`` -> ``known_sites.tsv``) and, given a crash's captured
stdout (and optionally its source.py for gdb resolution), decides whether the crash is a
*known* bug so the fuzzer can prune duplicates in-loop and self-label each crash dir.

Matching considers EVERY signal a crash offers and calls it known if ANY matches the
catalog: all assertions in stdout (glibc ``Assertion `expr'`` and CPython
``Assertion "expr"`` forms), a specific ``Fatal Python error: <msg>``, and -- for segvs
or generic-assert fatals, when ``resolve_segv`` is set -- every real CPython frame in the
gdb backtrace (re-running source.py on the same binary). Checking all signals avoids
false ``oomNEW`` labels when the gdb-caught frame is a secondary/cascade site but an
earlier assertion or a deeper frame is a known bug. The snapshot file format is the
contract shared with the catalog's ``ingest.py``.
"""

import collections
import os
import re
import subprocess

# ---- stdout classification ----
# An assertion line: "<file>:<line>: [ret] <func>[(args)]: Assertion <q>expr<q> failed[: msg]".
# Handles both glibc (`expr') and CPython ("expr") quoting, and an optional (args) list.
ASSERT = re.compile(
    r"([\w./+-]+\.(?:c|h)):(\d+):.*?\b(\w+)\s*(?:\([^)]*\))?\s*:\s*Assertion[ `\"]+([^`'\"]*)"
)
ASSERT2 = re.compile(
    r"([\w./+-]+\.(?:c|h)):(\d+):.*?Assertion[ `\"]+([^`'\"]*)"
)  # func-less fallback
FATAL = re.compile(r"Fatal Python error:\s*([^\n]+)")
SEGV = re.compile(
    r"AddressSanitizer: SEGV|Fatal Python error: Segmentation fault|Segmentation fault"
)
IMPORTERR = re.compile(r"(ModuleNotFoundError|ImportError):")
# Generic fatal wrappers that carry no usable site in stdout -> resolve via gdb instead.
GENERIC_FATAL = ("_PyObject_AssertFailed", "_Py_NegativeRefcount")

# Generic assert DETECTORS -- the assert() analog of GENERIC_FATAL. `Py_DECREF_MORTAL`'s
# `!_Py_IsStaticImmortal(op)` fires when a mortal decref hits an object whose refcount word has
# been corrupted to read back as static-immortal -- i.e. an over-decref / use-after-free where
# the freed block's 0xDD PYMEM_DEADBYTE fill happens to set the static-immortal flag bits. It
# CATCHES the corruption exactly like `_Py_NegativeRefcount` catches the negative-refcount face
# of the SAME family (frame-teardown / eval-loop over-decref); the assert site (pycore_object.h
# Py_DECREF_MORTAL) is never the defect. So carry NO site from it: drop it as a candidate and
# resolve PAST it to the real caller (producer), just like a generic fatal. Matched by the
# asserting FUNC or the expr (either alone is enough -- func parsing can vary by build). Kept in
# lockstep with the catalog's gen_known_sites.GENERIC_DETECTOR_FUNCS / GENERIC_ASSERTS.
GENERIC_ASSERT_FUNCS = ("Py_DECREF_MORTAL",)
GENERIC_ASSERT_EXPRS = ("!_Py_IsStaticImmortal(op)",)


def _is_generic_assert(func, expr):
    """True if an assertion is a generic over-decref/UAF detector (carries no real site)."""
    return func in GENERIC_ASSERT_FUNCS or expr in GENERIC_ASSERT_EXPRS


def _nf(f):
    return f.lstrip("./")


# ---- bounded stdout reader ----
# A crashing session's stdout can be huge: OOM-verbose `start=N` spew, or a runaway /
# binary-emitting vehicle (tens of MB). Feeding the whole thing to the classification
# regexes above makes the ``.*?`` patterns backtrack catastrophically (a multi-MB
# no-newline binary blob is one giant "line"), which would stall the in-loop keep-policy
# that runs synchronously in the session's deinit. The crash signature always lives at the
# HEAD (early asserts / import errors) or the TAIL (the Fatal/ASan backtrace that ends the
# process), never the middle, so read a bounded head+tail and cap each line -- lossless for
# every signal decide() uses. Mirrors the catalog's ingest.read_stdout. Env-overridable.
_STDOUT_HEAD = int(os.environ.get("OOM_STDOUT_HEAD", 256 * 1024))
_STDOUT_TAIL = int(os.environ.get("OOM_STDOUT_TAIL", 1024 * 1024))
_STDOUT_LINE_CAP = int(os.environ.get("OOM_STDOUT_LINE_CAP", 4096))


def _cap_lines(text):
    """Truncate over-long lines so a binary blob can't make the regexes backtrack."""
    if _STDOUT_LINE_CAP <= 0:
        return text
    return "\n".join(
        ln if len(ln) <= _STDOUT_LINE_CAP else ln[:_STDOUT_LINE_CAP] for ln in text.split("\n")
    )


def read_crash_stdout(path):
    """Read a crash's captured stdout, bounding huge files to head+tail and capping line
    length (decoded, errors-replaced) so decide()'s regexes can't catastrophically
    backtrack on OOM-verbose spew or embedded binary."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size <= _STDOUT_HEAD + _STDOUT_TAIL:
            fh.seek(0)
            return _cap_lines(fh.read().decode("utf-8", "replace"))
        fh.seek(0)
        head = fh.read(_STDOUT_HEAD)
        fh.seek(size - _STDOUT_TAIL)
        tail = fh.read(_STDOUT_TAIL)
    elided = size - _STDOUT_HEAD - _STDOUT_TAIL
    return _cap_lines(
        head.decode("utf-8", "replace")
        + f"\n...[{elided} bytes elided by read_crash_stdout]...\n"
        + tail.decode("utf-8", "replace")
    )


def all_asserts(text):
    """Every assertion in stdout as a list of (file, line, func|None, expr)."""
    out, seen = [], set()
    for m in ASSERT.finditer(text):
        key = (_nf(m.group(1)), int(m.group(2)))
        out.append((key[0], key[1], m.group(3), m.group(4).strip()))
        seen.add(key)
    for m in ASSERT2.finditer(text):  # catch lines without a parseable func
        key = (_nf(m.group(1)), int(m.group(2)))
        if key not in seen:
            out.append((key[0], key[1], None, m.group(3).strip()))
            seen.add(key)
    return out


def classify(text):
    """Coarse kind of a crash from its stdout (back-compat helper). Returns a dict with
    ``kind`` in {abort, fatal, segv, import, clean} plus the *first* resolved signal."""
    a = all_asserts(text)
    if a:
        # Drop generic-detector asserts (Py_DECREF_MORTAL/!_Py_IsStaticImmortal): like a generic
        # fatal they carry no real site -> treat as segv so callers resolve past them.
        real = [t for t in a if not _is_generic_assert(t[2], t[3])]
        if not real:
            return dict(
                kind="segv", file=None, line=None, func=None, assert_expr=None, fatal_msg=None
            )
        f, ln, func, expr = real[0]
        return dict(kind="abort", file=f, line=ln, func=func, assert_expr=expr, fatal_msg=None)
    fa = FATAL.search(text)
    if fa and not SEGV.search(text):
        msg = fa.group(1).strip()
        if msg.startswith(GENERIC_FATAL):  # carries no site -> treat like segv
            return dict(
                kind="segv", file=None, line=None, func=None, assert_expr=None, fatal_msg=None
            )
        return dict(kind="fatal", file=None, line=None, func=None, assert_expr=None, fatal_msg=msg)
    if SEGV.search(text):
        return dict(kind="segv", file=None, line=None, func=None, assert_expr=None, fatal_msg=None)
    if IMPORTERR.search(text):
        return dict(kind="import")
    return dict(kind="clean")


# ---- snapshot loading + matching ----
def load_snapshot(lines):
    """Load ``known_sites.tsv`` rows (an iterable of lines) into matcher tables."""
    by_func, by_assert, by_line = {}, {}, {}
    per_file_lines = collections.defaultdict(list)
    by_funcname = {}  # bare func name -> oids (faulthandler-only stacks; see fh_match)
    by_msg, by_msgfam, kind_of = [], [], {}
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
            fn = key.rsplit(":", 1)[-1]  # "file:func" -> "func"
            if re.fullmatch(r"\w+", fn):  # clean ident only (skip combined "a/b/c(...)" keys)
                by_funcname.setdefault(fn, set()).add(oid)
        elif kt == "assert":
            by_assert.setdefault(key, set()).add(oid)
        elif kt == "msg":
            by_msg.append((key, oid))
        elif kt == "msgfam":
            by_msgfam.append((key, oid))
        elif kt == "line":
            f, ln = key.rsplit(":", 1)
            by_line.setdefault((f, int(ln)), set()).add(oid)
            per_file_lines[f].append((int(ln), oid))
    return dict(
        func=by_func,
        assert_=by_assert,
        line=by_line,
        fl=per_file_lines,
        msg=by_msg,
        msgfam=by_msgfam,
        kind=kind_of,
        funcname=by_funcname,
    )


def load_snapshot_file(path):
    with open(path) as fh:
        return load_snapshot(fh)


def match(c, snap):
    """Match ONE candidate (file/line/func/assert_expr/fatal_msg) -> (oom_ids:set, how)."""
    if c.get("assert_expr") and c.get("file"):
        hit = snap["assert_"].get("%s:%s" % (c["file"], c["assert_expr"]))
        if hit:
            return hit, "assert"
    if c.get("fatal_msg"):
        cm = c["fatal_msg"]
        # Match when the cataloged key is a prefix of the crash message (a key may be a short
        # signature, e.g. "_Py_CheckFunctionResult:") OR the (truncation-shortened) crash
        # message is a prefix of the key. Use the FULL crash message, not a fixed [:30] slice --
        # a short slice stops before the discriminating content (e.g. "_Py_Dealloc: Deallocator
        # of type '<TYPE>'") and conflates type-specific keys (OOM-0007 'Context' vs OOM-0023
        # '_StoreAction'). LONGEST match wins so the most specific type key beats a shorter one.
        exact = [(k, o) for k, o in snap["msg"] if cm.startswith(k) or k.startswith(cm)]
        if exact:
            maxlen = max(len(k) for k, _ in exact)
            return set(o for k, o in exact if len(k) == maxlen), "msg"
        # Family fallback: a substring identifying a whole bug family (e.g. the generic
        # subtype_dealloc 'cleared the current exception'), tried ONLY when no type-specific key
        # matched -> a new/fuzzer type dedups to the family (OOM-0023) instead of oomNEW.
        fam = set(o for sub, o in snap.get("msgfam", ()) if sub in cm)
        if fam:
            return fam, "msgfam"
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


# ---- segv site resolution from the crash's own native backtrace ----
# gdb frame:  "#5  0x.. in func (args) at Objects/foo.c:123"  or  "#0 func (..) at ..."
_BT_FRAME = re.compile(
    r"^#\d+\s+(?:0x[0-9a-fA-F]+ in )?(\w+)\b.*?\bat "
    r"((?:Objects|Python|Modules|Include|Parser)/[\w./+-]+):(\d+)"
)
# ASan/sanitizer frame already printed to stderr at crash time (merged into stdout):
#   "    #5 0x.. in _excinfo_clear_type /abs/path/Python/crossinterp.c:1319:15"
# The CPython source dir is matched anywhere in the absolute path; leading libc/pthread
# frames carry no such path and are skipped, as is fatal/dump plumbing (via _BT_SKIP).
# The source path may be absolute (Clang builds: /home/.../Objects/foo.c:12:3) or relative
# (GCC builds: Objects/foo.c:12, also no column). Make the absolute prefix and the column
# optional so GCC-built crashes are parsed too -- otherwise extract_native_sites finds nothing
# in the ASan trace and the dedup falls back to faulthandler's sparser (GCC-inlined) C-stack,
# mislabelling known bugs as new (e.g. a whole OOM-0004 batch keyed on _Py_MergeZeroLocalRefcount).
_ASAN_FRAME = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\w+)\s+(?:\S*?/)?"
    r"((?:Objects|Python|Modules|Include|Parser)/[\w./+-]+\.(?:c|h)):(\d+)"
)
# fatal/assert/dump plumbing -- skip so a recorded frame is the real crash/assert site.
# The debug allocator's free-time checks (_PyMem_DebugCheckAddress / _PyMem_DebugRawFree /
# _PyMem_DebugFree) are likewise detectors: they catch a bad/double free ("bad ID") but the
# real defect is the CALLER doing the bad free (e.g. free_threadstate), so skip them too -- the
# resolved site becomes that caller, matching the catalog (gen_known_sites GENERIC_DETECTOR_FUNCS).
# tracemalloc's allocator hooks (tracemalloc_alloc/realloc/free, raw_*) are the same kind of
# pass-through layer when tracing is on -- skip them so the site is the real caller (e.g.
# free_list_items = OOM-0004), not the hook. (The by-design "tracemalloc_realloc() failed to
# allocate a trace" fatal is matched by its message, not this frame, so skipping it here is safe.)
_BT_SKIP = re.compile(
    r"^(fatal_error(_exit)?|_Py_FatalError\w*|_PyObject_AssertFailed"
    r"|_Py_NegativeRefcount|_Py_DumpStack|faulthandler\w*"
    r"|_Py_DumpExtensionModules"
    # Eval-loop operand-stack teardown + the generic dealloc dispatch: these frames CATCH
    # an already-corrupted object (over-decref / double-free / UAF) and are never the defect,
    # so resolve PAST them to the real caller (very often _CALL_LIST_APPEND = OOM-0036). Kept
    # in lockstep with the catalog's gen_known_sites.GENERIC_DETECTOR_FUNCS.
    r"|_Py_Dealloc|PyStackRef_XCLOSE|_PyFrame_ClearLocals|_PyFrame_ClearExceptCode"
    r"|clear_thread_frame"
    r"|_PyMem_DebugCheckAddress|_PyMem_DebugRawFree|_PyMem_DebugFree"
    # The _testcapi set_nomemory injection hooks and the PyMem_/PyObject_ free/realloc
    # wrappers are pass-through allocator plumbing: when one is the innermost frame the real
    # defect is the CALLER doing the bad free (e.g. free_list_items = OOM-0004), so skip them
    # too. Without this, a double-free caught in the free hook resolves to hook_ffree/PyMem_Free
    # (not a catalog site) and the crash is mislabelled oomNEW -- notably on GCC builds, whose
    # ASan trace exposes these frames where Clang inlines them away.
    r"|hook_fmalloc|hook_fcalloc|hook_frealloc|hook_ffree"
    r"|PyMem_Free|PyMem_RawFree|PyObject_Free|PyMem_Realloc|PyMem_RawRealloc|PyObject_Realloc"
    r"|tracemalloc_(raw_)?(alloc|calloc|realloc|free))$"
)
# Inlined refcount/atomic helpers live in these headers and show up as the innermost frame
# of a "DECREF a freed object" segv -- skip them so the site is the real .c caller (e.g.
# do_warn / PyContextVar_Set), not the shared Py_DECREF/_Py_atomic_load that masks dozens
# of distinct bugs behind one line.
_BT_SKIP_FILE = re.compile(r"(?:^|/)(?:refcount|pyatomic\w*|object)\.h$")
_SITE = re.compile(r"^(\w+)@([\w./+-]+):(\d+)$")


def _skip_frame(func, filename):
    return bool(_BT_SKIP.match(func) or _BT_SKIP_FILE.search(filename))


def extract_sites_from_bt(bt_text):
    """All real CPython frames in a gdb backtrace, innermost first, as 'func@file:line'
    (fatal/assert/dump plumbing + inlined refcount/atomic header helpers skipped)."""
    out = []
    for line in bt_text.splitlines():
        m = _BT_FRAME.match(line.strip())
        if m and not _skip_frame(m.group(1), m.group(2)):
            out.append("%s@%s:%s" % (m.group(1), m.group(2), m.group(3)))
    return out


def extract_native_sites(text):
    """Real CPython frames from a *live* sanitizer backtrace already present in the crash's
    captured stdout (innermost first), as 'func@file:line'. This is the actual crash -- no
    re-run -- so it is deterministic and immune to the hash-seed/threading nondeterminism
    that can stop a gdb re-run reproducing the same fault. ASan debug builds print this on
    SEGV/abort; plumbing + inlined refcount/atomic header frames are skipped so the site is
    the real .c caller."""
    out = []
    for m in _ASAN_FRAME.finditer(text):
        f = _nf(m.group(2))
        if not _skip_frame(m.group(1), f):
            out.append("%s@%s:%s" % (m.group(1), f, m.group(3)))
    return out


# A faulthandler "Current thread's C stack trace" frame: '... at <func>+0x...'. On a
# free-threaded debug SEGV this is often the ONLY symbol info (no ASan '#N file.c:line'
# frames), so extract_native_sites comes back empty.
_SYM = re.compile(r", at ([A-Za-z_]\w+)\+0x")
# Funcs to skip when matching such a symbol-only stack (innermost first): the asan/dump/eval/
# run plumbing + alloc/free + assert detectors + the dealloc dispatch and refcount macros
# that wrap every dealloc. The first SURVIVING func the catalog keys by name is the site.
_FH_SKIP = re.compile(
    r"^(___?interceptor\w*|__sanitizer\w*|__asan\w*|_Py_Dump\w*|faulthandler\w*"
    r"|_PyEval_EvalFrameDefault|_PyEval_EvalFrame|_PyEval_Vector|PyEval_EvalCode|_PyEval_Frame\w*"
    r"|Py_RunMain|Py_BytesMain|pymain_\w+|_start|__libc_start\w*|run_mod|run_eval_code_obj"
    r"|pyrun_\w*|_PyRun_\w*|clear_thread_frame|clear_gen_frame"
    r"|fatal_error\w*|_Py_FatalError\w*|_PyObject_AssertFailed|_Py_NegativeRefcount"
    r"|_Py_Dealloc|_Py_MergeZeroLocalRefcount|Py_X?DECREF|Py_X?INCREF|_Py_X?DECREF\w*"
    r"|_PyMem_Debug\w*|PyMem_\w*Free|PyObject_\w*Free|PyMem_\w*Realloc|PyObject_\w*Realloc"
    r"|hook_f\w+|tracemalloc_\w+)$"
)


def fh_match(text, snap):
    """Fallback for a SEGV/generic-fatal whose stdout has a faulthandler C stack (func names)
    but NO ASan ``#N ... file.c:line`` frames and no gdb resolution. Match the innermost
    catalog-keyed func BY NAME (e.g. PyList_New -> OOM-0004). Returns (oids, func) or
    (set(), None)."""
    for fn in _SYM.findall(text):  # faulthandler prints most-recent-call first
        if _FH_SKIP.match(fn):
            continue
        hit = snap.get("funcname", {}).get(fn)
        if hit:
            return set(hit), fn
    return set(), None


def extract_site_from_bt(bt_text):
    """First real CPython frame (back-compat)."""
    sites = extract_sites_from_bt(bt_text)
    return sites[0] if sites else None


def gdb_crash_site(python_bin, source_path, timeout=120, drop_uid=None, drop_gid=None):
    """Re-run source.py under gdb on ``python_bin`` (deterministic on the same binary) and
    return the chain of real CPython frames ['func@file:line', ...] (innermost first).

    This re-executes the *fuzzed* source.py, so it must never run it with more privilege
    than the original fuzzing child had. When the caller is root and a drop target is
    configured (``drop_uid``/``drop_gid`` -- the same ``fusil`` user the children drop to),
    gdb and the python it spawns are dropped to that user; a same-uid gdb can still ptrace
    its own child. The replay also runs with ``cwd`` set to the session dir (where source.py
    lives, matching the original child's cwd) rather than the root-owned run dir, so a fuzzed
    ``os.chmod``/``os.makedirs``/... on a relative path can't escalate against the run tree.
    """
    cwd = os.path.dirname(source_path) or None
    # Only drop when we are actually privileged: a non-root caller is already unprivileged
    # (and setgroups() would fail for it), so there is nothing to drop.
    drop = {}
    if os.getuid() == 0 and (drop_uid is not None or drop_gid is not None):
        if drop_gid is not None:
            drop["group"] = drop_gid
            drop["extra_groups"] = [drop_gid]  # drop root's supplementary groups
        if drop_uid is not None:
            drop["user"] = drop_uid
    try:
        out = subprocess.run(
            [
                "gdb",
                "-q",
                "-batch",
                "-ex",
                "set pagination off",
                "-ex",
                "set print frame-arguments none",
                "-ex",
                "set debuginfod enabled off",
                "-ex",
                "run",
                "-ex",
                "bt 30",
                "--args",
                python_bin,
                "-u",
                source_path,
            ],
            capture_output=True,
            text=True,
            # The re-run prints the fuzzed program's own stdout into gdb's captured output,
            # which is frequently binary (e.g. a gzip/zlib vehicle emits 0x1f 0x8b ...). Decode
            # tolerantly so it never raises UnicodeDecodeError -- otherwise the exception would
            # escape decide() and abort the session's keep/rename in deinit.
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"},
            **drop,
        ).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    return extract_sites_from_bt(out)


def _site_to_candidate(site):
    m = _SITE.match(site)
    if not m:
        return None
    return dict(
        file=_nf(m.group(2)),
        func=m.group(1),
        line=int(m.group(3)),
        assert_expr=None,
        fatal_msg=None,
    )


class Deduper:
    """Stateful in-loop deduper: feed each crash's stdout (+ source.py), get (keep, label).

    keep=False is only ever returned for a *confidently-known* bug already at its sample
    cap, and only when ``prune`` is enabled -- new/unresolved/segv crashes are always kept.
    ``segv_resolver`` (source_path -> ['func@file:line', ...] | 'func@file:line' | None) is
    injectable for testing; it defaults to :func:`gdb_crash_site`.
    """

    def __init__(
        self,
        snapshot_path,
        keep=5,
        prune=False,
        python_bin=None,
        gdb_timeout=120,
        resolve_segv=False,
        segv_resolver=None,
        drop_uid=None,
        drop_gid=None,
    ):
        self.snap = load_snapshot_file(snapshot_path)
        self.keep_cap = keep
        self.prune = prune
        self.python_bin = python_bin
        self.gdb_timeout = gdb_timeout
        self.resolve_segv = resolve_segv
        self._resolver = segv_resolver
        # Drop target for the gdb segv re-run, so the fuzzed source.py is never replayed as
        # root. Mirrors config.process_uid/gid (the user the fuzzing children drop to).
        self.drop_uid = drop_uid
        self.drop_gid = drop_gid
        self.seen = collections.Counter()  # bug/new-key -> total crashes seen
        self.kept = collections.Counter()  # bug -> directories kept

    def _resolve(self, source_path):
        """Return a list of 'func@file:line' chain frames (normalising the resolver).

        Any failure in the resolver is swallowed (-> no chain): segv resolution is a
        best-effort enrichment, and decide() must never raise into the caller's keep/rename.
        """
        try:
            r = (
                self._resolver(source_path)
                if self._resolver is not None
                else (
                    gdb_crash_site(
                        self.python_bin,
                        source_path,
                        self.gdb_timeout,
                        drop_uid=self.drop_uid,
                        drop_gid=self.drop_gid,
                    )
                    if (self.python_bin and source_path)
                    else None
                )
            )
        except Exception:
            return []
        if not r:
            return []
        return [r] if isinstance(r, str) else list(r)

    def decide(self, stdout_text, source_path=None):
        """Return (keep: bool, label: str) for one crash, matching ALL of its signals."""
        asserts = all_asserts(stdout_text)
        # Split off generic-detector asserts (Py_DECREF_MORTAL/!_Py_IsStaticImmortal): like a
        # generic fatal they carry no real site, so don't key them -- resolve past them instead.
        # ``generic_assert`` = the crash's ONLY assertion(s) were such detectors.
        real_asserts = [
            (f, ln, fn, expr) for (f, ln, fn, expr) in asserts if not _is_generic_assert(fn, expr)
        ]
        generic_assert = bool(asserts) and not real_asserts
        fa = FATAL.search(stdout_text)
        fmsg = fa.group(1).strip() if fa else None
        has_segv = bool(SEGV.search(stdout_text))
        generic_fatal = bool(fmsg) and fmsg.startswith(GENERIC_FATAL)

        # No crash signal at all -> import / clean (cheap shortcut).
        if not asserts and not has_segv and not fmsg:
            return True, ("oomimport" if IMPORTERR.search(stdout_text) else "oomclean")

        # Build candidate signals from everything the crash offers (generic-detector asserts
        # dropped -- they never key a real site).
        candidates = [
            dict(file=f, line=ln, func=fn, assert_expr=expr, fatal_msg=None)
            for (f, ln, fn, expr) in real_asserts
        ]
        if fmsg and not generic_fatal and not fmsg.lower().startswith(("segmentation", "aborted")):
            candidates.append(
                dict(file=None, line=None, func=None, assert_expr=None, fatal_msg=fmsg)
            )
        # Resolve a crash site when the stdout assertion text is unreliable (pure segv /
        # generic-assert fatal) or there is no assertion at all. PREFER the native backtrace the
        # crash already printed (ASan/debug build, captured in stdout): it is the actual
        # fault, so it is deterministic -- unlike a gdb re-run, which can fail to reproduce
        # under a different hash seed or thread timing and leave the crash mislabelled
        # oomSEGV. Fall back to a gdb re-run of source.py only when stdout has no parseable
        # native frames and --oom-dedup-resolve-segv is set.
        #
        # Guard on ``not asserts`` (NOT ``not real_asserts``): a pure generic-detector assert
        # (Py_DECREF_MORTAL/!_Py_IsStaticImmortal) must NOT trigger resolution. Its producer
        # already returned, so every backtrace method (native/gdb/faulthandler) yields only frame
        # teardown + bystander frames -- a gdb re-run would be slow AND resolve to a bystander
        # (Py_DECREF_MORTAL itself, or the eval frame -> spurious oomNEW / mis-fold). Leave it to
        # the needs-resolution branch below; the real producer is pinned offline via rr.
        chain = []
        if has_segv or generic_fatal or not asserts:
            chain = extract_native_sites(stdout_text)
            if not chain and self.resolve_segv:
                chain = self._resolve(source_path)
            # Match only the resolved SITE (chain[0], the innermost real frame after the
            # plumbing skip). Deeper frames are shared deallocator/eval plumbing
            # (_Py_Dealloc, subtype_dealloc, ...) that would over-match many bugs.
            if chain:
                cand = _site_to_candidate(chain[0])
                if cand:
                    candidates.append(cand)

        matched = set()
        for c in candidates:
            matched |= match(c, self.snap)[0]

        # Faulthandler-only fallback: a SEGV/generic-fatal with no ASan file:line frames and
        # no gdb resolution still carries func names in the faulthandler C stack -- match the
        # innermost catalog-keyed func by name (e.g. PyList_New -> OOM-0004) before giving up.
        # NOT done for a generic-detector assert (Py_DECREF_MORTAL/!_Py_IsStaticImmortal): its
        # producer is an over-decref that already returned, so the visible stack is only frame
        # teardown + innocent-bystander call frames -- matching one by name mis-folds the UAF
        # into an unrelated bug (e.g. a generic _PyObject_MakeTpCall frame -> OOM-0026). Those
        # need rr to pin the producer, so leave them needs-resolution.
        if not matched and not chain and (has_segv or generic_fatal):
            matched |= fh_match(stdout_text, self.snap)[0]

        if matched:
            oid = sorted(matched)[0]
            self.seen[oid] += 1
            if self.prune and self.kept[oid] >= self.keep_cap:
                return False, oid  # known + over cap -> prune duplicate
            self.kept[oid] += 1
            return True, oid

        # Nothing matched the catalog.
        if (has_segv or generic_assert) and not chain and not real_asserts:
            # A pure segv, or a generic-detector over-decref assert (Py_DECREF_MORTAL/
            # !_Py_IsStaticImmortal) we couldn't resolve to a real caller: it's the over-decref/
            # UAF family (needs rr to fold), NOT a discriminating new site. Keep it as
            # needs-resolution, never oomNEW -- mirrors ingest's needs_gdb bucket.
            self.seen["segv:unresolved" if has_segv else "assert:unresolved"] += 1
            return True, "oomSEGV"  # couldn't resolve a site -> always keep
        prim = candidates[0] if candidates else {}
        key = (
            (prim.get("assert_expr") and "%s:%s" % (prim["file"], prim["assert_expr"]))
            or (prim.get("func") and "%s:%s" % (prim["file"], prim["func"]))
            or prim.get("fatal_msg")
            or (chain[0] if chain else "?")
        )
        self.seen["NEW:" + key] += 1
        return True, "oomNEW"  # never prune a candidate-new site

    def report(self):
        lines = ["OOM dedupe summary (seen / kept):"]
        for key, n in self.seen.most_common():
            lines.append("  %-30s seen=%-5d kept=%d" % (key, n, self.kept.get(key, n)))
        return "\n".join(lines)
