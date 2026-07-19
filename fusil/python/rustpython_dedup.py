"""In-loop dedupe for RustPython (and other Rust-based interpreter) crash fuzzing.

Pure-Python and free of any runtime (python-ptrace) dependency, so it unit-tests in isolation
-- the RustPython analogue of ``oom_dedup.py`` / ``tsan_dedup.py``. RustPython crashes are
overwhelmingly ``.unwrap()`` / ``.expect()`` / ``panic!`` / unchecked-index sites reachable from
Python (a Rust *panic*) plus a smaller class of memory-unsafety *segfaults* (unguarded native
recursion, uninitialised-object protocol slots). This module reduces a crashing session's
captured stdout to a stable **signature** and decides whether that crash is already known, so a
fleet can prune duplicates in-loop and self-label each crash dir.

Signatures:

- **panic**: Rust prints ``thread '<name>' [(<tid>)] panicked at <path>.rs:<line>:<col>:`` (the
  ``(tid)`` group is present on newer toolchains, absent on older ones). The signature is
  ``<path>.rs:<line>`` -- the column is dropped (it drifts with formatting) and the path is
  normalised to start at ``crates/`` so a checkout-absolute path and a relative one dedupe
  together. A worker-thread panic can be printed anywhere in stdout (not just the tail), so the
  first panic in the whole text is used.
- **segv/abort**: a bare SIGSEGV/SIGABRT prints no panic line. With an (injectable) ``segv_resolver``
  -- a gdb re-run of ``source.py``, deterministic on the same binary -- the top Rust frame becomes
  the signature (``SEGV <frame>``); otherwise the crash buckets as ``rustpySEGV``.

The catalog snapshot (``known_panics.tsv``, produced by the sibling ``rustpython-findings``
catalog) maps each known signature to a bug id (``RUSTPY-00NN``). Matching is exact on the
signature. This format is a cross-repo contract (the catalog's ingest imports this module), so a
change here must keep existing signatures stable.
"""

import collections
import os
import re

# ---- report parsing ----
# A Rust panic header. Handles both the newer ``thread 'main' (12345) panicked at ...`` form and
# the older ``thread 'main' panicked at ...`` form. The path runs up to the first ``:`` (Rust
# source paths have no spaces), then ``:line`` and an optional ``:col`` we discard.
PANIC = re.compile(r"panicked at\s+([^\s:]+\.rs):(\d+)(?::\d+)?")


def _norm_panic_path(path):
    """Normalise a panic source path so a checkout-absolute path and a build-relative one dedupe.

    RustPython's compile-time panic locations are usually already ``crates/...rs``; a build that
    baked in an absolute path (``/home/.../checkouts/rustpython-abc123/crates/vm/src/x.rs``) is
    trimmed to the ``crates/...`` tail. Anything without a ``crates/`` segment is returned as-is.
    """
    idx = path.find("crates/")
    return path[idx:] if idx != -1 else path


def parse_report(text):
    """Parse the FIRST Rust panic in ``text``.

    Returns ``{signature, site, kind}`` (``kind == "panic"``) or ``None`` if there is no panic
    line (a bare segfault/abort prints none -- the deduper routes that to the segv path). ``site``
    is ``(file, line)`` for the report; ``signature`` is ``file:line``.
    """
    m = PANIC.search(text)
    if not m:
        return None
    path = _norm_panic_path(m.group(1))
    line = int(m.group(2))
    signature = "%s:%d" % (path, line)
    return dict(signature=signature, site=(path, line), kind="panic")


def parse_all_panics(text):
    """Every DISTINCT panic signature in ``text``, in first-seen order.

    A ``--concurrency-stress`` session can emit several worker-thread panics; this lets a caller
    tally them all. ``parse_report`` stays first-panic-only (the catalog's signature contract), so
    this is purely additive.
    """
    out = []
    seen = set()
    for m in PANIC.finditer(text):
        sig = "%s:%d" % (_norm_panic_path(m.group(1)), int(m.group(2)))
        if sig not in seen:
            seen.add(sig)
            out.append(sig)
    return out


# ---- gdb segv resolution (best-effort, real-path default; injectable for tests) ----
# The top frame in a RustPython backtrace we key a segv on: the innermost frame whose function is
# NOT libc/allocator/panic plumbing. Frame lines from `bt` look like
# ``#12 0x... in rustpython_vm::...::hash (...) at crates/vm/src/.../x.rs:123``.
_GDB_FRAME = re.compile(r"^#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(\S+)")
# Plumbing to skip when picking the top real frame (libc abort/raise, Rust panic runtime, alloc).
_SEGV_PLUMBING = re.compile(
    r"^(?:__|_?abort\b|_?raise\b|core::panic|std::panic|rust_panic|"
    r"core::result::unwrap|core::option::|alloc::alloc|__rust_|handle_alloc_error)"
)


def _gdb_top_frame(bt_text):
    """Given gdb backtrace text, return the top non-plumbing frame function, or None."""
    frames = []
    for line in bt_text.splitlines():
        fm = _GDB_FRAME.match(line.strip())
        if fm:
            frames.append(fm.group(1))
    if not frames:
        return None
    for fn in frames:
        if not _SEGV_PLUMBING.match(fn):
            return fn
    return frames[0]


def gdb_crash_site(python_bin, source_path, timeout=120, drop_uid=None, drop_gid=None):
    """Re-run ``source_path`` under gdb with ``python_bin`` and return the top Rust crash frame
    (a string) or ``None``. Deterministic on the same binary. Best-effort: any failure -> None.

    Drops to ``drop_uid``/``drop_gid`` when running as root (never replay a fuzzed script as root),
    mirroring ``oom_dedup.gdb_crash_site``.
    """
    import subprocess

    if not (python_bin and source_path):
        return None
    cmd = [
        "gdb",
        "-batch",
        "-nx",
        "-ex",
        "run",
        "-ex",
        "bt",
        "--args",
        python_bin,
        source_path,
    ]
    popen_kwargs = {}
    if os.getuid() == 0 and (drop_uid is not None or drop_gid is not None):
        if drop_uid is not None:
            popen_kwargs["user"] = drop_uid
        if drop_gid is not None:
            popen_kwargs["group"] = drop_gid
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "RUST_BACKTRACE": "1", "PYTHONPYCACHEPREFIX": "/tmp/fusil-pycache"},
            **popen_kwargs,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return _gdb_top_frame(out)


# ---- catalog snapshot ----
def load_catalog(lines):
    """Load ``known_panics.tsv`` rows (iterable of lines) -> {signature: bug_id}.

    Row format (tab-separated):  ``<bug_id>\\t<signature>``  (``#`` comment lines ignored).
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


# ---- bounded stdout reader (shared contract with oom_dedup / tsan_dedup) ----
_STDOUT_HEAD = int(os.environ.get("RUSTPY_STDOUT_HEAD", 256 * 1024))
_STDOUT_TAIL = int(os.environ.get("RUSTPY_STDOUT_TAIL", 1024 * 1024))


def read_crash_stdout(path):
    """Read a crash's captured stdout, bounding huge files to head+tail (a panic line can be at
    either end -- a worker panic mid-run, a main-thread panic at the tail). Decoded, errors
    replaced. Mirrors ``oom_dedup.read_crash_stdout``."""
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
class RustPyDeduper:
    """Stateful in-loop deduper: feed each crash's stdout (+ source.py), get ``(keep, label)``.

    ``keep=False`` is only returned for a confidently-known crash already at its sample cap, and
    only when ``prune`` is on -- new / unresolved-segv / unparseable crashes are always kept.
    ``segv_resolver`` (``source_path -> 'frame' | ['frame', ...] | None``) is injectable for
    testing; it defaults to :func:`gdb_crash_site` when ``resolve_segv`` and a ``python_bin`` are
    set.
    """

    def __init__(
        self,
        catalog_path=None,
        keep=5,
        prune=False,
        python_bin=None,
        gdb_timeout=120,
        resolve_segv=False,
        segv_resolver=None,
        drop_uid=None,
        drop_gid=None,
    ):
        self.snap = load_catalog_file(catalog_path) if catalog_path else {}
        self.keep_cap = keep
        self.prune = prune
        self.python_bin = python_bin
        self.gdb_timeout = gdb_timeout
        self.resolve_segv = resolve_segv
        self._resolver = segv_resolver
        self.drop_uid = drop_uid
        self.drop_gid = drop_gid
        self.seen = collections.Counter()
        self.kept = collections.Counter()

    def _resolve(self, source_path):
        """Return the resolved top-frame string for a segv, or None. Any resolver failure is
        swallowed -- resolution is best-effort and decide() must never raise into keep/rename."""
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
            return None
        if not r:
            return None
        return r[0] if isinstance(r, (list, tuple)) else r

    def decide(self, stdout_text, source_path=None):
        """Return ``(keep, label)`` for one crashing session.

        A panic keys on its site (``crates/...rs:line``); a bare segfault/abort with no panic
        line routes to the segv path -- resolved to its top frame via ``segv_resolver`` when
        ``resolve_segv`` is set, else bucketed as ``rustpySEGV``.
        """
        report = parse_report(stdout_text)
        if report is not None:
            return self._classify(report["signature"], kind="panic")
        # No panic line -> a memory-unsafety segfault/abort. Try to resolve a site for dedup.
        if self.resolve_segv:
            frame = self._resolve(source_path)
            if frame:
                return self._classify("SEGV %s" % frame, kind="segv")
        self.seen["rustpySEGV"] += 1
        return True, "rustpySEGV"

    def _classify(self, signature, kind):
        """Map a signature to ``(keep, label)`` via the catalog + prune cap, updating counters."""
        rid = self.snap.get(signature)
        if rid:
            self.seen[rid] += 1
            if self.prune and self.kept[rid] >= self.keep_cap:
                return False, rid  # known + over cap -> prune duplicate
            self.kept[rid] += 1
            return True, rid
        # New (uncatalogued) finding.
        if kind == "segv":
            self.seen["NEW-SEGV:" + signature] += 1
            return True, "rustpySEGV"
        self.seen["NEW:" + signature] += 1
        return True, "rustpyNEW"

    def report(self):
        lines = ["RustPython dedupe summary (seen / kept):"]
        for key, n in self.seen.most_common():
            lines.append("  %-48s seen=%-5d kept=%d" % (key, n, self.kept.get(key, n)))
        return "\n".join(lines)
