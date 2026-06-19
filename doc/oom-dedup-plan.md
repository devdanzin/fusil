# In-loop OOM crash dedupe — integration plan

Goal: let the OOM Python fuzzer dedupe crashes **as they happen**, against the
`cpython-oom-findings` catalog, so it (a) self-labels each crash directory with its bug
id and (b) optionally prunes known duplicates instead of writing thousands of them to
disk. This complements — does not replace — the catalog's batch `ingest.py`: same
snapshot, applied at the highest-leverage point (crash time, same binary).

## Why in-loop (vs. only batch ingest)

- **Same-binary site.** The crash is classified on the exact interpreter that produced
  it — no re-run, no host↔local nondeterminism (the thing that cost us ~26 NOREPROs).
- **No dup flood on disk.** Known-and-over-cap crashes never get persisted.
- **Real-time signal.** "NEW site!" surfaces immediately, not in a later batch.

The single-writer/read-only-snapshot design carries over: fuzzer instances only *read*
`known_sites.tsv`; the catalog stays the lone writer. (See the catalog repo's
`docs/DEDUP_PIPELINE.md`.)

## What is landed now (Phase A core — tested)

- **`fusil/python/oom_dedup.py`** — pure-Python, no python-ptrace dependency. Loads the
  snapshot, classifies a crash from its stdout (tier-1: aborts + fatals carry an exact
  `file:line: func(): Assertion …` / `Fatal Python error: <msg>`), matches the snapshot
  (assert ▸ msg ▸ func ▸ line/near-12), and a `Deduper.decide(stdout) -> (keep, label)`
  with per-bug seen/kept counters.
- **`tests/python/test_oom_dedup.py`** — 14 unit tests (classification, every match
  path, prune-over-cap, new/segv never pruned, prune-off keeps all). Runs in the dev
  venv (no ptrace): `python -m unittest tests.python.test_oom_dedup`.

Safety contract enforced by the engine: `keep=False` is returned **only** for a
*confidently-known* bug already at its sample cap, and **only** when `prune=True`.
New-site, segv (tier-1-unresolved), import, and clean outcomes are always kept.

## Wiring to apply on a python-ptrace host (Phase A glue — needs a live run)

These three edits are inert unless `--oom-dedup-catalog` is passed (off-path behaviour
is byte-for-byte unchanged), so they can't regress existing runs; the *enabled* path
should be smoke-tested on the fuzzing host before merge.

### 1. CLI options — `fusil/python/__init__.py`, in `createFuzzerOptions` OOM group

```python
oom_options.add_option("--oom-dedup-catalog", type="str", default=None,
    help="Path to known_sites.tsv; enables in-loop crash dedupe + dir labeling")
oom_options.add_option("--oom-dedup-keep", type="int", default=5,
    help="Keep at most N sample dirs per known bug (default: 5)")
oom_options.add_option("--oom-dedup-prune", action="store_true", default=False,
    help="Remove known-duplicate crash dirs beyond the keep cap (default: keep all)")
```

### 2. Install the keep-policy — `fusil/python/__init__.py`, end of `setupProject`

```python
if self.options.oom_dedup_catalog:
    from fusil.python.oom_dedup import Deduper
    self._deduper = Deduper(self.options.oom_dedup_catalog,
                            keep=self.options.oom_dedup_keep,
                            prune=self.options.oom_dedup_prune)
    self.session_keep_policy = self._oom_keep_policy   # consulted by SessionDirectory
```

and on the `Fuzzer` class:

```python
def _oom_keep_policy(self, session):
    """Synchronous (keep, label) decision for a crashed session, from its stdout."""
    import os
    try:
        text = open(os.path.join(session.directory.directory, "stdout"),
                    errors="replace").read()
    except OSError:
        return True, None
    return self._deduper.decide(text)
```

Report the tally at shutdown (in `Fuzzer.exit`):

```python
if getattr(self, "_deduper", None):
    self.error(self._deduper.report())
```

### 3. Consult the policy — `fusil/session_directory.py`, in `checkKeepDirectory`

Replace the success branch:

```python
        if session.isSuccess():
            policy = getattr(self.application(), "session_keep_policy", None)
            if policy is not None:
                keep, label = policy(session)
                if label:
                    self.on_session_rename(label)       # synchronous: labels the dir
                if not keep:
                    self.warning("Dedup: prune duplicate crash %s" % self.directory)
                    return False
            self.warning("Success: keep the directory %s" % self.directory)
            return True
```

Why synchronous (a `keep_policy` callback) rather than reacting to `session_success`:
the keep/rename decision happens in `SessionDirectory.deinit` → `checkKeepDirectory` →
`keepDirectory` (which consumes `rename_parts`). Deciding here — where the stdout file
is already complete — avoids racing the async `session_success`/`session_done` delivery
against session teardown. `on_session_rename` is called synchronously so the label lands
in `rename_parts` before `keepDirectory` renames the dir. The hook is generic (any
`Application` may set `session_keep_policy`); the OOM fuzzer is just its first user.

### Smoke test on the host

```bash
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --unsafe --oom-fuzz \
  --oom-dedup-catalog /path/to/cpython-oom-findings/catalog/known_sites.tsv \
  --modules json,sqlite3 --sessions 200
# expect: crash dirs named <module>-OOM-00NN / -oomNEW / -oomSEGV; the shutdown tally
# prints seen/kept per bug. Add --oom-dedup-prune to drop known dups past the keep cap.
```

## Phase B (later)

- **Segv resolution at crash time.** Tier-1 leaves segvs `unresolved` (always kept).
  Resolve them on the same binary via the existing debugger/ptrace path (`replay.py`
  already wires `ptrace_program='gdb.py'`, `allow_core_dump=True`; `process/debugger.py`
  already emits rename parts), so segvs dedupe/prune too. This is the bigger fidelity win.
- **Cross-instance merge.** N local instances each prune against their snapshot; a
  periodic single-writer merge (catalog `ingest.py`) reconciles new-site collisions and
  regenerates `known_sites.tsv`. Snapshot refresh: instances reload on SIGHUP or restart.
- **Snapshot staleness.** Ship a `--oom-dedup-catalog` mtime check / periodic reload so
  long-running instances pick up newly-cataloged bugs.

## Contract

`known_sites.tsv` is the interface between the catalog and the fuzzer:
`<oom_id>\t<kind>\t<keytype>\t<key>` with keytype ∈ {func, line, assert, msg}. The
classify/match logic here mirrors the catalog's `ingest.py`; if that format changes,
update both. (Deliberate small duplication — the two live in separate repos.)
