# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Fusil is a fuzzing framework originally by Victor Stinner, revived here. **Only the Python
fuzzing path is actively developed and tested** — `fuzzers/fusil-python-threaded` and the
`fusil.python` / `fusil.python.jit` subsystems. The other fuzzers (`fusil-firefox`,
`fusil-php`, `fusil-mplayer`, etc.) and non-Python subsystems (`fusil.network`,
`fusil.linux`, file/process mangling) are legacy: they may not work and are out of scope
unless explicitly being worked on. The current focus is finding crashes in CPython itself,
C extension modules, the CPython Tier 2 JIT, and out-of-memory (allocation-failure) error
paths via `--oom-fuzz` (see the OOM section).

## Environment & dependencies

- Active virtualenv: `/home/danzin/venvs/fusil_venv` (use its `python`).
- `python-ptrace` is a hard runtime dependency — `fusil.application` imports it at module
  load, so the fuzzer cannot start without it. It **is installed** in the dev venv
  (`python-ptrace` 0.9.9), so the runtime stack imports and tests that touch it run. (A real
  fuzzing run still wants the dedicated `fusil` user / `--unsafe`; see Commands.)
- `numpy` and `h5py` are optional; when absent, the relevant argument generators and tests
  skip gracefully (you'll see "Could not import tricky_numpy" / "Numpy is not available").
  Their support **is** verified to work when present: with `numpy`+`h5py` installed the suite
  runs the h5py/numpy tests (skips drop from ~32 to 1) and passes. They have no wheels for the
  free-threaded debug `3.16t` dev venv, so verification uses a normal-CPython venv
  (`~/venvs/fusil_np_verify`, CPython 3.14) — see the numpy/h5py PR.
- Python floor is **3.13+** (`requires-python`): the code uses PEP 701 f-strings (3.12) and
  `types.CapsuleType` (3.13). Earlier metadata claimed 3.11, which never actually worked.
- Tooling in the dev box: `gdb` (`/usr/bin/gdb`) is available and used by OOM-dedup segv
  resolution; `ruff` (`/snap/bin/ruff`) is available for linting; `pyflakes` is **not**
  installed (so `pyflakes.sh` won't run as-is), and `pytest` is not installed.

## Commands

```bash
# Tests use unittest, NOT pytest (pytest is not installed).
python -m unittest discover -s tests           # full suite (numpy-dependent tests skip;
                                               # tests.python.test_write_jit_code ERRORS on
                                               # import — see the JIT section)
python -m unittest tests.python.test_values    # single module
python -m unittest tests.python.test_oom_dedup tests.python.test_oom_dedup_wiring  # OOM dedup

python test_doc.py   # doctest-based tests over doc/*.rst and a few modules (not chmod +x)
# CI runs BOTH of these (ruff 0.15.18, pinned) over fusil/ tests/ fuzzers/fusil-python-threaded
# -- run both before pushing; `ruff check` passing does NOT imply `ruff format --check` passes.
ruff check fusil/ tests/ fuzzers/fusil-python-threaded          # lint (pyflakes.sh needs pyflakes, not installed)
ruff format --check fusil/ tests/ fuzzers/fusil-python-threaded # format check; `ruff format <paths>` to fix

# Build/install. Packaging is defined entirely in pyproject.toml (setuptools
# backend; no setup.py). pip install pulls in python-ptrace; build isolation
# installs setuptools, so it works even though setuptools isn't in the dev venv.
pip install -e .          # editable dev install; installs the 'fusil-python-threaded' command
python -m build           # build sdist + wheel into dist/
# Optional extras for the Python fuzzer's optional features:
pip install -e '.[numpy,h5py]'

# Run the Python fuzzer (needs python-ptrace; run from repo root).
# After install, 'fusil-python-threaded' is on PATH (the only fuzzer exposed as a
# console-script entry point: fusil.python:main). Other fuzzers/fusil-* run from a checkout.
# --unsafe runs child processes as the current user; without it, fusil expects a
# dedicated 'fusil' user/group and will warn/prompt.
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --unsafe [options]

# Useful fuzzer options (see fusil/python/__init__.py:createFuzzerOptions for all):
#   --modules json,sqlite3   limit to specific modules (default: discover all)
#   --only-c                 only C-extension modules
#   --sessions N             stop after N sessions
#   --only-generate          write source.py without executing it
#   --jit-fuzz               enable JIT-stressing code generation
#   --jit-mode synthesize|variational|legacy|all   (see JIT section)
#   --oom-fuzz               OOM (allocation-failure) injection mode (see OOM section)
#   --oom-seq                stateful call SEQUENCES (Phase 4): several calls per scan under
#                            one failure window (found OOM-0036); --oom-seq-len/--oom-window;
#                            --oom-seq-randomize varies len/window per sequence (those = maxes)
#   --oom-dedup-catalog F    in-loop crash dedupe/labeling vs known_sites.tsv; add
#                            --oom-dedup-prune to drop dups, --oom-dedup-resolve-segv
#                            to resolve segvs via gdb so they dedupe too
```

`jit_config.py` is a standalone helper (not part of the fuzzer) that rewrites CPython
source headers to lower JIT thresholds, making the JIT compile sooner/more aggressively
for fuzzing. Point it at a CPython checkout.

## Architecture

For a narrative walkthrough of the Python fuzzer (lifecycle, generation pipeline, crash
detection, OOM/JIT, plugins, safety, option reference), see **`doc/python-fuzzer.md`**.

### Multi-agent system (MAS) core — `fusil/mas/`

Everything is an `Agent` communicating by asynchronous messages. This is the substrate the
whole fuzzer is built on; understand it before touching control flow.

- **Events**: an agent reacts to event `foo` by defining a method `on_foo(self, *args)`.
  `self.send("foo", arg1, ...)` broadcasts to every agent subscribed to `foo`.
- **`MTA`** (`mta.py`) is the message bus: `send()` queues a `Message`; the MTA's `live()`
  delivers queued messages to subscriber mailboxes each step.
- **`Univers`** (`univers.py`) is the main loop: every "step" it calls `readMailbox()` then
  `live()` on each active agent, then sleeps (`--fast`/`--slow` set the sleep). `live()` is
  the per-step hook (abstract on `Agent`).
- **Lifecycle**: `activate()` → `init()`; `deactivate()` → `deinit()`; `destroy()` on
  teardown. Subscriptions are auto-derived by scanning for `on_*` methods.
- **Scoring**: a `ProjectAgent` may implement `getScore()` returning a float in `[-1.0, 1.0]`
  (1 = bug found, 0 = nothing, -1 = input rejected). `Session.computeScore()` normalizes,
  applies each agent's `score_weight`, and sums them into the session score.

### Application → Project → Session hierarchy

Three agent tiers with different lifetimes (`fusil/application.py`, `project.py`, `session.py`):

- **`Application`** (an `ApplicationAgent`): parses CLI/config, sets up logging and the MAS,
  loads plugins, then runs the project. `ApplicationAgent`s (MTA, Univers, logger, the app
  itself) persist for the whole run.
- **`Project`**: runs fuzzing sessions in a loop until enough successes
  (`--success`) or sessions (`--sessions`), or interrupt. Owns the aggressivity agent and the
  run directory (`run-N/`). `ProjectAgent`s are (re)activated per session.
- **`Session`**: one fuzzing attempt. Each session gets its own directory and `session.log`.
  A session stops (`session_stop` → `session_done`) when its score crosses the success or
  error threshold (from config). Key event chain: `project_start` → `session_start` →
  (agents act) → `session_stop` → `session_done` → next session or `univers_stop`. At
  teardown `SessionDirectory.checkKeepDirectory` keeps a *crashing* session's dir (else
  `rmtree`s it) — this is where the persisted crash dirs come from; dirs self-label via
  `session_rename` parts (module name, signal, exit code…), and an optional
  `application.session_keep_policy` (set by OOM dedup) can relabel or prune the dir.

A fuzzer is created by subclassing `Application`, overriding `createFuzzerOptions()` (add
CLI options) and `setupProject()` (wire up the agents). `doc/howto_write_fuzzer.rst` documents
this.

### Python fuzzer subsystem — `fusil/python/`

Entry: `fuzzers/fusil-python-threaded` → `fusil.python.Fuzzer(Application)`.

- **`Fuzzer`** (`__init__.py`): defines all `--*` options and, in `setupProject()`, wires the
  pipeline — `PythonSource` (generator agent) + `PythonProcess` (`CreateProcess`) +
  `WatchProcess`/`WatchStdout` (crash-detection probes). The crash signal is largely textual:
  `WatchStdout.words`/regexes match `segmentation fault`, `Fatal Python error`,
  `AddressSanitizer`, `SystemError`, etc.
- **`PythonSource`** (`python_source.py`): a `ProjectAgent`. Discovers importable modules
  (`ListAllModules`, filtered by `blacklists.py`), and on each `session_start` picks one
  module, calls `WritePythonCode.generate_fuzzing_script()` to emit `source.py`, then sends
  `python_source` so `PythonProcess` runs it under the target interpreter.
- **`WritePythonCode`** (`write_python_code.py`, the largest/most important file): generates
  the test script — imports the target, then emits randomized function calls, class
  instantiations, method calls, objects, and thread/async wrappers. Arguments come from
  **`ArgumentGenerator`** (`argument_generator.py`); hostile inputs come from `tricky_weird.py`
  and `samples/` (weird classes, tricky typing, tricky numpy, mangled objects).

### OOM-injection fuzzing & in-loop dedup — `--oom-fuzz`

Drives allocation-failure error paths to crash CPython / C-extensions. `WritePythonCode`
emits an OOM harness (`write_python_code.py`): `faulthandler.enable()`, a guarded
`from _testcapi import set_nomemory, remove_mem_hooks`, and an `oom_call(label, func,
*args, **kwargs)` wrapper that sweeps `set_nomemory(start, 0)` over `range(0, --oom-max-start)`
(default 1000) per call. Each call prints an `[OOM] <label>` marker (and `start=` per
iteration with `--oom-verbose`) so the crashing invocation/allocation is pinpointable on
replay; `MemoryError` is swallowed — it's the expected boring outcome, so `WatchStdout.kill_words`
drops "MemoryError" in OOM mode — while `SystemError` is surfaced. Real crashes (segfault/abort)
score via the signal probe. `--oom-calls` sets how many calls are wrapped. **Phase 2** also
sweeps class **constructors + methods** (`--oom-classes` / `--oom-methods`, default 5 each) —
reaching constructor/method allocation paths where high-value bugs live (e.g. OOM-0030 is a
str-subclass constructor bug).

**Stateful sequences — `--oom-seq` (Phase 4).** Beyond the single-call `oom_call`,
`--oom-seq` emits multi-step *sequences* (a guarded thunk run by `oom_run`) under one
**bounded failure window** — `set_nomemory(start, start+k)` fails `k` allocations then
*resumes* — so an allocation failure in one call can corrupt state a *later* call trips over
(the cross-call "stale state" class the single-call sweep can't reach). `--oom-seq-len`
(steps, default 3) / `--oom-window` (`k`, default 1; `0` = legacy fail-forever). Add
`--oom-seq-randomize` to randomize each emitted sequence's length (in `[1, --oom-seq-len]`)
and window (in `[1, --oom-window]`) independently, so one instance covers a range of
sequence shapes (the configured values become upper bounds; per-sequence window is passed
to `oom_run(..., window=k)`). Opt-in;
default output unchanged without it. It found **OOM-0036** — a `list.append()` double-free
under `MemoryError` in the `_CALL_LIST_APPEND` bytecode, filed as python/cpython#151818.
Design + the windowed-`set_nomemory` semantics: **`doc/oom-sequences.md`**.

**In-loop dedup** (`fusil/python/oom_dedup.py`; design in `doc/oom-dedup-plan.md`). OOM runs
are ~96% duplicate crashes, so `--oom-dedup-catalog <known_sites.tsv>` (a read-only snapshot
from the sibling `cpython-oom-findings` catalog) dedupes crashes as they happen. On a crash,
`Fuzzer._oom_keep_policy` reads the session's stdout, classifies it (tier-1: aborts/fatals
carry an exact `file:line: func(): Assertion` / `Fatal Python error:` site;
`--oom-dedup-resolve-segv` re-runs `source.py` under gdb (`--oom-dedup-gdb-timeout`, default
120) — deterministic on the same binary —
to resolve segvs/generic-assert fatals), matches the snapshot, and returns `(keep, label)`.
The crash dir self-labels with its bug id (`OOM-00NN` / `oomNEW` / `oomSEGV`); with
`--oom-dedup-prune`, known duplicates past `--oom-dedup-keep N` (default 5) are dropped rather
than persisted. Wiring is a generic `application.session_keep_policy` hook consulted by
`SessionDirectory.checkKeepDirectory` (absent policy ⇒ unchanged keep/rmtree behaviour). The
engine is pure-Python and unit-tested without the runtime stack (`tests/python/test_oom_dedup*.py`,
via an injectable `segv_resolver`).

**Sibling catalog + how we work.** Triage/reporting of these crashes lives in the sibling
**`cpython-oom-findings`** repo (`github.com/devdanzin/cpython-oom-findings`); its
`HANDOFF.md` + `CLAUDE.md` hold the campaign state, the commit/disclosure conventions, and
how the maintainer and Claude work together. Read them before any outward-facing
(issue / gist / PR) step.

### JIT fuzzing subsystem — `fusil/python/jit/`

Activated with `--jit-fuzz`. **`README_JIT.md` (at the repo root) is the authoritative
design doc** — read it before working here. Summary:

- **`WriteJITCode`** (`write_jit_code.py`) is the orchestrator, owned by `WritePythonCode`.
  It dispatches on `--jit-mode`:
  - `synthesize` (default): `ASTPatternGenerator` builds brand-new scenarios by constructing
    a Python AST from scratch.
  - `variational`: takes a template from `bug_patterns.py` (the `BUG_PATTERNS` knowledge base)
    and mutates it, optionally via an AST mutator.
  - `legacy`: original hard-coded friendly/hostile scenarios (regression baseline).
  - `all`: randomly picks a mode + modifiers per test case.
- Note: the `ASTMutator` used by variational mode now lives in the **`lafleur`** project, not
  in fusil. `write_jit_code.py` imports it as `from lafleur.mutator import ASTMutator` and, when
  lafleur is not installed, prints `ASTMutator not available ... Install lafleur for mutations`
  and degrades to a no-op (mutation is skipped). The legacy `tests/python/test_write_jit_code.py`
  still imports the removed `fusil.python.jit.ast_mutator`, so that test errors on import.
- `--jit-feedback-driven-mode` ties into `lafleur`, a corpus/coverage-guided JIT fuzzer that
  was spun off from this repo.

### Plugin system — `fusil/plugin_manager.py`

Plugins extend the Python fuzzer without modifying core. They are discovered via the
`fusil.plugins` entry-point group; each entry point is a `register(manager)` callable invoked
at `Application` startup. Through `PluginManager` a plugin can register: CLI options;
argument generators (categories `simple`/`complex`/`hashable`, with weight and a
`condition(config, module)` predicate); definitions/boilerplate providers; scenario
providers; whole fuzzing modes (`activation_check` + `setup_script`); and `startup`/`shutdown`
hooks. The cereggii fuzzing support was extracted into such a plugin (see git history) — use
it as the reference example for plugin shape.
