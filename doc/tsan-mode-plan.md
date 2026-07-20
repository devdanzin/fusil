# `--tsan` mode: concurrency data-race fuzzing under ThreadSanitizer

**Status:** design/plan (not implemented). Sibling of `doc/oom-fuzzing.md` /
`doc/oom-dedup-plan.md`; this mode is modelled on the OOM subsystem's structure (a
generator-side harness + parent-side wiring + a pure-Python noise-dedup engine).

## 1. Goal & scope

Drive **C-level data races** in CPython extension modules (and, secondarily, CPython
core) by generating source that hammers **shared objects from many threads at once**,
run under a **free-threaded, ThreadSanitizer-instrumented** interpreter, and score a
`WARNING: ThreadSanitizer: data race` report as a finding.

**Why this is worth building (not just noise):**

- **Free-threading is the gate.** Under the GIL, bytecode is serialized; TSan sees the
  GIL as one giant happens-before edge and finds essentially nothing at the Python
  level (only C code that explicitly drops the GIL can race). Under free-threading
  (`PYTHON_GIL=0`, a `--disable-gil` build) concurrent Python operations become
  concurrent C memory accesses — shared refcounts, container resizes, type/method
  caches, module state. **Non-FT TSan is out of scope** (it would be pure noise).
- **Core is fair game, not just extensions.** `Tools/tsan/suppressions_free_threading.txt`
  is currently **empty** — CPython expects *zero* known races on the free-threaded build, so
  any race we surface in core is a real finding, not pre-suppressed noise. Free-threading is
  still an active research area: cpython#149816 alone catalogs 22 races (in `_random`,
  `typeobject`, `call.c` kwargs growth, `listobject`, `dictobject`, `_pickle`,
  `gc_free_threading`, …), several with reproducers — a ready-made corpus to validate the
  harness against. Extension modules that haven't been made FT-safe are additional fresh
  ground (and where this project's recent finds live), but the empty core suppressions mean
  the CPython interpreter itself is squarely in scope. (Reality check: the builtin containers
  `list`/`dict`/`set` are now protected by per-object critical sections, so the races live in
  the less-travelled C paths, not the obvious ones — which is exactly why a fuzzer helps.)
- **It directly targets the bug class we already hit by harder means.** The cereggii
  finds — `AtomicDict` double-`DECREF` when a colliding key's `__eq__` raises, and
  `_Py_SetWeakrefAndIncref` corrupting deferred-refcount objects under *concurrent stores
  of a deferred key* — are textbook data races. They were pinned via rare OOM/GC crashes
  plus `rr`. TSan surfaces that same class **directly and deterministically as a race
  warning**, before it corrupts into a crash. That is the core motivation.

**Non-goals:** deadlock detection (TSan does it, but our generated code rarely takes two
locks); non-FT builds; combining with `--oom-fuzz` (see §5.1); making CPython-core races
actionable (they are upstream's job and largely suppressed).

## 2. Why the current generator is a weak TSan driver

Today `--threads` (on by default) wraps *every* generated call in a
`Thread(target=bound_method, args=fresh_args)` appended to `fuzzer_threads_alive`, then
`_write_concurrency_finalization` starts them all in one loop and joins them in another
(`write_python_code.py` `_write_thread_call_wrapper` / `_write_concurrency_finalization`).
So threads **do** overlap, and because `target_func` is a bound method of a **pooled,
shared** object, multiple threads already touch the same receiver concurrently (concurrent
`INCREF`/`DECREF` on it and its type). That is a nonzero TSan driver.

But it is tuned for *"does calling this in a thread crash"*, not *"do concurrent ops on one
object race"*:

| Weakness | Effect on TSan |
|---|---|
| One thread per call site, spread across many different objects | Low probability two threads pound the **same** object's **same** internal state — the thing that trips a race |
| Threaded args are freshly built per thread (`create_simple_argument`) | No **shared mutable argument** races (two threads mutating one list/dict/buffer passed in — a huge FT bug class) |
| One call per thread | Races usually need the op **repeated** in a loop to manifest the unordered access on a shared line |
| Threads trickle out of the start loop; `join(timeout=1.0)` abandons slow ones | Weak temporal overlap; an abandoned thread still racing at interpreter shutdown is itself noise |
| The `set_nomemory` swap is thread-unsafe (the documented `_thread-…-oomNEW` harness artifact in `non_bugs.md`) | `--oom-fuzz` + threads is a *harness* race — must be mutually exclusive with `--tsan` |

## 3. Design overview

Three pieces, each mirroring an existing subsystem:

- **(A) A concurrency-stress emitter** in `WritePythonCode`, gated on `self.options.tsan`,
  that replaces the per-call one-thread-per-callsite pattern with a **concentrated**
  shape: a few shared objects, K worker threads, each doing M iterations of a randomized
  op-mix on the *same* shared object(s), released together by a `threading.Barrier`.
- **(B) Parent-side wiring** in `Fuzzer.createFuzzerOptions` / `setupProject`: the option
  group, mutual exclusion with OOM, child-env setup (`TSAN_OPTIONS`, suppressions,
  `PYTHON_GIL=0`), a target-build preflight, and the TSan detection words on `WatchStdout`.
- **(C) A race-report dedup/suppression engine** `fusil/python/tsan_dedup.py`, pure-Python
  and unit-testable in isolation, mirroring `oom_dedup.py` / `hit_suppression.py`.

## 4. Generated harness (the emitter)

### 4.1 Shape

Instead of `fuzzer_threads_alive.append(Thread(...))` per call, the TSan harness emits, at
the end of `_write_main_fuzzing_logic`:

```python
# --- TSan concurrency-stress region (emitted only under --tsan) ---
import threading
_tsan_shared = [obj_3, obj_7, module_alias]         # S objects drawn from the pool
_tsan_ops = [                                        # thunks, each a closure over a shared obj
    lambda: obj_3.append(payload_a),                 # mutators/readers on the SAME objects,
    lambda: obj_3.pop() if obj_3 else None,          # incl. dunder/attr churn and shared args
    lambda: obj_7.update(shared_dict),               # shared_dict passed to MULTIPLE threads
    lambda: len(obj_3),
    lambda: setattr(obj_7, 'x', obj_3),
    ...
]
_tsan_barrier = threading.Barrier(TSAN_THREADS)
def _tsan_worker(wid):
    _tsan_barrier.wait()                             # release all workers hot, together
    for _ in range(TSAN_ITERS):
        op = _tsan_ops[(wid + _) % len(_tsan_ops)]   # deterministic per-wid schedule
        try:
            op()
        except Exception:
            pass                                     # a Python-level exc is not the signal
_tsan_threads = [threading.Thread(target=_tsan_worker, args=(i,), name=f'tsan{i}')
                 for i in range(TSAN_THREADS)]
for t in _tsan_threads: t.start()
for t in _tsan_threads: t.join()                     # clean join, NO timeout (see §11)
```

Key properties vs today: **the same objects and the same argument objects are shared by
multiple workers** (concurrent mutation is the point), **the op is repeated M times** to
manifest the race, and **the `Barrier` starts workers simultaneously** to maximize overlap.

### 4.2 Reuse of existing machinery

- Shared objects come from the existing object pool that `WritePythonCode` already builds
  (`obj_N`) plus the module alias; the emitter picks `--tsan-shared-objects` of them.
- The op thunks are built from the same call/method selection the synchronous path uses
  (`ArgumentGenerator`, method discovery, `tricky_weird`/`samples` hostile inputs) — a TSan
  op is just an existing call closed over a *shared* receiver/arg instead of a fresh one.
- Emission goes through the indentation API (`with self.indented():`) like the rest of the
  generator; no new output primitive.

### 4.3 Free-threading preflight (in the generated harness)

The harness must fail loudly if it is not actually running free-threaded (otherwise the
whole run is silent GIL-serialized noise):

```python
import sys
if getattr(sys, "_is_gil_enabled", lambda: True)():
    print("[TSAN] FATAL: GIL is enabled; free-threading required", file=stderr)
    raise SystemExit(3)
```

Parent-side we *also* preflight the target build (§5.2), but the in-harness check is the
authoritative guard and is cheap.

### 4.4 Relationship to `--threads` / `--async`

`--tsan` **replaces** the per-call thread wrapper (they would just dilute the stress region
and double-run everything). Implementation: when `options.tsan` is set, pass `threads=False`
to `WritePythonCode` (the async path can stay off too) and emit the stress region instead.
`--tsan` implies free-threading and is mutually exclusive with `--oom-fuzz`/`--oom-foreign`.

## 5. Parent-side wiring (`fusil/python/__init__.py`)

### 5.1 Options (new "TSan Fuzzing" `OptionGroup`, added like the OOM group)

| Flag | Default | Meaning |
|---|---|---|
| `--tsan` | off | Enable TSan concurrency-stress mode (implies FT; excludes `--oom-*`) |
| `--tsan-threads N` | 8 | Worker threads in the stress region |
| `--tsan-iterations N` | 200 | Op iterations per worker (repetition = race manifestation) |
| `--tsan-shared-objects N` | 3 | How many pooled objects are shared across workers |
| `--tsan-suppressions FILE` | auto | TSan suppressions file (defaults to the target's CPython `Tools/tsan/suppressions_free_threading.txt` if discoverable) |
| `--tsan-halt` | off | `halt_on_error=1` (stop at first race) vs report-and-continue |

`setupProject` validates: `--tsan` + `--oom-fuzz` → hard error (the `set_nomemory` swap is a
harness race, §2); `--tsan` with a non-FT `--python` → hard error from the preflight (§5.2).

### 5.2 Child environment & build preflight

`TSAN_OPTIONS` reaches the child through the **same** `process.env.set(...)` path that
`--oom-foreign` uses for `LD_PRELOAD`/`PYTHONMALLOC`:

```python
tsan_opts = [
    "halt_on_error=%d" % (1 if options.tsan_halt else 0),
    "history_size=4",              # deeper race histories; extensions have deep stacks
    "second_deadlock_stack=1",
    "exitcode=99",                 # distinct, so WatchProcess can also see it if halting
]
if suppressions: tsan_opts.append("suppressions=%s" % suppressions)
process.env.set("TSAN_OPTIONS", ":".join(tsan_opts))
process.env.set("PYTHON_GIL", "0")     # env.py already copies PYTHON_GIL to the child
```

Preflight the target build once at startup (mirrors `probe_shim_effective` for
`--oom-foreign`): run `python -c "import sys, sysconfig; print(sys._is_gil_enabled(),
sysconfig.get_config_var('CONFIG_ARGS'))"` and require **both** `_is_gil_enabled()==False`
(or GIL-disable-able) **and** a `--with-thread-sanitizer` build. If TSan is not compiled in,
the race instrumentation is absent and the whole run silently finds nothing — fail fast with
a clear message rather than run a no-op campaign.

### 5.3 Detection (the crucial gap)

Today `WatchStdout.words` has `AddressSanitizer: 1.0` but **no** TSan entry, and TSan
defaults to *report-and-continue* — so a race today would print to stderr, the process would
exit 0, and the session would be discarded as "no crash." Add:

```python
stdout.addRegex(r"WARNING: ThreadSanitizer: data race", 1.0)
stdout.addRegex(r"ThreadSanitizer: .*(heap-use-after-free|lock-order-inversion)", 1.0)
```

Because detection is textual, we catch the race **even when `halt_on_error=0`** (the process
keeps running and exits clean, but the warning is already in the captured stdout and scores).
`--tsan-halt`/`exitcode=99` is offered for runs that prefer a hard stop (then `WatchProcess`
sees the exit code too).

## 6. Noise control: `tsan_dedup.py` (race dedup + suppression)

TSan is noisy: the same race fires every run, and many races are known/benign. Mirror the
OOM subsystem's split — a **pure-Python engine** (`fusil/python/tsan_dedup.py`, no
python-ptrace import, unit-tested in isolation) that:

- **Parses** a TSan report into a signature: the pair of `(func@file:line)` access sites in
  the `Write`/`Read`/`Previous` stanzas, plus the mutex/thread-creation context. Canonicalize
  the two racing locations as an unordered pair so `A vs B` and `B vs A` dedupe together.
- **Suppresses** three sources, unioned like `hit_suppression.py`:
  1. CPython's `suppressions_free_threading.txt` (passed to TSan itself via `TSAN_OPTIONS`,
     but we also filter post-hoc so a suppressed race never scores).
  2. Per-target project suppressions (a race in the *extension* we accept / have filed).
  3. **fusil's own harness races** — anything whose both frames are in the generated harness
     scaffolding (`_tsan_worker`, the barrier, the thread registry) rather than target code.
- **Dedupes in-loop** against a catalog snapshot, exactly like `--oom-dedup-catalog`: a known
  race past `--tsan-dedup-keep N` is pruned; a new race self-labels the crash dir (`TSAN-00NN`
  / `tsanNEW`) via the `application.session_keep_policy` hook `SessionDirectory.checkKeepDirectory`
  already consults.

This composes with the existing hooks — no new keep/prune plumbing, just a third policy.

## 7. Build & target requirements

- **Interpreter:** CPython built `--disable-gil --with-thread-sanitizer` (TSan and ASan are
  mutually exclusive — this is a *separate* build from the ASan matrix builds). Point
  `--python` at it. The build matrix (`~/projects/python_build_matrix`) needs a new
  `{debug,release}-ft-tsan` cell.
- **Extensions:** must be compiled with `-fsanitize=thread` to instrument their C. An
  un-instrumented extension only races visibly through CPython's own (mostly suppressed) core
  — so the target extension **must** be a TSan build (document this; it is the #1 "why did I
  get nothing" gotcha, analogous to the `--oom-foreign` static-ASan shadowing note).
- **numpy default off** under `--tsan` (numpy is not FT-clean → it would flood); the numpy
  plugin's inject-everywhere behavior should honor a TSan opt-out.

## 8. Scoring / dir labeling / fleet integration

- A matched TSan word scores 1.0 → the session is kept (like any crash word).
- `tsan_dedup` self-labels the kept dir via `session_rename` parts (module, `TSAN-00NN` /
  `tsanNEW`) exactly as `oom_dedup` does.
- `StatsAgent` needs no change (it already records `PYTHON_GIL`); `fleet report` will show
  TSan-mode instances by their kept-dir taxonomy once the labels exist.

## 9. Phasing

- **Phase 1 (minimal end-to-end): IMPLEMENTED (2026-07-15).** Option group
  (`--tsan`/`--tsan-threads`/`--tsan-iterations`/`--tsan-shared-objects`/`--tsan-suppressions`)
  + mutual-exclusion with `--oom-*` + a target-build preflight (free-threaded **and**
  `--with-thread-sanitizer`, else fail fast) + the stress emitter
  (`WritePythonCode._write_tsan_stress_region`, which also disables the per-call thread/async
  wrappers) + the `WARNING: ThreadSanitizer: data race` detection regex + the child env. **See
  the "Phase 1 as-built" section below** for the environment recipe that made detection
  actually work (it took several non-obvious fixes). Validated end-to-end against a purpose-built
  racy `ctypes.memset` module on the `debug-ft-nojit-tsan` build: the race is generated,
  detected, scored, and the crash dir self-labels
  `…-exitcode66-warning_threadsanitizer_data_race`. Manual suppressions only (Phase 2 adds the
  dedup engine). Tests: `tests/python/test_tsan_generation.py` (6, gated so goldens are
  unchanged).
- **Phase 2: IMPLEMENTED (2026-07-15).** `fusil/python/tsan_dedup.py` (pure engine) + the sibling
  `cpython-tsan-findings` catalog repo + the `session_keep_policy` wiring + unit tests. See
  "Phase 2 as-built" below. Turns a noisy stream into deduped, labeled, prunable findings.
- **Phase 3: op-mix enrichment IMPLEMENTED (2026-07-15).** The worker now also exercises the
  FT-race-rich classes: concurrent `gc.collect()`, attribute-dict churn (`setattr`/`getattr`/
  `delattr` on one shared instance — the managed-dict race class), `weakref.ref` creation, and
  shared-container mutation (every sibling worker hammers one `list`/`dict`/`set`/`bytearray`).
  And **`--tsan` now implies `--no-numpy`** (the numpy plugin injected `import numpy` the TSan
  target lacks). See "Phase 3 as-built" below. **Still open (future):** per-target suppression
  management, barrier/iteration auto-tuning, and pointing it at real CPython core / an FT-unsafe
  extension (cereggii) rather than the synthetic fixture.
- **Phase 4 — fleet-triage readiness (2026-07-15).** The `cpython-tsan-findings` catalog is
  published (`github.com/devdanzin/cpython-tsan-findings`), its `ingest.py` verified against real
  fusil `--tsan` crash-dir stdout (it parses the race out of the full session output, not just a
  clean report), the `fleet` preflight validates a `--tsan` fleet's TSan target + `known_races.tsv`
  catalog, and `fleet/README.md` documents the `--tsan` fleet config + the ingest → report →
  `gen_known_races` triage loop. Ready to point at a real target and catalog real races.
- **Fleet 01 (first real run) + a harness fix.** The first `--tsan` fleet found ~17 distinct race
  signatures (11 seeded as `TSAN-0001..0011`; dominant = cjkcodecs `MultibyteIncrementalDecoder`
  getstate/reset, 10 vehicles). It also surfaced a repeated `SEGV addr=0xd8` in `pty` runs: the
  crashing pc resolves to **`__tsan::TraceSwitchPart`** — the *ThreadSanitizer runtime*, not
  CPython. Cause: the stress region reached `pty.fork()`/`os.forkpty()` (via the shared module
  object's `dir()`), forking a worker thread; TSan does not support `fork()` in a multithreaded
  process without an immediate `exec`, so the child crashes in the TSan runtime. Fix: the emitter
  now excludes process-lifecycle calls (`TSAN_UNSAFE_CALLS`: fork/forkpty/spawn*/exec*/_exit/
  abort/system/popen/…) from both `_tsan_funcs` and the runtime `dir()` loop — they are never a
  useful race target and would fork/replace the fuzzer anyway.
- **`posix-sigabrt` NOPARSE = the same self-destruct class, second face.** The other `tsanNOPARSE`
  cluster was two `posix` runs killed by **SIGABRT** (signal 6) with *no* ThreadSanitizer output at
  all — stdout ending exactly at `[TSAN] entering concurrency-stress region`. Diagnosed as
  `posix.abort()` (≡ `os.abort()`): the pre-fix unfiltered `dir()` loop over the shared `posix`
  module called it, and C `abort()` raises SIGABRT directly. Reproduces in one line
  (`posix.abort()` → exit 134). Same root cause and **same fix** as the `pty` SEGV — `abort` is in
  `TSAN_UNSAFE_CALLS`, so post-fix the shared module never exposes it. Deliberately *not*
  auto-suppressed in the deduper: a bare signal-6 with no message is a harness self-abort, but a
  signal-6 carrying a `Fatal Python error:` / `Assertion` banner would be a real concurrency crash,
  so NOPARSE stays a manual glance. (Catalog: `notes/harness-self-destruct-noparse.md`.)

## Phase 1 as-built: the environment recipe (hard-won)

Getting TSan to *actually report* took several non-obvious fixes — each one silently produced
"runs clean, finds nothing." Recorded here so they aren't rediscovered:

- **Build:** `~/projects/python_build_matrix/builds/debug-ft-nojit-tsan/python` — CPython 3.16
  `--disable-gil --with-thread-sanitizer` (GIL off by default). A `release-ft-nojit-tsan` cell
  also exists.
- **ASLR must be disabled — `setarch -R`.** Modern high-entropy ASLR is incompatible with TSan's
  shadow layout (`WARNING: ThreadSanitizer: memory layout is incompatible … high-entropy ASLR`),
  after which TSan detects nothing. `setarch -R` (`ADDR_NO_RANDOMIZE`) fixes it and is a thin
  exec wrapper (PID preserved, so process monitoring is unaffected). fusil prepends it to the
  target command under `--tsan`. (`mmap_rnd_bits` can't be lowered without root here, so
  per-process `setarch` is the portable fix.)
- **`RLIMIT_AS` must be unlimited.** TSan reserves terabytes of shadow and, if it sees a finite
  virtual-address cap, *re-execs itself* to raise it — and a finite **hard** cap makes that
  re-exec's `setrlimit()` fail with `EINVAL (22)`, after which TSan runs degraded and finds
  nothing. fusil applies a ~4 PiB `RLIMIT_AS` by default (fine for ASan, which fits); under
  `--tsan` the cap is dropped entirely (`create.py` zeroes `max_memory`, and `setupProject`
  skips the 4 PiB override so `limitResources` resets `RLIMIT_AS` to unlimited).
- **`TSAN_OPTIONS=halt_on_error=1:symbolize=1:exitcode=66:history_size=4` + `DEBUGINFOD_URLS=`
  (cleared in the child).** The earlier "symbolizer hang" was **diagnosed, not a TSan/build
  fault**: `llvm-symbolizer` honours `DEBUGINFOD_URLS`, which Ubuntu sets to
  `https://debuginfod.ubuntu.com` in every login shell (`/etc/profile.d/debuginfod.sh`), and
  that endpoint is currently blackholed (TCP connect gets no SYN-ACK/RST → libcurl spins in a
  ~forever `poll()` retry). Clearing `DEBUGINFOD_URLS` in the child makes symbolization return in
  ~0.3s with full frames from the target's own (complete) local debug info — so we **symbolize
  in-loop**, and the racing site lands in the crash dir for triage/dedup. (`DEBUGINFOD_TIMEOUT=1`
  is a gentler alternative but pays ~1s per module; the empty form is better for crash sessions.
  gdb was immune because Ubuntu's gdb defaults debuginfod off in batch mode.) fusil's child env
  is minimal and doesn't copy `DEBUGINFOD_URLS`, but it's set empty explicitly so symbolization
  stays fast regardless of the parent env. `halt_on_error=1` + `exitcode=66` stop at the first
  race with a clean exit.
- **`PYTHON_GIL=0`** (set explicitly even though the build defaults to it).
- **`--no-numpy` is required today.** The `fusil_numpy_plugin` (installed in the fuzzer venv)
  injects `import numpy` into *every* generated script's boilerplate; the TSan target has no
  numpy, so the child dies with `ModuleNotFoundError` before reaching the stress region. Pass
  `--no-numpy` (Phase 3: `--tsan` should imply it — numpy isn't FT-clean anyway).
- **Module discovery vs. the target's stdlib.** The fuzzer imports the target module to
  enumerate members; do **not** put the whole 3.16t `Lib` on the (3.14) fuzzer's `PYTHONPATH`
  (it will try to import 3.16's `encodings` against its own `_codecs` and die at startup). Give
  the fuzzer the test module via a *clean* directory; the target finds it on its own `sys.path`.

**Detection path:** a matched `WARNING: ThreadSanitizer: data race` scores the session 1.0
(`WatchStdout` regex, added unconditionally — it only fires on a real TSan report); the child
also exits 66. The kept dir self-labels `…-exitcode66-warning_threadsanitizer_data_race`.

**Validation fixture (throwaway):** a module whose class method / module function both do an
unsynchronized `ctypes.memset` on a process-global buffer — concurrent calls are a guaranteed
C-level race TSan reports. Dropping it in the target's `Lib` and pointing
`fusil --tsan --no-numpy --modules <mod>` at the `debug-ft-nojit-tsan` build yields
`Total: 1 success`. (A real campaign points at CPython core / an FT-unsafe extension instead.)

## Phase 2 as-built: dedupe + the catalog repo

- **`fusil/python/tsan_dedup.py`** (pure, unit-tested in isolation — the TSan analogue of
  `oom_dedup.py`). `parse_report(text)` pulls the first `data race` report out of a crash's
  stdout and reduces it to a **signature**: the sorted pair of top-real-CPython sites
  (`file:func | file:func`) from the two access stanzas. Frame handling learned from real
  reports: the *first* access is capitalised (`Write`/`Read`), the *second* lowercased
  (`Previous write`/`Previous read`); interceptor/`<null>`/non-CPython-`.so` frames carry no
  CPython source and drop out; generic call/eval dispatch (`_PyObject_MakeTpCall`,
  `_PyEval_EvalFrameDefault`, `*StackRef*`, …) is skipped to reach the real racing function.
  Function-level (lines drift). `TSanDeduper.decide(text) -> (keep, label)`: suppressed →
  `(False, None)`; both-sites-in-thread-scaffolding → `(True, "tsanFRAME")` (framework noise,
  kept out of the NEW bucket); catalog hit → the race id (prune past `--tsan-dedup-keep` with
  `--tsan-dedup-prune`); else `(True, "tsanNEW")`. `parse_report` also handles non-race TSan
  reports (`SEGV`/`heap-use-after-free`/`lock-order-inversion`/`deadlock`): one crash stack →
  the top-real-site signature if symbolized, else `SEGV addr=0x.. pc=0x..` (deterministic under
  `setarch -R`), labeled `tsanSEGV`. Added after fleet 01 turned up unsymbolizable SEGV storms
  (`nested bug … aborting`) that otherwise lumped as `tsanNOPARSE`.
- **Wiring** (`__init__.py`): `--tsan-dedup-catalog` / `--tsan-dedup-keep` / `--tsan-dedup-prune`,
  installed as `_tsan_keep_policy` on the same `application.session_keep_policy` hook the OOM/hit
  paths use (hit-suppression still wraps it). The kept dir self-labels e.g.
  `<mod>-warning_threadsanitizer_data_race-exitcode66-TSAN-0001`. `--tsan-suppressions` is reused
  post-hoc (TSan `race:`/`race_top:` lines + plain-regex over the signature). Verified end-to-end:
  a 4-session run with `--tsan-dedup-prune --tsan-dedup-keep 1` keeps one dir labeled `TSAN-0001`
  and prunes the three duplicates.
- **Catalog repo `~/projects/cpython-tsan-findings`** (sibling of `cpython-oom-findings`, stood up
  local-only — nothing to publish yet). `reports/TSAN-NNNN-*/meta.json` (`signatures[]`),
  `catalog/known_races.tsv` (`<race_id>\t<signature>`, generated by `scripts/gen_known_races.py`),
  `catalog/suppressions.txt`, and `scripts/ingest.py` which **reuses `tsan_dedup.py` by file path**
  (`FUSIL_TSAN_DEDUP=…`) so the snapshot and the in-loop deduper share one signature implementation
  and can't drift. Empty today (no races catalogued).
- Tests: `tests/python/test_tsan_dedup.py` (14) — parse, unordered-pair canonicalisation,
  interceptor/plumbing skip, catalog match, prune-past-cap, suppression, framework, no-race.

## Phase 3 as-built: op-mix enrichment + numpy-off

The Phase 1 worker only did read-churn + a method call + a module-function call. Phase 3 adds the
operation classes where free-threading bugs actually live (the ones the OOM/cereggii campaign
kept hitting), all guarded and type-agnostic, per worker iteration:

- **Attribute-dict churn** — `setattr(_obj, "_tsan_aN", i)` / `getattr` / periodic `delattr` on a
  *shared* instance: concurrent `__dict__` materialise/mutate, the managed-dict race class
  (OOM-0023/`set_keys`, dpdani's cereggii deferred-refcount corruption).
- **Concurrent `gc.collect()`** (every 16th iteration) while the above churns refcounts and
  containers — concurrent collection is itself a rich FT-race surface.
- **`weakref.ref(_obj)`** creation — concurrent weakref-list mutation on the shared object.
- **Shared-container mutation** — every sibling worker on one `_idx` hammers the same
  `list`/`dict`/`set`/`bytearray` (`append`/`pop`/`update`/`add`/`discard`), so the container
  itself is a concurrent-access target, not just an argument.

**`--tsan` implies `--no-numpy`** (`setupProject`): numpy isn't FT-clean and the numpy plugin
injects `import numpy` into every generated script, which the numpy-less TSan target can't import
— it died before the stress region. Now auto-forced (guarded: only when that plugin option exists
and the user didn't already pass it), logged as `TSan: forcing --no-numpy`. Verified end-to-end:
a run with **no** `--no-numpy` flag now auto-suppresses numpy and still detects + labels the race.
Test: `test_tsan_generation.py::test_enriched_op_mix_emitted`. Goldens unchanged (emitter gated).

### Phase 3.1: shared-iterator + read-while-mutate ops (2026-07-18)

Two op classes added after the `unicode_ascii_iter_next` find (cpython#153928) showed the op-mix
never *shared an iterator across threads* — it built iterators (`iter(_obj)`) but discarded them,
so the entire "concurrent `next()` on one iterator" surface was unreachable:

- **(h) Shared-iterator races** — a pool of one live iterator per kind, each held in a 1-element
  cell and shared *by reference* so every sibling worker advances the **same** cursor. Each
  iteration does a few `next()`s and a periodic `repr()` (state read racing the concurrent
  `next()`s). Covers the builtin iterator family (`str`/`bytes`/`list`/`tuple`/`dict`/`range` —
  the non-atomic `it_index`/`it_seq` class) plus the stdlib C iterators from the sibling reports:
  `struct.Struct.iter_unpack` (cpython#154013) and `itertools.count(10**18, 2)` in **big-int
  "slow mode"** (cpython#153981). Finite iterators are rebuilt from their factory on
  `StopIteration`; `count()` never exhausts.
- **(i) Read-while-mutate on the shared container** — iterate/copy/sort the shared
  `list`/`dict`/`set`/`bytearray` while sibling workers mutate it in (f): the non-atomic
  reader-vs-writer class (`list` `Py_SIZE` + `binarysort`/`list.sort` = TSAN-0013/0014,
  `bytes_join`, dict/odict/set iter-vs-resize = TSAN-0015/0026).

Tests: `test_tsan_generation.py::{test_shared_iterator_op_emitted,test_read_while_mutate_op_emitted}`.
Emitter still gated (non-`--tsan` output unchanged).

## Phase 4: target-object coverage + provenance + extension dedup

**Status (2026-07-18):** all five slices are **implemented** — **A** (worker roles, PR #213),
**B** (provenance/attribution, PR #214), **C** (target-object factories + extension-object
iterators + the `add_tsan_shared_factory` plugin hook, PR #215), **D** (external C-extension
source roots for `tsan_dedup` via `--tsan-source-root`, PR #216), and **E** (hostile subclasses of
the target's own C types, **opt-in** via `--tsan-weird-subclasses`). Operation *profiles* remain
deliberately PARKED. The slice descriptions below are the as-designed intent; see the commit
history / the memory note for exact as-built details. Slice D preserved the cross-repo signature
contract: re-ingesting fleet-06 with the new parser and no roots reproduced all 119 CPython
signatures byte-for-byte.

**Motivation.** Phase 3.1 proved the op-mix finds *builtin* races (TSAN-0037, the bytes iterator)
because the shared pool is mostly builtin containers + bare `Class()` instances. The campaign's
actual value is races in the *target C extension* (cereggii/h5py/…). Phase 4 points the same
machinery at the extension's own objects, attributes races correctly, and makes extension-source
races dedupable. Derived from a Codex review (2026-07-18); **operation *profiles* are deliberately
excluded** (parked — see Open questions) — Phase 4 keeps the single always-on op-mix and enriches
it in place.

### Slice A — complementary worker roles (in-place, no profiles)

Today every `_tsan_worker` runs the identical op-mix; identical workers under-produce the
reader-vs-writer overlap the interesting races need (next-vs-repr found the `count` bug #153981;
mutate-vs-iterate is the whole read-while-mutate class). Assign a **role by `_wid`** so siblings
sharing one `_idx`/resource do *complementary* ops: iterator group → some `next()` (advance),
others `repr()`/`len()`/`list()` (read cursor); container group → some mutate, others sort/iterate/
copy; object group → some read-churn, others attr-dict/weakref/GC mutation. Keep the single start
barrier (round-level re-sync noted as an optional knob, not built). File: `write_python_code.py`
only. Tests: role markers emitted + `compile()` + FT smoke-run. Risk: low (emitter-only, gated).

### Slice B — provenance / attribution

Fixes the real misattribution: a builtin race gets stamped with whatever module the session picked.
The parent knows the full context at generation time → emit a stdout marker into the generated
script (`[TSAN] provenance module=… shared=<factory-descriptors> roles=<map> ops=<…> seed=<N>` +
a `[TSAN-MANIFEST] {json}` line) so it lands in every crash dir's stdout, and record the op-family /
shared-object *kind* per session in `fusil_stats.json` (`stats_agent.py`) so `fleet report` shows
iterator-race vs target-object-race distribution. Files: `write_python_code.py`, `stats_agent.py`,
a thread-through in `python_source.py`. Risk: low (additive output + one stats field).

### Slice C — better target objects (+ extension-object iterators)

Replace the `_tsan_shared` builder (currently `sample(module_classes)` instances + module) with a
set of **guarded factories**, recording which succeed (feeds Slice B):
1. splice the already-discovered-but-unused `self.module_objects` into the pool;
2. instantiate `module_classes` with args from the existing `ArgumentGenerator` (guarded), not just
   `Class()`;
3. a new `PluginManager` hook (`add_tsan_shared_factory` / `get_tsan_shared_factories`) so
   cereggii/h5py plugins contribute target-specific shared objects (e.g. `AtomicDict()`);
4. module fallback (keep).

**Extension-object iterators (folded in):** for each object factory, also register wrapped variants
`lambda: iter(factory())` (and `lambda: iter(factory(range(X)))` where a sequence-ish arg fits) into
the op-(h) iterator pool — pointing the shared-iterator machinery at the extension's own
`tp_iternext`. Everything guarded, so non-iterable/failed factories drop out. Files:
`write_python_code.py`, `plugin_manager.py`, `doc/plugins.md`. Using the hook from the sibling
plugins is a follow-up. Risk: medium — keep factories guarded; `--tsan` gate intact.

### Slice D — external C-extension source roots (strictly additive; contract-touching)

Without it, extension `.so` frames are dropped (`CPY_SRC` only matches CPython dirs) → `noparse`.
Add an **optional** `source_roots=None` param to `parse_report`/`_frame_site` (`tsan_dedup.py`):
default → current behavior byte-for-byte (CPython matched first, all 119 catalog sigs unchanged);
otherwise normalize a non-CPython frame to its path relative to a matching root (`/…/cereggii` →
`src/atomic_dict.c:func`). New repeatable `--tsan-source-root` feeds the in-loop dedup. Sibling
catalog `ingest.py` reads roots from env/config and passes them through, plus CPython-vs-ext /
ext-vs-ext signature tests. **Guardrail (mandatory):** `test_tsan_dedup` + re-ingest fleet-06 →
119 CPython sigs identical. Risk: medium (the cross-repo contract) — additive-only + the re-ingest
check.

### Slice E — weird subclasses derived from extension classes (later / optional)

Wire the `tricky_weird` weird-class machinery to derive hostile subclasses from *discovered
extension bases* and share instances — the hostile-dunder-under-concurrency angle that turned up
cereggii's `__eq__`-raises-during-concurrent-store bug. **Deferred** because: subclassing is gated on
`Py_TPFLAGS_BASETYPE` (only a subset of C types allow it — guarded, lower/target-dependent yield);
it's a bigger integration than a factory variant; and it can surface the weird class's *own*
Python-level races (noise). Gate on subclassability; do after A–D land and lean on Slice B/D to keep
its output attributable and dedupable.

### Order & verification

**A → B → C → D** (A/B low-risk quick wins; C is the payoff; D independent but needs the catalog in
lockstep), E later. After each slice: full suite, `test_tsan_generation` + `test_tsan_dedup`,
non-`--tsan` golden check (untouched), `ruff check` + `ruff format --check`; for C/D a real
emitted-script smoke run + a fleet re-ingest showing **0 unexpected new signatures**.

## Phase 5 as-built: multi-race per session (`--tsan-no-halt`)

**Status (2026-07-18):** foundation landed as PR #221, dedup/keep + sidecar as PR #222.

**Motivation.** After the count-`__repr__` fast-mode fix (cpython#153917) landed and the TSan
build was rebuilt, fleet-10 surfaced a diverse spray of *new* races (`setiter_iternext`,
`unicodeiter_next`, `dictiter_iternext_threadsafe`, `_decimal_Context_clear_traps_impl`,
`_PyLong_DigitCount`, `_elementtree create_extra`) — but that diversity was **across** sessions.
Under the default `halt_on_error=1`, TSan reports only the **first** race per session and exits,
so every other race a session could expose is thrown away. Re-running one fleet-10 `_decimal`
`source.py` under `halt_on_error=0` produced **13 report blocks = 10 distinct races** from a
single session (the count residual + its UAF faces + two genuine new `_decimal` Context races
`…clear_traps_impl | context_repr` and `… | type_call` + a cascade SEGV) — proving both the
value and the caveat: the count UAF cascaded into a SEGV, so races reported *after* a fault can be
corruption artifacts rather than independent findings.

**#1 + #2 — capture (PR #221).**
- `--tsan-no-halt` sets `TSAN_OPTIONS halt_on_error=0` (opt-in; default stays `halt_on_error=1`;
  exit is still 66 and detection stays textual, so a session surfaces *every* race instead of the
  first).
- `tsan_dedup.parse_all_reports(text, source_roots=None)` splits a report-and-continue stdout on
  each `WARNING:`/`==PID==ERROR: ThreadSanitizer:` header, parses each chunk with the *unchanged*
  `parse_report`, de-dupes by signature, and returns the distinct races in stream order with an
  `order` index. `parse_report` stays first-report-only, so the sibling catalog's signature
  contract (which imports `parse_report`) is untouched.

**#3 — dedup / keep / sidecar (PR #222).**
- `TSanDeduper.decide_all(text)` classifies **every** distinct race (via the shared
  `_classify_report`, so tallying and the prune cap behave exactly as the single-race `decide`).
  It returns `(keep, headline_label, races)`: **keep-if-ANY** race is worth keeping; a dir is
  pruned only when **every** race is a known-over-cap duplicate or suppressed. The dir name takes
  the **headline** label — the first new finding (`tsanNEW`/`tsanSEGV`), else the first kept known
  id. For 0 or 1 parseable reports it delegates to `decide`, so the default `halt_on_error=1` path
  (accounting, label, noparse) is byte-for-byte unchanged.
- Each race carries `after_fault` — True once a SEGV/UAF has appeared earlier in the same stream —
  flagging the corruption-artifact caveat above.
- A multi-race kept session drops a **`tsan_races.tsv` sidecar** (`format_races_tsv`, columns
  `order/label/kind/after_fault/signature`, signature last so a naïve tab-split is safe) next to
  `source.py`, recording the full per-race breakdown for the sibling catalog's ingest (#4). Only
  written under `--tsan-no-halt` with ≥2 distinct races, so default runs are unaffected.

## Phase 6 as-built: concurrent stateful-object mutation (`--tsan-mutate-state`)

The base op-mix is tuned for **CPython-level** races (managed-dict, refcount, container,
iterator, gc, weakref) and is **argument-starved** on the target object: op (b) calls methods
with four fixed generic containers (`_tsan_shared_args`), so an extension's real mutators
(`Tokenizer.add_tokens(list[str])`, `enable_truncation(int)`, …) `TypeError` on the wrong
arg types and are swallowed *before mutating*; op (d) only reassigns a synthetic `_tsan_aN`
int, never a real settable property (`.normalizer` / `.model`). Consequence, proven on the
tokenizers fleet (`fusil-tokenizers_01`): a 32-dir gdb sample was **32/32 CPython, 0/32
tokenizers** — the interesting *mutate-while-read* extension race surface was never exercised.

`--tsan-mutate-state` (opt-in, `store_true`, default off; in the `tsan_options` group so it
applies to `--tsan` **and** `--concurrency-stress`) adds it via a runtime `_MUTATE_STATE` gate
in the single worker body — off ⇒ op (b) runs today's container-arg path verbatim and op (j)
is skipped, so existing campaigns and the dedup catalog are unchanged:

- **op (b) enriched** — when a plugin registry entry exists for `type(_obj)`, call its curated
  `mutators` with real args; else draw from a type-diverse pool `_tsan_call_args` (str/int/
  float/bool/list/tuple/dict/bytes/None) so generic single-arg mutators actually fire.
- **op (j) property reassign** (new) — writers reassign a settable property while readers read
  it. Curated tier: a fresh value from the plugin registry (`.normalizer = Lowercase()`).
  Generic fallback (any object): **self-reassign** `setattr(o, n, getattr(o, n))` over the
  type's settable descriptors (`hasattr(getattr(type(o), n), "__set__")`) — always type-valid,
  still races the setter's internal lock / pointer-swap against a concurrent reader.

**Core/plugin split.** The mechanism + generic fallback are in core (module-agnostic); the
curated per-type *mutators / property factories* live in a plugin, published as the child-side
global `_FUSIL_STATEFUL_MUTATORS` via `add_definitions_provider` (the scenario pattern — no
live callable crosses the process boundary). The region reads `globals().get(
"_FUSIL_STATEFUL_MUTATORS", {})` defensively, exactly as it reads optional `plugin_factories`.
Contract + recipe: [`plugins.md`](plugins.md) (*Concurrency-stress mutators*).

**Provenance.** The manifest gains `"mutate_state": bool` and appends `"j:prop-reassign"` to
`ops` (human line `ops=a-i` → `ops=a-j`) only when the flag is on. Tests:
`test_tsan_generation.py` (`test_mutate_state_off_by_default`,
`test_mutate_state_ops_emitted_when_enabled`, `test_plugin_mutator_registry_spliced_and_consulted`).

**Caveats / EV.** Mutations succeed, so they cut swallowed-exception noise but reduce
reproducibility (state diverges per run) and can wedge slow mutators; the generic tier is a
blind `dir()`/descriptor sweep. And real *race detection* for a lock-correct extension (HF
tokenizers wraps state in `Arc<RwLock<…>>`) wants a **TSan-instrumented** extension build
(`.so` compiled `-fsanitize=thread`) — on a plain ASan/FT build only genuine memory-safety
bugs in the extension's `unsafe` code surface.

## 10. Testing

- **Golden emitter tests:** the stress region is deterministic given a seed → add a golden
  like the existing generator goldens (no golden regen for non-`--tsan` output — the emitter
  is gated, so default output is unchanged).
- **Pure-engine tests** for `tsan_dedup.py` (parse a canned TSan report → signature; unordered
  pair canonicalization; suppression union; catalog dedupe) — no runtime stack, like
  `test_oom_dedup.py`.
- **Smoke target:** a tiny hand-written FT-unsafe C extension (unguarded shared counter) as a
  deterministic "TSan must fire" fixture, kept out of CI if no TSan build is available there.

## 11. Open questions & risks

- **Throughput.** TSan is slower and more memory-hungry than ASan; sessions will run fewer
  ops/sec. Mitigate with smaller `--tsan-iterations` and by concentrating on a targeted module
  set rather than discover-all.
- **Nondeterminism.** A race may not fire every run even with repetition; this is a
  *statistical* fuzzer — lean on many sessions (fleet) rather than expecting per-session hits.
  (Contrast with OOM, which is deterministic on a given binary.)
- **Clean shutdown.** Drop the `join(timeout=1.0)` abandonment in the stress region — a thread
  still racing while the interpreter tears down produces shutdown-phase races that are noise.
  Workers are bounded by `--tsan-iterations`, so a plain `join()` terminates.
- **Suppression maintenance.** The CPython suppressions file drifts per version; pin it to the
  target build's copy (discover via `sysconfig`), and keep fusil-harness suppressions minimal
  by construction (the scaffolding should never itself race).
- **Attribution.** Distinguishing target-extension races from CPython-core races (mostly
  suppressed) from fusil-harness races is exactly what `tsan_dedup`'s three suppression sources
  are for; getting the harness-frame filter right is the main correctness risk.

## 12. Summary

`--tsan` reuses the OOM subsystem's proven skeleton — a gated generator harness, parent-side
env/detection wiring, and a pure-Python noise-dedup engine — but points it at a different
failure class (data races) on a different build (FT + TSan). The generator change is the
substance: swap the diluted one-thread-per-call pattern for a concentrated, repeated,
barrier-released stress region over **shared** objects and arguments. The payoff is a direct
lens on the FT-unsafe-extension bug class this project already finds the hard way.
