# OOM (Out-Of-Memory) Fuzzing in Fusil

This document describes the design and phased plan for fusil's OOM-injection
fuzzing mode, which fails memory allocations to drive code down its rarely-tested
allocation-failure error paths and surface crashes (segfaults / aborts) caused by
unchecked allocations.

The technique is adapted from the `cext-review-toolkit` reproducer catalog
(Techniques 18, 23, 27, 31). The key adaptation for fusil: the toolkit runs each
sweep iteration in its own subprocess because it wants to *classify every
allocation offset*; fusil only wants to *find a crash*, and the generated
`source.py` is already a disposable child process whose crash is exactly the
signal fusil watches for. So **no per-iteration subprocess isolation is needed**.

## How it fits fusil's model

- **Crash detection is signal-based.** `WatchProcess.computeScore`
  (`fusil/process/watch.py`) returns `signal_score = 1.0` for any process killed
  by a signal (SIGSEGV/SIGABRT). The OOM-injected `source.py` crashing *is* the
  success signal.
- **Calls are centralized.** All calls route through the generated
  `callMethod` / `callFunc` helpers, and `jit_harness` already establishes the
  "run target in a loop" idiom. An OOM sweep is the same shape:
  `for start in range(N): set_nomemory(start, 0); target()`.

## Phases

- **Phase 1 (implemented):** `_testcapi.set_nomemory` injection,
  **module-level functions only**, no refactor.
- **Phase 2 (implemented — constructors + methods):** extend OOM coverage to
  class **constructors** and **methods**, where the high-value unchecked-allocation
  bugs live (e.g. OOM-0030 is a str-subclass constructor bug). Done with a targeted
  `_generate_oom_class_fuzzing(prefix, class_name, class_obj)` that reuses the existing
  `oom_call` harness rather than the originally-sketched `_emit_call` seam refactor —
  the seam (unifying the plain/JIT/OOM call-emission paths) is deferred as separate
  cleanup since it touches the working plain and JIT paths for no extra coverage.
  Returned-object methods (depth > 1) remain a future Phase 2c.
- **Phase 3:** libfiu / `LD_PRELOAD` system-malloc injection (reaches foreign C
  libraries that `set_nomemory` cannot), driven via the child process env.
- **Phase 4 (prototype — stateful call sequences, behind `--oom-seq`):** let one OOM scan
  exercise *several* calls so an allocation failure in one call can corrupt state that a
  *later* call trips over (the cross-call "stale state" class — OOM-0033, OOM-0035, the
  stale-exception family). Built on a **bounded failure window**
  (`set_nomemory(start, start+k)`, which fails `k` allocations then auto-resumes) so probe
  steps can run past the failure. Phase 4a (method chains + function sequences) is
  implemented; producer→consumer (4b) and mutate-reread (4c) are deferred. Full design in
  [`oom-sequences.md`](oom-sequences.md).

## Phase 2 specification (classes)

Gated behind `options.oom_fuzz`, after the Phase 1 function sweeps and bounded by two
new options (so OOM-mode cost is controlled separately from the non-OOM
`--classes-number`/`--methods-number`):

| Option | Default | Meaning |
|--------|---------|---------|
| `--oom-classes` | `5` | Classes to OOM-fuzz per script (constructor sweep + method sweeps); `0` disables class fuzzing in OOM mode. |
| `--oom-methods` | `5` | Method sweeps per instantiated class. |

`_generate_oom_class_fuzzing` emits, per chosen class:

1. **Constructor sweep** — the class object is itself the callable:
   `oom_call("oc<i>:<mod>.<Class>", getattr(fuzz_target_module, "<Class>", None), <ctor args>)`.
2. **One live instance**, built once *outside* any sweep via the existing `callFunc`
   helper in a `try/except`, so methods run against a real object (not re-created 1000×).
3. **Method sweeps** on that instance (discovered at generation time via
   `_get_object_methods`, blacklist-respecting), guarded by
   `if inst is not None and inst is not SENTINEL_VALUE:` — each is
   `oom_call("oc<i>m<j>:<mod>.<Class>.<method>", getattr(inst, "<method>", None), <args>)`.
   The safe `getattr(..., None)` plus the harness guard `if ... or func is None: return`
   make a missing bound method a no-op sweep, never a raise.

The non-OOM class/object blocks stay gated off in OOM mode (the function loop falls
through to the class loop, then returns).

---

## Phase 1 specification

Every change is gated behind `options.oom_fuzz` so non-OOM generation is
byte-for-byte unchanged.

### 1. CLI options (`fusil/python/__init__.py`, `createFuzzerOptions`)

A new `OOM Fuzzing` option group:

| Option | Type | Default | Meaning |
|--------|------|---------|---------|
| `--oom-fuzz` | bool | `False` | Enable OOM mode. |
| `--oom-max-start` | int | `1000` | Dense sweep upper bound (exclusive): each call sweeps `range(--oom-start-min, N)`. |
| `--oom-start-min` | int | `0` | Dense sweep lower bound (inclusive): sweep `range(M, --oom-max-start)` instead of from 0. Skips shallow failure points; with a small window below `--oom-max-start` it enables fast **targeted replay** of a known crash near its trigger `start`. Must be `< --oom-max-start` (an empty range is rejected at startup). |
| `--oom-calls` | int | `10` | Number of OOM-wrapped function calls per script (replaces `--functions-number` in OOM mode, bounding `oom_calls × (oom_max_start − oom_start_min)` total iterations). |
| `--oom-verbose` | bool | `False` | Also print the sweep `start` index before each injection, so the exact failing allocation can be pinpointed on replay (verbose; ~`oom_max_start` lines per call). |

Options thread automatically via `self.options` → `PythonSource` →
`WritePythonCode.options`.

### 2. Generated-script changes (`write_python_code.py`)

**Boilerplate** (in `_write_script_header_and_imports`, gated):

```python
import faulthandler
faulthandler.enable()          # C traceback on SIGSEGV, before any arming
try:
    from _testcapi import set_nomemory as _set_nomemory, remove_mem_hooks as _remove_mem_hooks
    _OOM_AVAILABLE = True
except ImportError:
    _OOM_AVAILABLE = False
    print("OOM mode requested but _testcapi.set_nomemory unavailable; running without injection", file=stderr)
```

**Harness** (in `_write_helper_call_functions`, gated):

```python
_OOM_MAX_START = <oom_max_start>
_OOM_MIN_START = <oom_start_min>   # default 0
_OOM_VERBOSE = <oom_verbose>

def oom_call(label, func, *args, **kwargs):
    # Dense OOM sweep. The per-call marker (printed once, before the sweep)
    # identifies which invocation was running if a crash follows -- more reliable
    # than the faulthandler frame, which is often an incidental allocation rather
    # than the fuzzed target. MemoryError is swallowed silently; SystemError is
    # surfaced (PyCFunction contract violations); a segfault/abort terminates the
    # process (the signal fusil scores). remove_mem_hooks runs in the inner finally
    # so the except clauses allocate safely.
    if not _OOM_AVAILABLE:
        return
    print("[OOM] " + label, file=stderr)
    for _start in range(_OOM_MIN_START, _OOM_MAX_START):
        if _OOM_VERBOSE:
            print("[OOM]   start=" + str(_start), file=stderr)
        _set_nomemory(_start, 0)
        try:
            try:
                func(*args, **kwargs)
            finally:
                _remove_mem_hooks()
        except MemoryError:
            pass
        except SystemError:
            print("[OOM] SystemError in " + label, file=stderr)
        except BaseException:
            pass
```

**Call sites** (new `_generate_oom_function_call`, reusing
`_write_arguments_for_call_lines` and `get_arg_number`):

```python
# OOM sweep: <func_name>
oom_call("<prefix>:<module>.<func_name>", getattr(fuzz_target_module, "<func_name>"),
    <arg lines>,
)
```

Arguments are built **once** at the `oom_call(...)` expression (outside the sweep
loop); arming happens inside `oom_call` after the args exist.

### Pinpointing which call crashed

faulthandler's top Python frame is frequently an *incidental* allocation (GC /
finalization / warnings firing as the budget runs out), not the fuzzed target —
so it is unreliable for attribution. The **last `[OOM] <prefix>:<module>.<func>`
marker** printed before the crash dump identifies the culprit invocation. With
`--oom-verbose`, the immediately preceding `[OOM]   start=N` line gives the exact
allocation offset, which is enough to write a minimal reproducer. Marker prefixes
(`[OOM]`) are chosen to avoid the stdout scorer's words.

### 3. Wiring (`_write_main_fuzzing_logic`)

Branch the function loop and bound it by `--oom-calls`; gate the class and object
fuzzing blocks with `if not self.options.oom_fuzz:` so Phase 1 emits only function
sweeps.

### 4. Detection config (`fusil/python/__init__.py`, `setupProject`)

```python
stdout.kill_words = {"mimalloc"} if self.options.oom_fuzz else {"MemoryError", "mimalloc"}
```

With `MemoryError` out of `kill_words` it matches none of the scoring words, so it
neither kills nor scores. The harness's `print(type(_err).__name__)` surfaces other
exceptions; of single-token exception names only `SystemError` collides with a
scoring word (intended — catches PyCFunction contract violations). Real crashes
score via `WatchProcess` signal handling, independent of stdout.

## Behavioral decisions

- **Silent harness** (no per-iteration prints) — avoids log floods,
  `FileWatch.max_process_time` stalls, and accidental word matches.
- **Surface non-MemoryError exceptions** so `SystemError` etc. are still caught.
- **`remove_mem_hooks` in the inner `finally`** so the `except` clause runs with
  the allocator restored.
- **Dense, from 0** — sparse sweeps miss one-allocation-wide crash windows;
  deeper-budget coverage accumulates across sessions.
- **`_testcapi` self-guarded** — mode no-ops with a notice if the target
  interpreter lacks it.

## Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Session timeout from long sweeps | `oom_calls × oom_max_start` bounded; timeouts non-scoring unless `--record-timeouts`. |
| `_testcapi` missing | Self-guarded import → no-op with notice. |
| Output volume / log stalls | Silent harness except surfaced exception types. |
| False-positive scoring | Exception-name prints don't match scoring words except intended `SystemError`. |
| First crash ends that script's sweep | By design — crash = the find; coverage accumulates across sessions. |

## Acceptance criteria

1. `--oom-fuzz` produces a script with guarded `_testcapi` import,
   `faulthandler.enable()`, an `oom_call` dense-sweep harness, and `oom_calls`
   function-call sweep sites.
2. Non-OOM generation is unchanged.
3. Benign module: runs to completion, MemoryError neither kills nor scores.
4. A segfault/abort in any swept call is scored 1.0 by existing `WatchProcess`.

## Usage

```bash
# Inspect generated output only:
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --unsafe --oom-fuzz \
    --modules json --sessions 1 --oom-calls 5 --oom-max-start 200 --only-generate

# Run for real on a benign module:
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --unsafe --oom-fuzz \
    --modules json --sessions 3 --oom-calls 5 --oom-max-start 200
```
