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

- **Phase 1 (this doc, implemented first):** `_testcapi.set_nomemory` injection,
  **module-level functions only**, no refactor.
- **Phase 2:** extract a single call-emission seam
  (`_emit_call(target, name, args, harness=...)`) so the OOM/plain/JIT paths
  share one primitive, then extend OOM coverage to methods, constructors, and
  returned objects (where the high-value unchecked-allocation bugs live).
- **Phase 3:** libfiu / `LD_PRELOAD` system-malloc injection (reaches foreign C
  libraries that `set_nomemory` cannot), driven via the child process env.

---

## Phase 1 specification

Every change is gated behind `options.oom_fuzz` so non-OOM generation is
byte-for-byte unchanged.

### 1. CLI options (`fusil/python/__init__.py`, `createFuzzerOptions`)

A new `OOM Fuzzing` option group:

| Option | Type | Default | Meaning |
|--------|------|---------|---------|
| `--oom-fuzz` | bool | `False` | Enable OOM mode. |
| `--oom-max-start` | int | `1000` | Dense sweep upper bound (exclusive): each call sweeps `range(0, N)`. |
| `--oom-calls` | int | `10` | Number of OOM-wrapped function calls per script (replaces `--functions-number` in OOM mode, bounding `oom_calls × oom_max_start` total iterations). |
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
    for _start in range(_OOM_MAX_START):
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
