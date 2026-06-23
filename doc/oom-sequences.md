# OOM stateful call sequences ("corrupt-then-probe")

**Idea 1**, prototyped behind `--oom-seq` (default off): let a single OOM scan exercise
*more than one* call, so an allocation failure during one call can leave damaged state
that a *later* call trips over. This targets the cross-call "stale state" bug class that
the current single-call harness can only find by accident.

Companion to [`oom-fuzzing.md`](oom-fuzzing.md) (Phase 1 = module functions, Phase 2 =
constructors/methods, Phase 3 = libfiu). This is **Phase 4**.

## Motivation

The current harness (`oom_call`) is *stateless and single-call*: it sweeps the failure
point through **one** call and can only catch a bug when the allocation failure **and**
the thing that trips over the damage happen inside that one call. But several of our own
findings are inherently multi-step — damage in step A, crash in step B:

| Bug | Step A (damage under OOM) | Step B (clean-ish step that crashes) |
|-----|---------------------------|--------------------------------------|
| **OOM-0035** | `StringIO.write…` grows the buffer, leaves uninitialized `Py_UCS4` garbage | `getvalue()` scans the garbage → bad `maxchar` |
| **OOM-0033** | `sys.path[:] = str` over-decrefs an entry | `__import__` walks the freed entry |
| **stale-exception family** (0008/0010/0011/0015/0025/0032) | an OOM error path leaves an exception *pending* | a later op asserts none is pending |

We caught these mostly by luck (Phase-2 method sweeps re-run the same method ~1000×, so
accumulation happened inside one label). Making sequences first-class generalizes that.

## Mechanism

Two ingredients: a **bounded failure window** so execution can continue past the failure,
and a **multi-step body** swept by that window.

### 1. The windowed `set_nomemory` primitive (the key)

`set_nomemory(start, stop)` (confirmed from `Modules/_testcapi/mem.c`): a global counter
increments on every allocation; allocation #`n` fails iff `n > start` **and**
(`stop <= 0` **or** `n <= stop`). So:

- `set_nomemory(start, 0)` — the current sweep: fail allocation `start+1` and **every one
  after, forever**.
- `set_nomemory(start, start + k)` — fail exactly **k** allocations (`start+1 … start+k`),
  then **resume succeeding**. The hook stays installed as a transparent passthrough (it
  does *not* auto-uninstall — `remove_mem_hooks()` is still required), the counter keeps
  ticking globally.

That auto-resume is exactly what a sequence needs: with the current fail-*forever* mode,
the moment you cross the threshold every later allocation also fails, so probe steps can't
allocate and do nothing. A bounded window fails a burst, then lets execution continue so
later steps run on whatever state the burst left behind.

### 2. The `oom_run` harness (generated, gated)

A sequence is emitted as a 0-arg thunk whose body is the multi-step scenario; `oom_run`
sweeps the failure window around calling it:

```python
def oom_run(label, thunk, window=1):
    if not _OOM_AVAILABLE:
        try: thunk()
        except BaseException: pass
        return
    print("[OOM-SEQ] " + label, file=stderr)
    for _start in range(_OOM_MAX_START):
        if _OOM_VERBOSE:
            print("[OOM-SEQ]   start=" + str(_start) + " window=" + str(window), file=stderr)
        _set_nomemory(_start, (_start + window) if window > 0 else 0)
        try:
            try:
                thunk()
            finally:
                _remove_mem_hooks()
        except MemoryError:
            pass
        except SystemError:
            print("[OOM-SEQ] SystemError in " + label, file=stderr)
        except BaseException:
            pass
```

Because the counter resets on each arm and the window is armed **once** before the whole
thunk, sweeping `_start` walks the failure burst across the sequence's allocation
timeline: low `_start` lands the burst inside step A; once A's allocations are exhausted,
higher `_start` lands it inside step B (which is now operating on A's output/state). One
sweep covers "fail inside A" *and* "fail inside B after A set things up" — no explicit
corruptor/probe split is needed in the mechanism; the corruptor/probe *structure* is just
how we pick steps so that step _k_ tends to use state from step _k-1_.

### 3. Generated shape

The thunk guards each step so a step that fails (e.g. the corruptor `MemoryError`s)
doesn't abort the tail — the probe still runs. Result vars are pre-bound to `None`:

```python
def _oom_seq_f1():
    r1 = None
    try:
        r1 = getattr(fuzz_target_module, "dumps")(<arg>)
    except BaseException:
        pass
    try:
        getattr(fuzz_target_module, "loads")(r1)          # probe reuses A's (maybe half-built) result
    except BaseException:
        pass
oom_run("f1:json[dumps>loads]", _oom_seq_f1, window=1)
```

A segfault/abort isn't catchable, so it still terminates the process and scores; only
`MemoryError`/ordinary exceptions are swallowed per step, and `SystemError` is surfaced.

## Assessment: variable-N failure windows

> *Your question: does `set_nomemory(start, N)` with variable N make sense, and does
> "variable number of failures" add useful variability the way module mixing would?*

**Yes — and it's the enabling primitive above, not merely a variability knob.** The
windowed mode is what makes probe steps runnable. Beyond that, the window width `k` is a
genuine, *structured* coverage dimension — it selects **which slice of the failure space**
you probe:

| Window | What it tests | Yield |
|--------|---------------|-------|
| `k = 1` (recommended default) | a *single* unchecked allocation fails, program otherwise runs → both the immediate error path **and** deferred/aftermath bugs. Purest "what if exactly this alloc fails?" | highest signal |
| `k` small (2–8) | a short **burst** fails → error paths that only break when *several* allocations fail (retry loops, multi-alloc ops partially failing) | real, lower density |
| `k = 0` (fail-forever, current) | the operation **cannot allocate at all** → the immediate cleanup/error path of one call | already mined for all 35 bugs |

So this axis is **orthogonal and complementary** to Idea 2's module-mixing: variable-N
varies the *failure pattern*; module-mixing varies the *code surface*. Variable-N is much
cheaper and more targeted, and it's the right first lever — fold it into Idea 1 as the
injection primitive (`--oom-window`, default 1), optionally randomizing `k` per sequence
for extra spread. Frame it as coverage, not noise.

> **Implemented (`--oom-seq-randomize`).** This per-sequence randomization now exists: with
> the flag set, each emitted sequence draws its window uniformly from `[1, --oom-window]` and
> its length from `[1, --oom-seq-len]` independently (the configured values become upper
> bounds; the window is passed per call as `oom_run(..., window=k)`). One instance thus covers
> a range of sequence shapes instead of a single static config — strictly more general (a
> fixed config is just the `min == max` case). Default off; generated output is unchanged
> without it.

**Cost to be honest about:** auto-resume means the crash can occur *far* from the
injection point (causal distance grows with `k` and sequence length), which weakens the
"which allocation caused it" link and makes minimization harder. `k = 1` keeps it tight;
fail-forever keeps the crash nearest the first failure. The `[OOM-SEQ] start=` markers +
site-keyed dedup bound the damage, and the existing subprocess self-sweep repro convention
already handles allocation-baseline drift.

## Step selection (how steps come to share state)

In increasing sophistication:

1. **Phase 4a — independent steps over shared state** *(implemented)*. Two emitters,
   both with steps that interact only through *shared* state (no return-value threading):
   - **method chains** (`_generate_oom_class_fuzzing` under `--oom-seq`): one `oom_run`
     over `oom_seq_len` methods of Phase 2's single live instance — the instance is the
     shared state. Directly matches OOM-0035 (`write…` then `getvalue()`).
   - **function sequences** (`_generate_oom_function_sequence`): `oom_seq_len` module
     functions in a row — shared state is module/interpreter globals (a pending exception,
     specializer/GC state), targeting the stale-exception family.
2. **Phase 4b — producer → consumer** *(deferred)*. Capture a call's return value and feed
   it to the next (`r = f(...); g(r)`), reusing fusil's object-passing. The shared state is
   the returned object, possibly half-built under OOM. The thunk form already supports it;
   only the generator needs to thread `r_k → arg_{k+1}`.
3. **Phase 4c — mutate-then-reread shared state** *(deferred, research-y)*. `lst[:] = …`
   then read it; `sys.path` mutation then import (OOM-0033). Higher-level and often
   module-specific.

## CLI options (new, gated behind `--oom-fuzz`)

| Option | Default | Meaning |
|--------|---------|---------|
| `--oom-seq` | `False` | Emit stateful call sequences. **Opt-in**, so the default fleet behavior and baseline are unchanged and `--oom-seq` can be A/B'd. |
| `--oom-seq-len` | `3` | Steps per sequence (corruptor + probes). |
| `--oom-window` | `1` | Failure-burst width `k` for windowed injection; `0` = legacy fail-forever (only sensible for single calls). Applies to `oom_run`; `oom_call` stays fail-forever. |

## Labeling & dedup

- Sequence marker `[OOM-SEQ] <label>` once; `--oom-verbose` prints `start=`/`window=` per
  iteration and (added) each step's sublabel as it executes, so the last line printed
  before the signal pinpoints the crashing step on replay.
- **In-loop dedup is unaffected** — `oom_dedup` keys off the crash *site* (native ASan
  backtrace / abort assertion in stdout), independent of how many calls preceded. Sequences
  will re-hit known sites more often; `--oom-dedup-*` + `--oom-dedup-prune` already handle
  the duplicate volume.

## Wiring (where the code goes)

- **Harness:** add `oom_run` to the boilerplate block in
  `_write_script_header_and_imports`, gated on `oom_fuzz and oom_seq`, beside `oom_call`.
- **Generation:**
  - 4a: in `_generate_oom_class_fuzzing`, when `--oom-seq`, emit a guarded multi-step
    thunk over `oom_seq_len` instance methods + one `oom_run(...)` instead of the
    independent per-method `oom_call`s.
  - 4b: add `_generate_oom_function_sequence(prefix)` (pick `oom_seq_len` module
    functions, optionally thread `r_k → arg_{k+1}`), driven from `_write_main_fuzzing_logic`
    when `--oom-seq`.
  - Reuse `_write_arguments_for_call_lines`; the one non-trivial bit is emitting a
    **guarded multi-statement thunk** (per-step `try/except`, result vars pre-bound to
    `None`) rather than a single call expression.
- All gated; with `--oom-seq` absent, generated output is byte-for-byte the current
  Phase-1/2 output.

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Probe steps can't allocate | Bounded window (auto-resume) is the default mechanism; don't use fail-forever for sequences. |
| Crash far from injection → harder triage/minimization | `--oom-window 1` default; keep `--oom-seq-len` small (≤3); rely on subprocess self-sweep + shrinkray. |
| Allocation-baseline sensitivity amplified by length | In-loop dedup is site-keyed (unaffected); repro convention already cold-starts each `start`. |
| More duplicate crashes | `--oom-dedup-catalog` + `--oom-dedup-prune` already in place. |
| Default-behavior / fleet-baseline drift | `--oom-seq` opt-in, default off. |
| Per-step swallow hides a signal | Segfault/abort uncatchable (still scores); `SystemError` surfaced per step. |

## Acceptance criteria

1. `--oom-fuzz --oom-seq` emits the `oom_run` helper and ≥1 multi-step sequence using
   `set_nomemory(_start, _start + window)`; with `--oom-seq` absent, output is unchanged.
2. Benign module (e.g. `io`, `json`) runs to completion; `MemoryError` neither kills nor
   scores; probe steps demonstrably execute (verify under `--oom-verbose`).
3. A segfault/abort in any step scores 1.0 via existing `WatchProcess`; in-loop dedup
   labels it by site, unchanged.
4. Defaults: `--oom-window 1`, `--oom-seq-len 3`.
5. A short A/B fleet run (`--oom-seq` vs not) reaches at least the OOM-0035-class shape
   (method-chain corrupt-then-read).

## Trying it

```bash
# Inspect generated sequences only (functions, then a method chain):
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --force-unsafe --oom-fuzz --oom-seq \
    --modules json --sessions 1 --oom-calls 2 --oom-seq-len 3 --oom-max-start 40 \
    --only-generate --source-output-path /tmp/seq.py

# Run for real on a benign module (debug build, set_nomemory available):
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --force-unsafe --oom-fuzz --oom-seq \
    --modules io --sessions 3 --oom-classes 3 --oom-seq-len 3 --oom-window 1
```

Fleet A/B: add `--oom-seq` to one instance's flags (leave another on the current
single-call harness) and compare `oomNEW` yield over a few hours against the same catalog.
`--oom-seq` composes with `--oom-dedup-catalog`/`--oom-dedup-prune` unchanged (dedup is
site-keyed). Defaults: `--oom-seq-len 3`, `--oom-window 1`.

## Validation plan

- **Unit:** add `TestOOMSeqGeneration` to `tests/python/test_oom_fuzz.py` — assert the
  helper + a windowed multi-step `oom_run(...)` appear with the flag, and that legacy
  output is unchanged without it.
- **Manual:** `--only-generate` inspection on `io`/`json`.
- **A/B fleet:** one instance `--oom-seq`, one without; compare `oomNEW` yield over a few
  hours on the same catalog.
