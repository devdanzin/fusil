# How the Python fuzzer works

This is the developer guide to `fusil-python-threaded` — the actively-developed fuzzer that
finds crashes in CPython, C-extension modules, the Tier-2 JIT, and allocation-failure (OOM)
error paths. It is the one fuzzer in this repo that is maintained and tested; the legacy
fuzzers under `*/notworking/` are out of scope.

For the OOM and JIT subsystems there are dedicated docs — this guide links to them rather
than repeating them: [`oom-fuzzing.md`](oom-fuzzing.md), [`oom-sequences.md`](oom-sequences.md),
[`oom-dedup-plan.md`](oom-dedup-plan.md), and `README_JIT.md` (repo root).

## The big picture

Fusil runs a loop of independent *sessions*. Each session:

1. picks a target module,
2. **generates** a standalone Python script (`source.py`) full of randomized, hostile calls
   into that module,
3. **runs** that script under the target interpreter as a separate child process, and
4. **watches** the child for crash signals (signal, exit code, stdout/stderr patterns).

If a session looks like a crash, its directory is kept (and self-labelled with the crash
signature); otherwise it's deleted. The fuzzer adapts its *aggressivity* based on a per-session
score and stops after enough sessions or successes.

Everything is built on a small multi-agent system (MAS); the generation, execution, and
crash-watching are all agents communicating by messages.

## The MAS substrate (`fusil/mas/`)

The whole framework is agents talking over a message bus. Understand this before touching
control flow.

- An **`Agent`** reacts to an event `foo` by defining `on_foo(self, *args)`. Subscriptions are
  auto-derived by scanning the instance for `on_*` methods (`Agent.getEvents`).
- `self.send("foo", arg1, ...)` broadcasts `foo` to every agent subscribed to it.
- **`MTA`** (`mta.py`) is the bus: `send()` queues a `Message`; its `live()` delivers queued
  messages into each subscriber's `Mailbox` once per step (pruning dead/inactive mailboxes).
- **`Univers`** (`univers.py`) is the main loop: each *step* it calls `readMailbox()` then
  `live()` on every active agent, then sleeps (`--fast`/`--slow` set the sleep).
- **Lifecycle:** `activate()` → `init()`; `deactivate()` → `deinit()`; `destroy()` at teardown.
- **Scoring:** a `ProjectAgent` may implement `getScore()` returning a float in `[-1.0, 1.0]`
  (1 = bug found, 0 = nothing, −1 = input rejected). `Session.computeScore()` weights and sums
  them.

The bus is covered by `tests/test_mas.py`; the scoring helpers by `tests/test_core_logic.py`.

## Application → Project → Session

Three agent tiers with different lifetimes (`fusil/application.py`, `project.py`, `session.py`):

- **`Application`** (`fusil.python.Fuzzer` subclasses it): parses CLI/config, sets up logging
  and the MAS, loads plugins, then runs the project. Application-level agents (MTA, Univers,
  logger, the app) persist for the whole run.
- **`Project`**: runs sessions in a loop until enough successes (`--success`) or sessions
  (`--sessions`), or an interrupt. Owns the aggressivity agent and the run directory (`run-N/`).
- **`Session`**: one fuzzing attempt, with its own directory and `session.log`. The event chain
  is `project_start` → `session_start` → (agents act) → `session_stop` → `session_done` → next
  session or `univers_stop`. At teardown `SessionDirectory.checkKeepDirectory` keeps a *crashing*
  session's dir (else `rmtree`s it); the dir self-labels via `session_rename` parts
  (module / signal / exit code / OOM id …). An optional `application.session_keep_policy` hook
  (set by OOM dedup) can relabel or prune the dir.

A fuzzer is created by subclassing `Application` and overriding `createFuzzerOptions()` (add CLI
options) and `setupProject()` (wire up the agents). See `doc/howto_write_fuzzer.rst`.

## The Python fuzzer subsystem (`fusil/python/`)

Entry point: `fuzzers/fusil-python-threaded` → `fusil.python.Fuzzer`.

- **`Fuzzer`** (`__init__.py`) defines all `--*` options and, in `setupProject()`, wires the
  pipeline: `PythonSource` (generator agent) + `PythonProcess` (a `CreateProcess`) +
  `WatchProcess` / `WatchStdout` (crash-detection probes).
- **`PythonSource`** (`python_source.py`): a `ProjectAgent`. Discovers importable modules
  (`ListAllModules`, filtered by `blacklists.py`), and on each `session_start` picks one module,
  calls `WritePythonCode.generate_fuzzing_script()` to emit `source.py`, then sends
  `python_source` so `PythonProcess` runs it under the target interpreter.
- **`WritePythonCode`** (`write_python_code.py`, the largest/most important file): generates the
  test script — imports the target, then emits randomized function calls, class instantiations,
  method calls, objects, and thread/async wrappers. Arguments come from **`ArgumentGenerator`**
  (`argument_generator.py`); hostile inputs come from `tricky_weird.py` and `samples/` (weird
  classes, tricky typing, tricky numpy, mangled objects). Argument *counts* come from
  `arg_numbers.py` (tested in `tests/python/test_arg_numbers.py`).

### Crash detection

The crash signal is largely **textual** plus process state. `WatchProcess` scores by exit
signal/code; `WatchStdout` (`process/stdout.py`) matches the child's stdout/stderr against
`words`/regexes — `segmentation fault`, `Fatal Python error`, `AddressSanitizer`,
`SystemError`, etc. — and `kill_words` that abort a session early. Because detection scrapes
the child's stdout, the fuzzer's own diagnostics must go through the logger / stderr, not bare
prints (see `fusil/application_logger.py`).

### Deep diving (`--deep-dive`, off by default)

After a method call, the generator can recursively fuzz the call's *return value*
(`generation_depth+1`, up to `MAX_FUZZ_GENERATION_DEPTH`). This is multiplicative and has not
historically paid off, so it is opt-in via `--deep-dive`.

## OOM (allocation-failure) fuzzing — `--oom-fuzz`

Drives allocation-failure error paths to crash CPython / C-extensions. `WritePythonCode` emits
an OOM harness: `faulthandler.enable()`, a guarded `from _testcapi import set_nomemory,
remove_mem_hooks`, and an `oom_call(label, func, *args)` wrapper that sweeps
`set_nomemory(start, 0)` over `range(0, --oom-max-start)` per call. Each call prints an
`[OOM] <label>` marker so the crashing allocation is pinpointable on replay; `MemoryError` is
swallowed (the boring outcome) while `SystemError`/segv/abort are surfaced. **Phase 2** also
sweeps class constructors + methods (`--oom-classes` / `--oom-methods`). Stateful **sequences**
(`--oom-seq`) run several calls under one bounded failure window so a failure in one call can
corrupt state a later call trips over. In-loop **dedup** (`--oom-dedup-catalog`) classifies and
optionally prunes the ~96%-duplicate crashes as they happen.

Full details: [`oom-fuzzing.md`](oom-fuzzing.md), [`oom-sequences.md`](oom-sequences.md),
[`oom-dedup-plan.md`](oom-dedup-plan.md).

## JIT fuzzing — `--jit-fuzz`

`WriteJITCode` (`jit/write_jit_code.py`) generates code designed to stress the Tier-2 JIT,
dispatching on `--jit-mode` (`synthesize` / `variational` / `legacy` / `all`). The authoritative
design doc is `README_JIT.md` (repo root); the keep/move/spin-off decision is in
[`jit-decision-memo.md`](jit-decision-memo.md).

## Plugins (`fusil/plugin_manager.py`)

Plugins extend the Python fuzzer without modifying core. They are discovered via the
`fusil.plugins` entry-point group; each entry point is a `register(manager)` callable invoked at
`Application` startup. Through `PluginManager` a plugin can register CLI options, argument
generators, definitions/boilerplate, scenarios, whole fuzzing modes, and `startup`/`shutdown`
hooks. The cereggii support was extracted into such a plugin — use it as the reference example.

## Safety model

Fuzzed code is hostile and runs arbitrary calls, so the child process is **dropped to an
unprivileged `fusil` user** before executing `source.py` (`process/prepare.py`); a failed drop
aborts the child rather than running as root. `--unsafe`/`--force-unsafe` run as the current
user instead (for quick local runs). Resource limits (`process/prepare.py:limitResources`) cap
the child's memory/cpu/process count; the `RLIMIT_AS` memory cap is automatically skipped for
AddressSanitizer targets (whose huge address-space reservation is incompatible with it) and via
`--no-memory-limit`. **Never** point `--filenames` at real files — fuzzed calls may truncate or
chmod them.

## Running it

```bash
# From a checkout (needs python-ptrace; --unsafe runs children as the current user).
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --unsafe [options]

# Useful options (see fusil/python/__init__.py:createFuzzerOptions for the full list):
#   --modules json,sqlite3   limit to specific modules (default: discover all)
#   --only-c                 only C-extension modules
#   --sessions N             stop after N sessions
#   --only-generate          write source.py without executing it
#   --deep-dive              recursively fuzz method return values (off by default)
#   --jit-fuzz               enable JIT-stressing code generation
#   --oom-fuzz / --oom-seq   OOM (allocation-failure) injection
#   --oom-dedup-catalog F    in-loop crash dedup/labeling vs a known-sites snapshot
#   --no-memory-limit        don't apply RLIMIT_AS (implied for ASan targets)
```

## Where to look

| Concern | File |
|---|---|
| CLI options + project wiring | `fusil/python/__init__.py` |
| Module discovery / session driver | `fusil/python/python_source.py` |
| Script generation | `fusil/python/write_python_code.py` |
| Argument values / counts | `fusil/python/argument_generator.py`, `arg_numbers.py` |
| Hostile inputs | `fusil/python/tricky_weird.py`, `samples/` |
| OOM dedup engine | `fusil/python/oom_dedup.py` |
| JIT generation | `fusil/python/jit/` |
| Crash probes | `fusil/process/watch.py`, `process/stdout.py` |
| Child setup / privilege drop / limits | `fusil/process/prepare.py`, `create.py`, `tools.py` |
| MAS substrate | `fusil/mas/` |
| Run/session dirs + keep/prune | `fusil/project.py`, `session.py`, `session_directory.py` |
