# Fusil complexity-reduction report

*Analysis date: 2026-06-30. Scope: the live `fusil/` tree (≈15.5k LOC), with a focus on
the actively-developed Python fuzzing path. Read-only analysis — no code changed by this
report. Every claim below was spot-verified against the source; file:line citations are
current as of this date.*

## TL;DR

Fusil carries three kinds of avoidable complexity:

1. **Clearly-dead code** still in the live tree (X11 support, an orphaned module, dead
   config switches, dead MAS events). ~250 LOC, low risk to remove.
2. **Two latent bugs** hiding in the config layer (the ptrace debugger and numpy support
   are both silently off-by-default in the common case). Small fixes, real behavior impact.
3. **Structural over-generality** inherited from Victor Stinner's original framework: a
   general multi-agent pub/sub bus + adaptive scoring running what is, in practice, a
   deterministic linear pipeline; and a 4.6k-LOC h5py carve-out that is ~30% of the live
   tree.

The recommended order is: land the quick wins + bug fixes first (cheap, safe, immediately
reduce surface), then decide on the larger structural questions (h5py plug-in-ization; MAS
simplification) which trade real risk for real payoff.

---

## 1. Clearly-dead code (quick wins)

### 1.1 X11 / X support — fully dead (~60 LOC, LOW/LOW)

X11 support is live (not under `notworking/`) but **unreachable**. The only function that
would enable it, `CreateProcess.setupX11()` (`fusil/process/create.py:322`), has **zero
callers** — confirmed by grep across the whole live tree. Everything downstream is therefore
permanently inert:

- `fusil/xhost.py` — entire 14-LOC file (`xhostCommand()`).
- `fusil/application.py` — `from fusil.xhost import xhostCommand` (26), `self._setup_x11 =
  False` (276, never set True), `initX11()`/`deinitX11()`/`_xhost()` (560-584), and the
  unconditional `self.deinitX11()` in `exit()` (471, always a no-op).
- `fusil/process/create.py` — `self.use_x11 = False` (65) + dead `setupX11()` (322).
- `fusil/process/env.py` — `copyX11()` (205), only called from the dead `setupX11()`.
- `fusil/process/replay_python.py` — `if process.use_x11` branches (183, 201-203), always False.
- `fusil/config.py` — `fusil_xhost_program` default + getter.

**Recommendation:** delete in one mechanical sweep. The only subtlety is the unconditional
`deinitX11()` call in `Application.exit()` — drop it with the rest. This is the cleanest
single removal available.

### 1.2 `cmd_help_parser.py` — orphaned (188 LOC, LOW/LOW)

`fusil/cmd_help_parser.py` is imported by **no** live or `notworking/` module. Its only
references are `doc/code-review-findings.md` and a stale doctest (`tests/cmd_help_parser.rst`).
**Recommendation:** delete the module + its doctest.

### 1.3 Dead config switches (LOW/LOW)

- **`process_use_cpu_probe`** (`config.py:22,89`) is set into `self.process_use_cpu_probe`
  but **never read** — `CpuProbe` is created unconditionally in `process/watch.py:23`. The
  knob has no effect.
- **`fusil_slow_calm_load` / `fusil_slow_calm_sleep`** (`config.py:19-20,78-83`) are read into
  attributes that have **zero consumers**. (The default `--slow` mode sets `system_calm =
  None`; see §3.3.)

**Recommendation:** remove these defaults + their getters.

### 1.4 Dead MAS events and handlers (LOW/LOW–MED)

Several events are broadcast but have **no live handler** (the handlers live only in
`notworking/`), and one handler has no live sender:

| Symbol | Sent at | Status |
| --- | --- | --- |
| `aggressivity_value` | `aggressivity.py:47` | no live `on_aggressivity_value` — the adaptive feedback loop is severed |
| `process_pid` | `create.py:128` | no live `on_process_pid` |
| `project_start` | `project.py:168` | no live `on_project_start` |
| `session_success` | `session.py:116` | no live `on_session_success` |
| `on_application_error` | `application.py:539` (handler) | no live sender of `application_error` |

**Recommendation:** remove the dead sends/handler. Note `aggressivity_value` ties into §3.2.

### 1.5 JIT leftovers — cosmetic only (LOW/LOW)

The JIT subsystem is gone (PR #140). Remaining references are comments only:
`python/__init__.py:214-217`, `write_python_code.py` ("Standard (non-JIT) function call"),
`samples/weird_classes.py:166` ("attack the JIT optimizer"). **Recommendation:** scrub the
stale comments opportunistically; no functional change.

---

## 2. Latent bugs found during the sweep (fix regardless of complexity)

These are not style issues — they change runtime behavior and are almost certainly unintended.

### 2.1 The ptrace debugger is off by default (config.py:110)

```python
self.debugger_use_debugger = self.getbool(
    "debugger", "debugger_use_debugger", DEFAULTS["debugger_trace_forks"]   # <-- wrong default key
)
```

The fallback default is `DEFAULTS["debugger_trace_forks"]` (**False**) instead of
`DEFAULTS["debugger_use_debugger"]` (**True**). So with no `fusil.conf` present (the normal
case), `debugger_use_debugger` resolves to **False**, and `debugger.py:46` gates the whole
ptrace debugger on it. A copy-paste error that silently disables a core feature. **Fix:** use
the correct default key. (Worth checking whether crash triage has been quietly running without
the debugger.)

### 2.2 numpy argument support silently requires h5py (argument_generator.py:189)

```python
if not self.options.no_numpy and use_numpy and H5PyArgumentGenerator:
    ...
    self.simple_argument_generators += (self.genTrickyNumpy,) * 50
```

The numpy generators (`genTrickyNumpy`) are gated on `H5PyArgumentGenerator` being truthy —
i.e. on **h5py** importing successfully. Two independent optional dependencies are entangled:
install numpy without h5py and the numpy tricky-value generators silently never activate.
**Fix:** gate numpy on numpy and h5py on h5py (split the predicate).

---

## 3. Structural over-generality (the Victor-era framework)

These are the "early days produced a complex piece of software" items. They are real
functionality, not dead code — so simplifying them trades risk for payoff. Presented
largest-payoff-first with an honest risk read.

### 3.1 The MAS pub/sub bus runs a linear pipeline (≈400 LOC core, HIGH/HIGH)

`fusil/mas/` (agent.py 179, mta.py 59, mailbox.py 42, univers.py 40, agent_list.py 40, +
small files) implements a generic multi-agent system: agents register `on_<event>` handlers,
`MTA` queues `Message` objects, per-agent `Mailbox`es are drained each step by `Univers`, and
`getScore()`/`score_weight` aggregate a session score.

The reality of the Python fuzzer:

- **No competing agents.** Each role (source, process, watchers, directory, aggressivity…) is
  a singleton in a fixed pipeline. There is no plurality the bus exists to mediate.
- **Fan-out is trivial.** Of ~16 event types, only `session_start` broadcasts to >2 handlers
  (4: aggressivity, python_source, watch, create); `session_done`/`session_stop` reach 2
  each; **every other event is point-to-point (1→1)**. A deterministic call graph is being
  run through generic pub/sub + a polling `live()` loop.
- **Scoring generality is unused.** Only 4 `getScore()` implementations exist; the dominant
  real signal is textual crash detection in `WatchStdout`. `score_weight` is **always 1.0**
  (set once in `project_agent.py:17`, never reassigned), yet `Session.computeScore`
  (session.py:46-70) calls `normalizeScore` three times per agent for an effectively
  pass-through value.

**Assessment:** this is the single largest *conceptual* simplification — collapsing the bus
to direct method calls and the scoring to a boolean "did a watcher detect a crash" would make
the control flow legible. But **every control-flow path runs through it**, including the
session keep/drop logic that produces crash dirs, so the risk is high and the test coverage of
the MAS itself is thin. **Recommendation:** do *not* rip it out wholesale. Instead, (a) delete
the dead events/scoring generality (§1.4, the `score_weight` triple-normalize), and (b) treat a
full MAS→pipeline rewrite as a separate, well-tested project only if maintenance pain justifies
it. Document the actual event graph first (a one-page diagram) so the indirection is at least
navigable.

### 3.2 `AggressivityAgent` adaptive loop — broadcasts into the void (152 LOC, MED/MED)

`fusil/aggressivity.py` maintains a feedback-control value (`update`/`updateState`/
`writeGraphData`) and broadcasts `aggressivity_value` on every `session_start` — which, per
§1.4, **nothing consumes** in the Python path. Its only live effect is `setValue` from
`--aggressivity` and a line in the project summary (`project.py:282`). The adaptive control
machinery is dead weight. **Recommendation:** collapse to a plain scalar option (the
configured aggressivity) and drop the feedback loop + graph output. MED risk because the
summary string and a few call sites touch it.

### 3.3 `SystemCalm` + `linux/cpu_load` — off in the default config (≈213 LOC, MED/MED)

`SystemCalm` (`system_calm.py`, 50 LOC) is instantiated **only** in `project.py`'s "medium"
mode (`not fast and not slow`). The default is `--slow=True` (`application.py:127`), and the
slow branch sets `system_calm = None` after printing the misleading warning *"SystemCalm class
is not available"*. So the load-throttling wait loop and `SystemCpuLoad`/`linux/cpu_load.py`
(163 LOC) are dead in the default configuration. **Recommendation:** either wire it on
deliberately or remove the load-throttling path; at minimum fix the misleading warning.

### 3.4 The h5py subsystem is 30% of the live tree (4,623 LOC, MED/MED)

`fusil/python/h5py/` (`write_h5py_code.py` 2,166 + `h5py_tricky_weird.py` 1,442 +
`h5py_argument_generator.py` 1,018) is a special-case carve-out for **one** third-party
library — fully optional (guarded by `try: import h5py`). It is the largest single complexity
sink in the project and dwarfs the generic fuzzer (`write_python_code.py` is 1,472 LOC). It is
*not* dead (verified working with h5py installed), but it sits in the core tree.

**Recommendation:** extract it into a **plugin**, mirroring the cereggii extraction (fusil
already has a plugin system: `fusil.plugins` entry points, with argument-generator/definition/
scenario hooks). This would (a) remove ~30% of the core LOC, (b) make the generic fuzzer the
clear center of gravity, and (c) turn h5py into the reference example of a non-trivial plugin.
MED effort (the h5py writer reaches into `self.parent` heavily, so the plugin boundary needs
the parent's `write`/`indented`/`arg_generator` surface exposed cleanly). This is the
highest-LOC, moderate-risk win.

### 3.5 Config-file round-trip machinery (≈150 LOC, MED/MED)

`config.py` (392 LOC) carries `ConfigParserWithHelp` + `OptionGroupWithSections` +
`OptionParserWithSections` + `optparse_to_configparser()` + `write_sample_config()` to support
`--write-config`/`--use-config` (generate and read a commented `fusil.conf`). It also
hard-codes ~30 Python-fuzzer attribute defaults (`config.py:116-141`) that **duplicate** the
optparse defaults in `python/__init__.py` — two sources of truth for the same options (and the
source of bug §2.1). **Recommendation:** if config files aren't used in practice, remove the
round-trip subsystem and collapse to optparse defaults as the single source of truth. MED risk
(need to confirm no workflow depends on `fusil.conf`).

### 3.6 Privilege-drop / `fusil`-user model (spread, HIGH/HIGH)

`unsafe.py` + `process/prepare.py:changeUserGroup()` (setgid/setuid/setgroups) + the
`process_user="fusil"` config + `safetyWarning()` flow (`application.py:367-415`) implement the
dedicated-user sandboxing model, mostly bypassed by `--unsafe` in dev. It is real safety
functionality, but heavy and never exercised on the dev path. **Recommendation:** leave as-is
unless the project decides to standardize on container-based isolation; flag only as a known
large surface. Do **not** treat as a quick win.

### 3.7 Fine-grained class-per-concept style (minor)

`score.py` (16 LOC wrapping trivial math), `agent_id.py` (14 LOC to hand out an incrementing
int), `agent_list.py` (wraps a list), and the `Agent → ProjectAgent → SessionAgent` +
`Directory` mixin hierarchies illustrate the framework's "a class for every concept" style.
Individually minor; collectively they raise the cognitive cost of a linear pipeline. Fold
opportunistically when touching adjacent code; not worth a dedicated pass.

---

## 4. Cross-cutting note: the lafleur ↔ fusil soft-coupling

`argument_generator.py:40-66` does `try: from lafleur.mutator import (…10 genStateful*/
genLying* functions…)` with a `HAS_MUTATOR` fallback, wiring them into the object-generator
dispatch. This is a clean optional integration, but it means fusil now optionally imports
argument generators **from its own spinoff**. Worth documenting explicitly (the two repos
point at each other) so the dependency direction is intentional, not accidental. Notably, the
"stateful/lying" generators lafleur contributes are exactly the bug-object family this report's
companion (`reproducer-techniques-for-fusil.md`) recommends growing — see that doc.

---

## 5. Recommended roadmap

**Phase 1 — quick wins + bug fixes (one or two small PRs, low risk):**
1. Fix the two latent bugs (§2.1 debugger default, §2.2 numpy/h5py predicate).
2. Delete X11 (§1.1) and `cmd_help_parser.py` (§1.2).
3. Remove dead config switches (§1.3) and dead MAS events/handler (§1.4).
4. Remove the always-1.0 `score_weight` generality + triple-normalize (§3.1.b).
5. Scrub JIT comment leftovers (§1.5); fix the misleading SystemCalm warning (§3.3).

Net: ~450 LOC removed, two real bugs fixed, no behavior change to the fuzzing path (modulo the
two fixes, which *restore* intended behavior).

**Phase 2 — the big structural decision (separate, well-tested):**
6. Plugin-ize h5py (§3.4) — the largest LOC win. Decide first whether h5py coverage is a
   current priority; if not, this is the clear next move.
7. Collapse `AggressivityAgent` to a scalar (§3.2) and resolve the `SystemCalm` path (§3.3).

**Phase 3 — only if maintenance pain justifies it (high risk):**
8. Config round-trip removal (§3.5), single-source-of-truth defaults.
9. MAS → direct-pipeline rewrite (§3.1) — document the event graph first; treat as its own
   project with new tests for the keep/drop crash-dir logic before touching it.

The golden-output test (`tests/python/test_golden_output.py`) and the OOM/feat/h5py
before-after harnesses guard the *generation* path; none of the above touches generation
except the h5py plugin move (which the h5py harness covers). The MAS/lifecycle work would need
new tests around session keep/drop *before* starting — that coverage gap is itself a finding.
