# The MAS + session lifecycle: architecture, and why the "direct-pipeline rewrite" is off

This documents the multi-agent-system (MAS) control flow of the Python fuzzer, captured
from the code and a real event trace, as the prerequisite the complexity report
(`doc/complexity-reduction-report.md` §3.1) asked for before touching it — and records the
decision that came out of doing so.

## Agent tiers and lifecycle

Everything is an `Agent` (`fusil/mas/agent.py`). An agent reacts to event `foo` by defining
`on_foo(self, *args)`; `self.send("foo", ...)` broadcasts to every subscribed agent. Three
tiers with different lifetimes:

- **`ApplicationAgent`** (MTA, Univers, the Application, logger): live for the whole run.
- **`ProjectAgent`** (Project, AggressivityAgent, the directory, PythonSource, the process +
  watchers): (re)activated per session.
- **`SessionAgent`** (Session, SessionDirectory): created per session; note `SessionAgent`
  registers on **both** `project.agents` and `session.agents`, so the Univers loop (which
  iterates `project.agents`) drives session agents too.

`activate()` → `init()`; `deactivate()` → `deinit()`; `destroy()` at teardown. Subscriptions
are auto-derived by scanning for `on_*` methods.

## The event graph (live tree)

Every live event and its handler(s). All 12 have handlers — there are **no dead sends** in
the live tree (Phase 1, PR #155, removed the dead ones):

| Event | Handler(s) | Fan-out |
| --- | --- | --- |
| `session_start` | WatchProcess, PythonSource, CreateProcess | 1→3 |
| `session_stop` | Session, FileWatch | 1→2 |
| `session_done` | AggressivityAgent, Project | 1→2 |
| `univers_stop` | Univers, Project | 1→2 |
| `session_rename` | SessionDirectory | 1→1 |
| `python_source` | Fuzzer | 1→1 |
| `process_create` | WatchProcess | 1→1 |
| `process_stdout` | WatchStdout | 1→1 |
| `process_exit` | WatchStdout | 1→1 |
| `project_session_destroy` | Project | 1→1 |
| `project_stop` | Project | 1→1 |
| `application_interrupt` | Application | 1→1 |

Captured trace of a real 2-session run (`--modules _json --sessions 2 --fast`), via the
opt-in `MTA.trace` hook — this is the behavioural baseline any rewrite must reproduce:

```
per session:  session_start → session_rename → python_source → process_stdout
              → process_create → process_exit → session_stop → session_done
              → project_session_destroy
end of run:   univers_stop
```

## The execution model — and the two things the report's §3.1 missed

`Univers.execute(project)` is a polling loop:

```
while True:
    for agent in project.agents:      # MTA registered first
        agent.readMailbox()           # drain mailbox → on_* handlers
        agent.live()                  # per-step hook
    if is_done: return
    sleep(step_sleep)                 # --fast/--slow set this
```

`MTA.live()` (first each step) drains the send queue into subscriber mailboxes; each agent's
`readMailbox()` then runs its `on_*` handlers. So a `send()` is delivered ~one step later —
**delivery is deferred, not synchronous.**

§3.1 framed this as "a deterministic linear pipeline run through generic pub/sub + a polling
loop," implying it could collapse to direct method calls. Doing the homework shows two
reasons that is **wrong**, and both are load-bearing:

1. **The step loop is the child-process monitor.** `live()` is not idle polling of a message
   queue — `WatchProcess.live()` calls `self.process().poll()`, `WatchStdout`/`FileWatch.live()`
   read the child's output, `CpuProbe.live()` samples CPU, and `Session.live()`/`Project.live()`
   recompute the score and enforce the timeout. The child runs **asynchronously**; the loop is
   how fusil watches it (exit / output / timeout / CPU) every `step_sleep`. Sequential direct
   calls cannot express "run the child and monitor it concurrently" — you would have to
   re-implement an equivalent poll loop.

2. **Deferred delivery is a safety mechanism, not incidental.** The end-of-session cascade
   (`session_stop → session_done → project_session_destroy → destroySession()+createSession()`)
   **mutates `project.agents`** (deactivates the finished session's agents, appends the next
   session's). Because delivery is deferred to controlled step boundaries — and
   `destroySession()` explicitly clears mailboxes and `mta.clear()` — this mutation never
   happens *while the Univers loop is iterating `project.agents`*. Make `send()` synchronous
   and that cascade fires mid-iteration from inside `Session.live()`, mutating the list being
   iterated (re-entrancy → `RuntimeError`/skipped agents). The queue's safe-point semantics
   are what prevent this.

## Decision: do not do the wholesale MAS → direct-pipeline rewrite

The premise of §3.1 (a) — "collapse the bus to direct method calls" — does not hold: the
polling loop is essential to process monitoring, and the deferred dispatch is a re-entrancy
guard for the per-session teardown/rebuild. A wholesale rip-out is **high risk for low or
negative gain**: it would re-introduce, by hand, the very poll loop and safe-point semantics
it deletes. The unit tests pin handler *logic* but not wiring/timing, and the trace covers
only the happy path, so the rewrite is also under-verified by construction.

What remains genuinely worth doing (smaller, self-contained, lower risk) — none of which
require touching the poll loop or the dispatch semantics:

- **`AggressivityAgent`** (§3.2, MED/MED): **DONE** — the adaptive-aggressivity state machine
  and its `aggressivity.dat` graph were dead weight (nothing reads the value to scale fuzzing;
  it only appeared in log/summary strings), so it was collapsed to a plain scalar on `Project`.
- **Teardown robustness**: **DONE** — `AgentList.__del__ → clear → unregister` raised
  `'NoneType' has no attribute 'unregisterAgent'` at interpreter shutdown (the application
  weakref is already dead); `ApplicationAgent.unregister` now None-guards it, matching
  `ProjectAgent.unregister`.
- **Scoring** (§3.1 c): the report suggested collapsing it to a boolean, but investigation
  shows `getScore` is **not** dead generality — `WatchProcess` (signal), `WatchStdout`/`FileWatch`
  (crash text), `CpuProbe`, and `CreateProcess` implement it, and `computeScore`'s sum is the
  actual crash-detection/stop signal. It is load-bearing like the poll loop; **left as-is**.
  (`score_weight`, the genuinely dead part, was already removed in Phase 1.)

The safety net (`tests/test_mas.py`, `tests/test_session_lifecycle.py`,
`tests/test_session_directory.py`) and the `MTA.trace` hook remain useful for any of the
above, and would be the verification basis if a future rewrite is ever revisited.
