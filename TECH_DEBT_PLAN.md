# Fusil technical-debt paydown plan

Status: **APPROVED — in progress** (decisions recorded 2026-06-22). Tracking doc for the
debt paydown across the actively-developed path (`fusil-python-threaded`, `fusil/python/*`,
core `fusil/*`). Grounded in a read-only survey done 2026-06-22.

## Decisions made (2026-06-22)

1. **Orphaned legacy `fusil/*` modules** → move into a new **`fusil/notworking/`** subpackage
   (mirrors `fuzzers/notworking/`). Recoverable, out of the live tree.
2. **Object-mangling feature** → **remove** it (never paid off; not known to have worked).
   Revisit the idea fresh someday if wanted.
3. **JIT** → write a decision memo (`doc/jit-decision-memo.md`) with the concrete
   move-to-lafleur decoupling diff; the directional choice stays with the maintainer. Phase 8
   *execution* is the only thing blocked on input.
4. **ruff config** → propose a default `[tool.ruff]`; maintainer evaluates later. Land it in
   Phase 4.
5. **This plan** → commit as a tracking doc. **CI** → introduce at the *end* (after the tree
   is test-green and lint-clean) so its first run is green; minimal GH Actions (install +
   `unittest`, then `ruff check`).
6. **Memory cap / ASan** → the cap was disabled because ASan reserves a ~20 TB virtual
   address space and `RLIMIT_AS` kills it. Re-enable the cap but make it **ASan-safe**:
   auto-detect an ASan target (and add `--no-memory-limit`) and skip *only* `RLIMIT_AS` then,
   relying on the external cgroup cap (the fleet's systemd `MemoryMax`). Non-ASan runs get the
   `RLIMIT_AS` safety back. Keep core-dump / nproc / nice limits in all cases.
7. **`tools/fuzz_loop.sh`** → experiment subsumed by the fleet → move to `notworking`.
8. **`ruff format`** → record the format commit SHA in `.git-blame-ignore-revs` so
   `git blame` skips it (and document `git config blame.ignoreRevsFile .git-blame-ignore-revs`).
9. **Logging** → fusil's logger is *not* plain prints: `ApplicationLogger` is dual-sink
   (terse stdout + verbose `fusil.log`) and prefixes every line with
   `[nb_success][session][step][agent]` context (`application_logger.py:formatMessage`).
   Conversions must route through the agent logger (`self.error/info/...`) to preserve that;
   module-level code with no agent uses a module `logging.getLogger(__name__)` → stderr.

### Process for this sweep (interim decisions)

- One **umbrella GitHub issue** anchors the effort; each coherent unit is a **branch → PR →
  self-merge (`--merge --delete-branch`)** referencing it (skipping a separate issue per tiny
  PR to keep an unattended run moving).
- The suite is kept green at every merge.
- Any further fork in the road during implementation: make a sensible **interim decision**,
  record it in the "Interim decisions log" at the bottom, and proceed.

---

## Baseline (what the survey found)

- `fusil/python/` is 14,312 LOC — the real codebase. Core `fusil/*.py` ≈ 4,800 LOC.
- `fuzzers/`: 16 scripts; **only `fusil-python-threaded` is a console-script entry point**.
  15 others are legacy; `fuzzers/notworking/` already holds 8.
- Tests: 19 files, ~229 cases, but ~19% of modules; **all core `fusil/*` and `mas/`,
  `process/` are untested**. `test_oom_dedup.py` is the model for runtime-free unit tests.
- Two **safety regressions** live in the tree (disabled `if 0:` blocks from an Oct-2025 "Temp
  fix" series) — see Phase 0.
- One test **errors on import** today (`test_write_jit_code.py` imports the removed
  `fusil.python.jit.ast_mutator`), so the suite isn't clean.

---

## Phase 0 — Stabilize the baseline  (done first; small, high value)

1. **Un-break the suite.** Guard the `ast_mutator` import in `test_write_jit_code.py:13` and
   skip the tests that need it (`unittest.skipUnless`), so `unittest discover` is clean. Full
   disposition in Phase 8.
2. **Restore the disabled safety controls** (`fusil/process/prepare.py`):
   - `:71-72` `if 0: limitResources(...)` → restore. Make `limitMemory` **ASan-safe**: skip
     `RLIMIT_AS` when the target is an ASan build (auto-detected) or `--no-memory-limit` is
     set; keep core-dump / nproc / nice. Add the `--no-memory-limit` option + a
     `config.no_memory_limit`/ASan-detect flag computed once at startup.
   - `:59-60` `if 0:` → restore the `if not access(program, X_OK):` executable check.
   - Clean the dead imports these left only if they stay unused after restore.
3. **Drop** `print(sys.version)` at `fusil/python/__init__.py:26` (pollutes scraped stdout).
4. **Characterization tests** for the drop/limit wiring + the ASan-skip logic (runtime-free,
   mocked like the oom_dedup tests).

Output: a test-fix PR + a safety-fix PR. Suite green afterward.

---

## Phase 1 — Shrink the surface area  (Task 1)

Move everything that isn't the Python fuzzer out of the live tree.

- 15 legacy **fuzzer scripts** → `fuzzers/notworking/`.
- Legacy-only **modules** → new **`fusil/notworking/`** subpackage: `mangle*.py`,
  `auto_mangle.py`, `dummy_mangle.py`, `incr_mangle*.py`, `x11.py`, `xhost.py`, `c_tools.py`,
  `bits.py`, `fixpng.py`, `zzuf.py`, `network/`, `linux/syslog.py`.
- **Keep** (shared, verified importers): `file_watch.py`, `linux/cpu_load.py`,
  `bytes_generator.py`, `unicode_generator.py`, `write_code.py`.
- **Verify before moving:** `application.py:20` (`xhostCommand` from `fusil.xhost`) is on a
  legacy path; `fixpng.py`↔`bits.py` move together.
- Update `pyproject.toml` discovery + `MANIFEST.in`; keep suite green; smoke-run
  `fusil-python-threaded --only-generate`.

---

## Phase 2 — Code hygiene  (Tasks 2 + 3)

- **Remove object-mangling** (decision 2): `USE_MANGLE_FEATURE` constant + gated branches
  (`write_python_code.py:57,406,769`), commented `--no-mangle` (`__init__.py:166-167`), and
  any now-dead mangle plumbing not already moved in Phase 1.
- **Logging (decision 9):** convert stdout-polluting library `print()`s to the agent logger
  (`write_python_code.py` banners ~29-53 → module logger; `python_source.py:57,75,80` →
  `self.info/error`; `directory.py:32-33,48-49` → logger, drop the `getrusage` dump). Preserve
  the dual-sink + context-prefix behavior — do **not** just swap one print for another.
- **`tools/fuzz_loop.sh`** → `notworking` (decision 7).
- **Commented-out code:** delete the ~18 dead blocks; for the ~34 disabled/ambiguous blocks
  apply **delete-unless-vetoed**, listing them in the PR body.

---

## Phase 3 — Make deep-diving opt-in  (Task 4)

`--deep-dive` (default **off**) + config default; gate the 3 sites
(`write_python_code.py:1311-1342`, `write_h5py_code.py:1691-1700`, the
`_fuzz_generic_object_methods` log msgs). Tests assert off→no deep-dive code, on→present.

---

## Phase 4 — Format + lint  (Task 5)

- Add a proposed `[tool.ruff]` to `pyproject.toml` (line length, target version, rules,
  scoped ignores for the string-building generators).
- `ruff format` → **one isolated PR, no logic changes**; add the merge commit SHA to
  `.git-blame-ignore-revs` and document `blame.ignoreRevsFile`.
- `ruff check --fix` safe rules → triage rest → fix or scoped-ignore. Retire `pyflakes.sh`.

---

## Phase 5 — Optional deps + external review  (Tasks 9 + 6)

- `pip install -e '.[numpy,h5py]'` into the dev venv → run the numpy/h5py tests → fix
  breakage → confirm graceful skip still works absent → update CLAUDE.md.
- Run **code-review-toolkit** over the cleaned `fusil/python/` + core; triage into the backlog.

---

## Phase 6 — Tests  (Task 8)

Tiered, runtime-free where possible: T1 `score`/`tools`/`error`; T2 `python/arg_numbers`
(top), `bytes_generator`, `unicode_generator`, `python/blacklists`; T3 `session_directory`,
`directory`, `python/utils` (light mock); T4 MAS bus, scoring, `application`/`project` (mocks).

---

## Phase 7 — Documentation  (Task 7)

`doc/python-fuzzer.md` (lifecycle/MAS, generation pipeline, OOM/`--oom-seq`/dedup, plugins,
option reference). Refresh `README.rst` to the Python-only focus. Stale top-level docs
(`TODO`, `IDEAS`, `README.windows.txt`) → archive under `doc/legacy/` (interim).

---

## Phase 8 — JIT decision  (Task 10)  ⚠️ blocked on maintainer

Memo: `doc/jit-decision-memo.md` (keep / move-to-lafleur (rec) / spinoff / notworking) with
the concrete decoupling diff. Execution waits on the choice. The broken test is already
skipped (Phase 0); final disposition follows the decision.

---

## Task 11 — Additional items (folded into the phases)

- **CI** (decision 5): GH Actions `unittest` + `ruff check`, added at the end (green on first
  run).
- **`pyproject.toml` audit** (metadata, `requires-python`, extras, wheel builds post-move).
- **Stale helper scripts** `graph.sh`/`lsall.sh`/`pyflakes.sh` — fix/document/remove.
- **Typing noise** from dynamic `FusilConfig` attrs — consider a typed config / `__getattr__`.
- **`CONTRIBUTING.md`** dev-setup (venv, ptrace, extras, test commands).

---

## Suggested execution order

`0 Stabilize` → `1 Shrink` → `2 Hygiene` → `3 Deep-dive` → `4 Format/lint` → `5 Deps+review`
→ `6 Tests` → `7 Docs` → `8 JIT (blocked)` → CI + extras last.

## Completion status (2026-06-23)

Phases 0–7 + CI/extras are **done and merged**; Phase 8 (JIT) is the only item left, awaiting
the maintainer's direction (`doc/jit-decision-memo.md`). Suite grew 0→308 tests; CI is green
on Python 3.13 + 3.14.

| Phase | PR(s) |
|---|---|
| Plan + umbrella issue | #107, #106 |
| 0 Stabilize (un-break suite; ASan-safe memory cap; exit-code path) | #108, #109 |
| JIT decision memo | #110 |
| 1 Shrink → `notworking/` | #111 |
| 2 Hygiene (remove mangling; logging; dead-code; fuzz_loop) | #112, #113, #114 |
| 3 Deep-dive opt-in | #115 |
| 4 ruff format + check (+ requires-python ≥3.12) | #116, #117 |
| 5 numpy/h5py verify (+ ≥3.13) + code-review backlog | #118, #119 |
| 6 Tests (+77, core/MAS/generators/arg_numbers/blacklists/dirs) | #120, #121 |
| 7 Docs (`doc/python-fuzzer.md`, README, archive) | #122 |
| CI + CONTRIBUTING + script archival | #123 |

Real bugs fixed along the way: disabled `limitResources()` (no memory cap on children),
disabled exec-perm check, `fatalError()` exit-code typo (exited 0), the OOM-dedup segv resolver
running fuzzed code as root (earlier, #105), a blacklist key typo, and a too-low
`requires-python`. Remaining non-blocking backlog lives in `doc/code-review-findings.md`.

## Interim decisions log

- (2026-06-22) Process: umbrella issue + PR-per-unit, self-merged; suite green at each merge.
- (2026-06-22) CI added at the end so its first run is green (decision 5 timing).
- (2026-06-22) Stale top-level docs archived under `doc/legacy/` rather than deleted (Phase 7).
- (2026-06-23) `requires-python` raised to **3.13** (PEP 701 f-strings need 3.12, `types.CapsuleType` needs 3.13); numpy/h5py verified on a normal-CPython 3.14 venv (no wheels for 3.16t).
- (2026-06-23) Object-mangling removed (decision 2); JIT left untouched pending decision 5.
- (2026-06-23) `graph.sh`→`tools/`, `lsall.sh`/`pyflakes.sh`/`fuzz_loop.sh`→`*/notworking/`.
