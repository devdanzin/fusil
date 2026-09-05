# Handoff — fusil `--tsan` feature set (for Codex)

Written 2026-07-18. Purpose: give an incoming agent the **off-repo** context around the
ThreadSanitizer (`--tsan`) data-race fuzzing feature — builds, venvs, the sibling catalog,
fleet infra, campaign state, and gotchas that are **not** discoverable from the fusil repo
alone. Complements CLAUDE.md's in-repo `--tsan` section — read that first for the code-side
overview; this file is the surrounding environment. Uncommitted; delete when done.

Repo states at handoff: **fusil** `main`@`45061ea`; sibling **cpython-tsan-findings**
`main`@`819e740`.

---

## 1. What `--tsan` is, and where it lives in this repo

`--tsan` turns fusil into a free-threading **data-race** fuzzer (vs the OOM/crash mode). Instead
of the single-threaded OOM sweep, it emits a **concurrency-stress region**: a few SHARED objects
hammered by many worker threads (barrier-released), so concurrent C-level access to one object's
state trips a TSan race.

In-repo touch points:
- **`fusil/python/write_python_code.py` → `_write_tsan_stress_region()`** — the emitter.
  The op-mix is ops **(a)–(i)**; (h) shared-iterator races and (i) read-while-mutate are the
  newest (PR #211) and are what just found the bytes-iterator race. Emitter is **gated behind
  `--tsan`** — non-`--tsan` generated output (and its goldens) are unchanged, so don't expect
  golden regen for tsan-only edits.
- **`fusil/python/tsan_dedup.py`** — the race-report **parser + dedup engine + `Suppressor`**.
  `parse_report(stdout)` → `{signature, sites, framework, kind}`, where `signature` is the
  sorted `"file:func | file:func"` site pair. **This is a cross-repo contract** (see §4).
- **`fusil/python/__init__.py`** — the `--tsan*` CLI options (`--tsan-threads`,
  `--tsan-iterations`, `--tsan-shared-objects`, `--tsan-suppressions`, `--tsan-dedup-catalog`,
  `--tsan-dedup-keep`, `--tsan-dedup-prune`). `setupProject()` makes `--tsan` imply `--no-numpy`.
- **`doc/tsan-mode-plan.md`** — the design doc + phase history (Phase 3.1 = the new iterator ops).
- **Tests**: `tests/python/test_tsan_generation.py` (emitter markers + "emitted script compiles")
  and `tests/python/test_tsan_dedup.py` (parser/signature/suppression, pure-Python).
- **`fleet/`** — systemd-based multi-instance runner (`fleet up/down/status/report/finds`,
  `fleet check` is `--tsan`-aware). README documents the tsan fleet config.

fusil applies the whole TSan **env recipe internally** when `--tsan` is passed (see §3) — you
don't set it by hand for a fuzzing run, only for manual repros.

---

## 2. Off-repo: builds & venvs

**CPython build matrix** — `~/projects/python_build_matrix/builds/<name>/python`. Built via
`cd ~/projects/python_build_matrix && JOBS=$(nproc) bash build_all.sh <name>`. clang-21 at
`/usr/local/bin`. Builds relevant to TSan work:
- `debug-ft-nojit-tsan` — **the TSan target** (CPython 3.16.0a0, `--disable-gil
  --with-thread-sanitizer`). What the fleets run against.
- `release-ft-nojit`, `release-ft-nojit-asan`, `debug-ft-nojit-asan`, `debug-ft-nojit` — used
  for crash-repro / severity confirmation of races (ASan gives UAF/OOB backtraces).
- `release-ft-nojit-o0` — a `-O0` **NDEBUG** FT build made for the #153928 OOB-char demo
  (`-O2` register-caches the iterator cursor, hiding the OOB window; NDEBUG turns the UAF into a
  real segfault). Handy for demonstrating iterator OOB reads.

**Venvs** (the ones that actually exist and work):
- `~/venvs/fusil_np_verify/bin/python` — **CPython 3.14, GIL**, has `python-ptrace`. Use for
  running the test suite and non-FT verification. The `oom_dedup`/`tsan_dedup` tests are
  pure-Python and run here fine.
- `~/venvs/matrix_venvs/fusil_debug-ft-nojit_venv/bin/python` — **CPython 3.16 free-threaded**,
  has `python-ptrace` + fusil. This is the **fleet runner** venv (a FT runner is required because
  `PYTHON_GIL=0` is inherited by the runner too).
- **`~/venvs/fusil_venv` is GONE** — don't use it.

`python-ptrace` is a hard import-time dependency of `fusil.application`, so the runtime stack
only imports under a venv that has it (the two above). Pure-engine tests (`tsan_dedup`,
`oom_dedup`, generation) don't need the runtime stack.

---

## 3. Off-repo: the TSan env recipe (needed for MANUAL repros)

fusil sets these itself under `--tsan`; you only need them to reproduce a race by hand against
`debug-ft-nojit-tsan`:

```sh
setarch -R bash -c "ulimit -v unlimited; PYTHON_GIL=0 \
  TSAN_OPTIONS='halt_on_error=1:symbolize=1:exitcode=66:history_size=4' \
  DEBUGINFOD_URLS= \
  <build>/python repro.py"
```
- **`setarch -R`** (ASLR off) and **`ulimit -v unlimited`** (RLIMIT_AS) are mandatory for TSan.
- **`DEBUGINFOD_URLS=`** is load-bearing: without it `llvm-symbolizer` hangs for ~120 s on the
  blackholed Ubuntu debuginfod server (any local ASan/TSan symbolizer hang = this). gdb is immune.
- exit **66** = a data race was detected. `--no-numpy` (numpy isn't FT-clean; the plugin injects
  `import numpy` which the tsan build can't import).

---

## 4. Off-repo: the sibling catalog `cpython-tsan-findings` (CRITICAL LOCKSTEP)

`~/projects/cpython-tsan-findings` (published: github.com/devdanzin/cpython-tsan-findings) is the
triage/reporting home for the races. It is **coupled to fusil**:

- `scripts/ingest.py` **imports fusil's `tsan_dedup.py`** via
  `FUSIL_TSAN_DEDUP=/home/danzin/projects/fusil/fusil/python/tsan_dedup.py`. So **the signature
  format that `tsan_dedup.parse_report` emits is a hard contract** — if you change how signatures
  are built (site pair format, framework filtering, the ACCESS/stanza regexes), you change what
  matches `catalog/known_races.tsv` and can silently break dedupe across the whole catalog. There
  is a matching-order + normalization subtlety (`gen_known_races._normalize` sorts the pair);
  keep them in sync.
- `catalog/known_races.tsv` (119 sigs / 34 races) = the dedupe snapshot fusil reads with
  `--tsan-dedup-catalog`. Regenerated from `reports/*/meta.json` by `scripts/gen_known_races.py`.
- `catalog/suppressions.txt` = TSan-style suppressions consumed by `tsan_dedup.Suppressor`
  (framework noise, glibc/OpenSSL false positives, subinterpreter machinery). Post-hoc regex over
  the signature.
- Triage loop: `FUSIL_TSAN_DEDUP=… python3 scripts/ingest.py '<fleet>/inst-*/python*/*'` buckets
  crash dirs by signature; new signatures get a `reports/TSAN-NNNN-*/meta.json` (+ optional
  `repro.py` / `backtrace.txt`), then `gen_known_races.py` regenerates the TSV. Catalog convention:
  **commit straight to `main`** (no PR), then push.

**If Codex edits `tsan_dedup.py`, re-run the catalog's `test_tsan_dedup.py` AND re-ingest a fleet
to confirm known races still match.** The parser has been bug-fixed twice for exactly this class
of regression (PR #207: the `ACCESS` regex missed "Previous atomic write" stanzas → fabricated
`A | A` signatures; framework-FP over-matching).

---

## 5. Off-repo: fleet infra + campaign state

- Fleets run at **`/home/fusil/runs/fusil-tsan_fleet_NN/inst-*/python*/*`** (systemd, as the
  `fusil` user). **Ingest glob must be `inst-*/python*/*`** — a restarted instance gets a fresh
  `python-2`/`python-3` project dir; `inst-*/python/*` silently ingests only the pre-restart run.
- Campaign so far: fleets **01–06 triaged**, all converged (each ingests 0 new signatures after
  its faces are folded). **37 races cataloged (TSAN-0001..0037)**; umbrella issue
  **python/cpython#153852** holds 15 findings.
- **PR #211 (the new iterator ops) just paid off**: fleet-06 (first run with them) surfaced
  **TSAN-0037 = the `bytes` iterator race** (`striter_next` non-atomic `it_index` + `it_seq`
  double-DECREF), 196/223 dirs — the bytes analog of **python/cpython#153928** (the `str`
  iterator, johng's issue, which we reproduced + commented on). We just commented on #153928 with
  the bytes `it_seq` UAF + the "whole sequence-iterator family" point. The `list`/`tuple`/`range`
  iterators share the exact shape and haven't been fleet-caught yet — likely fleet-07 material.
- **Process-leak history**: the fleet leaked python processes owned by the `fusil` user; fixed in
  **PRs #208/#209** (`start_new_session=True` + `killpg`; reap-on-self-exit in
  `fusil/process/create.py`). If you touch process/child handling, don't regress this.
- **Policy**: do NOT file FT-**subinterpreter** races upstream (per cpython#143232) — they're
  suppressed in `suppressions.txt`, not cataloged as bugs.

---

## 6. Running the tests (gotcha)

Some test modules do `from python._test_options import …`, so run from the **`tests/` dir** or via
discover so the `python` subpackage resolves:
```sh
cd ~/projects/fusil && ~/venvs/fusil_np_verify/bin/python -m unittest discover -s tests
# or a single module (from tests/):
cd tests && ~/venvs/fusil_np_verify/bin/python -m unittest python.test_tsan_generation
```
CI runs **both** `ruff check` and `ruff format --check` over `fusil/ tests/
fuzzers/fusil-python-threaded` — `check` passing does not imply `format --check` passes.

---

## 7. If Codex changes TSan things — quick guardrail checklist

- Edited `_write_tsan_stress_region`? → `test_tsan_generation.py` must still pass (it compiles the
  emitted script + asserts op markers); keep the emitter gated behind `--tsan`.
- Edited `tsan_dedup.py`? → `test_tsan_dedup.py` must pass **and** re-ingest a fleet to confirm
  `known_races.tsv` still matches (the signature format is the cross-repo contract, §4).
- Edited process/child handling? → don't regress the #208/#209 process-reaping fix.
- New race worth cataloging? → that's the sibling-repo's job (meta.json + `gen_known_races.py`),
  not a fusil change. Ping the maintainer (devdanzin) rather than filing upstream directly.
