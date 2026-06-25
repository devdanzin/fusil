# JIT fuzzing subsystem — decision memo

**For:** maintainer decision (Phase 8 of `TECH_DEBT_PLAN.md`).
**Question:** keep `fusil/python/jit/` as-is, move it to **lafleur**, spin it off as a new
project, or park it in `notworking/`?
**TL;DR recommendation:** **move the reusable core to lafleur**, leave a thin shim in fusil.
The coupling is small and well-defined, lafleur is where the AST mutator already lives, and
you're not currently using fusil to fuzz the JIT.

> **Refinement (2026-06-25) — scope is narrower than "move bug_patterns + ast_pattern_generator."**
> An empirical trace of what lafleur *actually* runs (see **`jit-seed-generation.md`**) shows
> lafleur uses fusil **only as a subprocess** for seed generation, and only via the
> `--jit-target-uop=ALL` path — which **overrides `--jit-mode`**, so `synthesize`/`variational`/
> `legacy` are never exercised. The MVP "parts lafleur uses" are therefore just:
> `UOP_RECIPES` + `generate_uop_targeted_pattern` (of `ast_pattern_generator.py`),
> `_generate_uop_targeted_scenario` (of `write_jit_code.py`), and the **simple** half of
> `argument_generator.py`. `bug_patterns.py` is **not** used by seeding, and the evil/stateful
> object generators are **already in `lafleur.mutator`** (fusil imports them back via
> `HAS_MUTATOR`). So Option B/C should target that slice; the full port of `bug_patterns.py` /
> the synthesize grammar is a *later, quality* step (better seeds), not the MVP. Full port list
> in `jit-seed-generation.md` §6.

---

## What's actually there

`fusil/python/jit/` — 4,483 LOC:

| File | LOC | Role |
|------|-----|------|
| `write_jit_code.py` | 2,766 | Orchestrator `WriteJITCode`: mode dispatch, legacy scenario generators, hot-loop / execution-environment wrapping |
| `ast_pattern_generator.py` | 1,015 | `ASTPatternGenerator`: synthesizes novel test ASTs from a statement grammar |
| `bug_patterns.py` | 702 | `BUG_PATTERNS`: 18 named, templated JIT bug patterns (data only) |
| `__init__.py` | 0 | empty marker |

**Feature surface:** 15 `--jit-*` options; 4 modes via `--jit-mode`:
- `synthesize` (default) — `ASTPatternGenerator` builds fresh scenarios from a grammar.
- `variational` — mutate a `BUG_PATTERNS` template, optionally via lafleur's `ASTMutator`.
- `legacy` — hard-coded friendly/hostile scenarios (regression baseline).
- `all` — random mode + modifiers per test case.
Plus `--jit-correctness-testing` ("twin execution"), `--jit-target-uop`,
`--jit-feedback-driven-mode` (corpus mutation), `--jit-loop-iterations`, etc.

**lafleur coupling today:** `write_jit_code.py:42` does `from lafleur.mutator import
ASTMutator` inside a `try/except ImportError` and degrades gracefully (prints a `[!!!]`
warning, skips mutation) when lafleur is absent. So fusil → lafleur is already a soft,
optional dependency in this one direction. lafleur itself was spun off from this repo.

**State of repair:** `test_write_jit_code.py` imported the *removed*
`fusil.python.jit.ast_mutator`; Phase 0 guarded that import and skipped the one dependent
test. The legacy hard-coded `--rediscover-decref-crash` repro and ~60 scenario methods are
unmaintained. You've said you don't use fusil for JIT fuzzing and don't remember the full
feature set.

---

## How entangled is it? (measured)

`WriteJITCode` reaches back into its owner `WritePythonCode` (`self.parent`) through a
**small, well-defined surface** — 6 distinct attributes total:

| `self.parent.…` | uses | nature |
|-----------------|------|--------|
| `write_print_to_stderr` | 60 | logging only |
| `module_classes` | 3 | module introspection |
| `_get_object_methods` | 3 | module introspection |
| `write_block` | 2 | output buffer |
| `module_functions` | 2 | module introspection |
| `module` | 1 | the module under test |

Entry points from fusil into the JIT writer are just **three**: construction at
`write_python_code.py:121` (`self.jit_writer = WriteJITCode(self)`) and two calls —
`generate_scenario` (`:661`) and `generate_stateful_object_scenario` (`:786`).

`ASTPatternGenerator` and `BUG_PATTERNS` are essentially **self-contained** (stdlib `ast` +
`random` + a logging callback). `WriteJITCode`'s entanglement is almost entirely the logging
call; the only real fusil-specific dependency is module introspection (3 small methods).

---

## Options

### A. Keep as-is
- **Pros:** zero work.
- **Cons:** 4,483 LOC of unmaintained, unused code in the live tree; drags on every
  format/lint/test/doc pass; the lafleur dependency split is half-done.
- **Verdict:** not recommended — it's the status quo that created this debt.

### B. Move the reusable core to lafleur  ★ recommended
Move `bug_patterns.py` (pure data) and `ast_pattern_generator.py` (self-contained) to
lafleur, where `ASTMutator` already lives, so all the JIT-AST machinery is co-located. Reduce
fusil's `WriteJITCode` to either (a) a thin adapter that imports the generators from lafleur,
or (b) move `WriteJITCode` too and leave fusil with a small shim behind `--jit-fuzz`.
- **Decoupling cost:** introduce a tiny interface so the moved code doesn't import
  `WritePythonCode`:
  - replace the 60 `self.parent.write_print_to_stderr(...)` with an injected `log` callback
    (one constructor arg);
  - pass the 3 introspection results (`module`, `module_classes`, `module_functions`,
    `_get_object_methods`) in as plain data/callbacks at the 2 entry points.
  That's the whole surface — ~1 day of mechanical work, no behavior change.
- **Pros:** fusil shrinks to a thin JIT shim; the JIT/AST capability lives with the
  coverage-guided fuzzer that actually exercises it; clean dependency direction
  (fusil → lafleur, already established).
- **Cons:** requires a coordinated change in the lafleur repo; need to decide whether fusil
  keeps a `--jit-fuzz` shim at all.

### C. Spin off a new project (JIT test-case generator for lafleur's corpus)
Package `ASTPatternGenerator` + `BUG_PATTERNS` as a standalone generator that emits seed
test cases into lafleur's corpus, independent of fusil's pipeline.
- **Pros:** maximum independence; matches your stated idea ("create test cases for lafleur's
  corpus"); the synthesizer is the natural fit for this.
- **Cons:** a third project to maintain; duplicates module-introspection/arg-gen that fusil
  already has; more packaging overhead than B for similar benefit. Could be done *later* on
  top of B (lafleur would then own the generator and could expose a corpus-seeding entry
  point).

### D. Park in `notworking/`
Move `fusil/python/jit/` under `notworking/` and drop `--jit-fuzz` wiring.
- **Pros:** cheapest way to get it out of the live path now; reversible.
- **Cons:** abandons working capability that lafleur could use; loses it from the maintained
  set. Best only if you want it gone and aren't ready to invest in B/C.

---

## Recommendation & suggested path

**B now, C optional later.** Concretely:
1. In lafleur: add `bug_patterns` + `ast_pattern_generator` (verbatim, plus a `log` callback
   param replacing `write_print_to_stderr`).
2. In fusil: make `WriteJITCode` import them from lafleur; replace the `self.parent.*`
   logging with the callback; pass introspection in at the 2 entry points. Keep `--jit-fuzz`
   as a thin shim **iff** you still want to launch JIT runs from fusil; otherwise go to D for
   the fusil side and let lafleur own JIT fuzzing entirely.
3. Replace the skipped `test_write_jit_code.py` with tests living next to the moved code in
   lafleur.

If you'd rather not touch lafleur right now, **D** is the no-regret interim: park it,
revisit B/C when you next work on lafleur. Either way the broken test is already neutralized
(Phase 0), so this decision blocks nothing else in the sweep.

**Decision needed:** B (move to lafleur, keep shim?) · B-then-D (move, drop fusil shim) ·
C (spinoff) · D (park) · keep as-is.
