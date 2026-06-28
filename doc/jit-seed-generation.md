# JIT seed generation: what lafleur actually uses, and the MVP to absorb it

**Companion to `jit-decision-memo.md`.** That memo asked *where* the JIT subsystem should
live. This doc answers the prerequisite questions empirically: **what does each JIT option
actually generate, is it lafleur-usable, and exactly which fusil code does lafleur depend on
to produce seeds** — so the "move only the parts lafleur uses" MVP can be scoped precisely.

Grounded in: the real command lafleur runs (`lafleur/corpus_manager.py:431` `generate_new_seed`),
generated sample seeds (one per mode, see *Appendix: how to regenerate*), and a read of the
call graph from `write_jit_code.py` → `ast_pattern_generator.py` → `argument_generator.py`.

---

## TL;DR

- **JIT fuzzing does NOT emit "classic" call-spray scripts.** Classic fusil = `callFunc/
  callMethod(...)`-heavy bodies driven by `--functions/--classes/--methods-number`. JIT mode
  replaces that body with a **hot-loop harness**. lafleur sets the classic knobs to ~0, so its
  seeds are *only* a JIT harness.
- **lafleur never imports fusil.** Its sole fusil dependency is a **subprocess** call to
  `fusil-python-threaded` for seed generation. It already owns its own boilerplate
  (`mutation_controller.get_boilerplate`), its own `ASTMutator`, coverage, corpus, mutation.
- **lafleur only exercises the `--jit-target-uop` path.** It passes `--jit-target-uop=ALL`,
  which **overrides `--jit-mode`** — so `synthesize`/`variational`/`legacy` are never used by
  lafleur. Of the 4,483-LOC JIT subsystem, lafleur's seeds come from **one method**
  (`_generate_uop_targeted_scenario`) + **one data table** (`UOP_RECIPES`, 38 entries) + the
  **simple** half of the argument generator.
- **The "evil object" half of the value generator already lives in lafleur**
  (`lafleur.mutator.genSimpleObject` / `genStateful*`); fusil imports them *back* via
  `HAS_MUTATOR`. So the MVP only needs the **simple scalar/collection generators** — exactly
  the "simplified copy of fusil's simple argument generators" that's acceptable.

---

## 1. What lafleur runs (the only coupling)

`CorpusManager.generate_new_seed` (`lafleur/corpus_manager.py:431`) shells out to:

```
<fusil> --jit-fuzz --jit-target-uop=ALL --jit-loop-iterations=300 --no-jit-external-references
        --classes-number=0 --functions-number=1 --methods-number=0 --objects-number=0
        --sessions=1 --only-generate --modules=encodings.ascii --python=<target>
        --no-threads --no-async --no-numpy
```

Then it runs the produced script, measures JIT coverage, strips the boilerplate to `core_code`,
and adds that to the corpus. `lafleur/orchestrator.py:209` passes
`mutation_controller.get_boilerplate` *into* `CorpusManager` — **lafleur supplies its own
boilerplate**, independent of fusil. The `--fusil-path` arg (`orchestrator.py:1039`) is the only
fusil handle; there is no `import fusil` anywhere in lafleur.

Consequence: making lafleur self-sufficient for seeds = **removing this subprocess**, by porting
the small slice of fusil it drives.

## 2. The seed shape (what `--jit-target-uop=ALL` emits)

A self-contained, reliably-hot, trivially-mutable harness (from the real generated seed):

```python
# setup: typed vars realized from each recipe's placeholders
int_v1 = -8109937; int_v2 = -5396; ...; tuple_v7 = (True, None, bytearray(b"test"), ...)
stateful_getattr_object_v8 = ...   # (a real evil object when lafleur is installed; see §6 note)

def uop_harness_f1():
    int_v1 < int_v1                 # _COMPARE_OP_LT_INT
    int_v4 | int_v2                 # _BINARY_OP_OR_INT
    if stateful_bool_object_v5: pass  # _TO_BOOL
    {int_v2: any_v6}                # _BUILD_MAP
    for res in tuple_v7: pass       # _FOR_ITER_TUPLE
    stateful_getattr_object_v8.x    # _LOAD_ATTR
    int_v9 & int_v2                 # _BINARY_OP_AND_INT

for i_f1 in range(300):             # --jit-loop-iterations
    try: uop_harness_f1()
    except Exception as e: print(...); break
```

`_generate_uop_targeted_scenario` (`write_jit_code.py:314`) picks 3–7 uops from `UOP_RECIPES`,
calls `ast_pattern_generator.generate_uop_targeted_pattern()` for the setup+body, then wraps it
with `_begin_hot_loop` + `_generate_guarded_call`. Each body line is a `UOP_RECIPES` template
(`write_jit_code.py:36` imports `UOP_RECIPES`); e.g.

```python
"_BINARY_SUBSCR_LIST_INT": {
    "pattern": "{result_var} = {target_list}[{index}]",
    "placeholders": {"result_var": ("new_variable",),
                     "target_list": ("list","object_with_getitem","stateful_getitem_object"),
                     "index": ("small_int","stateful_index_object")}},
```

## 3. The JIT options — effect, lafleur use, compatibility

| option | effect | lafleur uses? | output lafleur-usable? |
|---|---|---|---|
| `--jit-fuzz` | swap classic body → JIT harnesses | ✅ | gate |
| `--jit-target-uop=NAME\|ALL` | **overrides mode**; emits a `uop_harness` of `UOP_RECIPES` snippets in a hot loop | ✅ (`ALL`) | ✅ **best** — clean, hot, mutable |
| `--jit-loop-iterations=N` | the `range(N)` warm-up count | ✅ (`300`) | — |
| `--no-jit-external-references` | recipe values use literals/locals, not boilerplate names → core is strippable/self-contained | ✅ | — (what makes stripping work) |
| `--jit-mode=synthesize` (default) | `ASTPatternGenerator.generate_pattern()` grammar in a random env | ❌ overridden | ⚠️ parseable but sampled output is **called once, no outer hot loop** → weak JIT seed |
| `--jit-mode=variational` (+`--jit-pattern-name`, `--jit-fuzz-ast-mutation`, `-systematic-values`, `-type-aware`) | fill a `BUG_PATTERNS` template (18 curated JIT-bug shapes) | ❌ | ⚠️ rich but larger & **module-coupled** (refs `encodings.ascii.X`, `target_instance_*`); some template artifacts |
| `--jit-mode=legacy` (+`--jit-hostile-prob`) | hard-coded scenarios / `friendly_base` | ❌ | ⚠️ has a hot loop but **bloated** (e.g. 260 params + 260 giant int args) |
| `--jit-mode=all` | random mode+modifiers per case | ❌ | mixed |
| `--jit-correctness-testing` / `--jit-correctness-prob` | "twin execution": JIT vs non-JIT, compare, raise `JITCorrectnessError` | ❌ | finds *silent* bugs, not crashes |
| `--jit-feedback-driven-mode` | mutate an existing corpus file via lafleur's `ASTMutator` | ❌ | overlaps lafleur's own job |
| `--jit-wrap-statements` | synthesize: wrap each stmt in try/except | ❌ | — |
| `--jit-fuzz-classes` | **defined but never consumed — dead option** | ❌ | — |

All four modes emit valid, parseable, self-contained Python (so all are *syntactically*
mutable). They differ in seed **quality**: **uop > synthesize (clean but weak hot-loop) >
variational (rich but coupled/large) > legacy (bloated).**

## 4. Mode shapes (empirical, post-boilerplate)

- **uop** (lafleur): `def uop_harness_fN(): <uop snippets>` + `for i in range(N): try: uop_harness()`. ~90 lines.
- **synthesize**: `class Runner_fN: def harness(self,...): try: <synth assigns/exprs> except...` called **once** (no outer hot loop in the sample).
- **variational**: `def harness_fN(...): <BUG_PATTERN template>` — e.g. `evil_deep_calls` recursive chain that calls into the target module; module-coupled.
- **legacy/friendly_base**: `def outer_fN(): def harness_fN(p_0..p_259): ...; for i in range(1,2000): <mutable ops>; harness_fN(<260 huge ints>)`.

## 5. The exact seed-gen call graph (fusil side)

```
fusil-python-threaded --jit-fuzz --jit-target-uop=ALL ...
└─ WriteJITCode.generate_scenario                         write_jit_code.py:103
   └─ (jit_target_uop set ⇒ overrides mode)               write_jit_code.py:139
      └─ _generate_uop_targeted_scenario                  write_jit_code.py:314
         ├─ UOP_RECIPES (38 entries, data)                ast_pattern_generator.py:33
         ├─ ASTPatternGenerator.generate_uop_targeted_pattern   ast_pattern_generator.py:721
         │  ├─ arg_generator.generate_arg_by_type(p_type,var)   argument_generator.py:521
         │  │  ├─ simple: genInt/genFloat/genString/genSmallUint/genBytes/
         │  │  │          genList/genTuple/genDict/genSet  argument_generator.py:288–509   ← fusil-only
         │  │  └─ objects (HAS_MUTATOR): genSimpleObject/genStateful*  ← ALREADY in lafleur.mutator
         │  └─ helpers: _get_unique_var_name, _get_substitutions_for_recipe,
         │             _collect_assigned_variables, _generate_evil_snippet
         ├─ _begin_hot_loop, _generate_guarded_call        write_jit_code.py
         └─ CodeTemplate (CT)                              fusil/write_code.py
+ boilerplate preamble                                     ← lafleur already owns (mutation_controller.get_boilerplate)
```

The simple generators rest on small helper classes set up in `ArgumentGenerator.__init__`
(`IntegerGenerator`, `IntegerRangeGenerator`, `UnsignedGenerator`, `UnicodeGenerator`,
`BytesGenerator`, `UnixPathGenerator`) and value tables (`INTERESTING`, `SURROGATES`,
`BUFFER_OBJECTS`, `LETTERS`/`ASCII8`/`UNICODE_65535`, `TEMPLATES` from `fusil.python.values` /
`fusil.unicode_generator`) plus `escapeUnicode` (`fusil.python.unicode`). The collection
generators recurse through `create_simple_argument` → `simple_argument_generators`.

## 6. Exact MVP port list (what to move/copy into lafleur)

**Goal:** native `generate_jit_seed()` in lafleur; drop the fusil subprocess.

**Port (the uop generator — small, mostly self-contained):**
1. `UOP_RECIPES` (`ast_pattern_generator.py:33–~700`) — pure data, 38 recipes. Verbatim.
2. `ASTPatternGenerator.generate_uop_targeted_pattern` + `_get_unique_var_name`,
   `_get_substitutions_for_recipe`, `_collect_assigned_variables`, `_generate_evil_snippet`,
   `_get_prefix` (`ast_pattern_generator.py:721+`). Replace the lone `self.parent.
   write_print_to_stderr` with an injected `log` callback. (The `generate_pattern` synthesize
   grammar and everything else in this 1,015-line file is **not** needed for the MVP.)
3. `_generate_uop_targeted_scenario` + `_begin_hot_loop` + `_generate_guarded_call`
   (`write_jit_code.py`) — re-home as a plain function; `jit_target_uop`/`jit_loop_iterations`
   become parameters; `write_print_to_stderr` → `log`.
4. `CodeTemplate` (`fusil/write_code.py`) — small dedent/format helper. Copy or reimplement.

**Copy a trimmed value generator (the simple half only):**
5. From `ArgumentGenerator`: `generate_arg_by_type` (the dispatch) + `genInt/genFloat/genString/
   genSmallUint/genBytes/genList/genTuple/genDict/genSet` + `_gen_collection_internal`,
   `_create_dict_item_lines`, `_gen_unicode_internal`, `create_simple_argument`/
   `create_hashable_argument`/`_create_argument_from_list`.
6. Their helper generators + value tables (items in §5). A **simplified copy is acceptable**:
   keep `IntegerGenerator`/`IntegerRangeGenerator`/`UnsignedGenerator` + a minimal
   `UnicodeGenerator`/`BytesGenerator` + the `INTERESTING` table; have the collection generators
   recurse only into the simple scalars. Drop tricky/weird/numpy/h5py/template/external-reference
   generators (lafleur passes `--no-jit-external-references`; the object kinds come from lafleur).

**Already in lafleur — wire `generate_arg_by_type`'s object branch directly to these:**
- `lafleur.mutator.genSimpleObject`, `genStateful{Getattr,Getitem,Index,Bool,Iter,Len}Object`,
  `genUnstableHashObject`, `genLyingEqualityObject`, `genStatefulStrReprObject`
  (fusil currently imports these *from* lafleur via `HAS_MUTATOR`, `argument_generator.py:38`).

**Do NOT port (unused by lafleur's seeding):** `bug_patterns.py` (variational); `generate_pattern`
(synthesize grammar); all `WriteJITCode` legacy/twin/feedback/stateful-object scenarios; the
classic call-spray pipeline in `write_python_code.py`.

> **Runtime note (verified):** when generating these samples, lafleur was **not** importable in
> the driver venv, so `HAS_MUTATOR` was False and the `stateful_*`/`object*` placeholders
> degraded to plain ints/lists via the `"any"` fallback. In lafleur's real runtime
> (`HAS_MUTATOR` True) those placeholders yield genuine evil objects from `lafleur.mutator` —
> confirming the object half is already lafleur's. A native lafleur generator should call those
> directly (no degraded fallback), which **also improves seed quality** for free.

## 7. Recommendation & "better seeds"

- **MVP = port §6 Tier-1 (uop generator) + a trimmed §6 Tier-2 (simple value gen); call
  lafleur's own object generators directly.** This is far narrower than the decision memo's "move
  `bug_patterns.py` + `ast_pattern_generator.py`": `bug_patterns.py` is unused by seeding, and
  only `UOP_RECIPES` + `generate_uop_targeted_pattern` of `ast_pattern_generator.py` are used.
- **Grand deliverable (better seeds).** Today lafleur seeds *only* from repetitive uop harnesses
  (same operands repeated, constants, shallow data flow). Two high-value sources already exist in
  fusil and are currently untapped as seeds: the **18 curated `BUG_PATTERNS`** (known
  JIT-fragile shapes — ideal seeds) and a **hot-loop-wrapped synthesize grammar** (real
  data-flow / polymorphism / side-exits). A native generator can emit all three families
  straight into the corpus and target the traits lafleur's scheduler already rewards
  (`trace_length`, `side_exits`, `lineage_depth`). Recommended sequence: (1) port the uop MVP and
  delete the subprocess; (2) add `BUG_PATTERNS` as direct corpus seeds; (3) add a
  hot-loop-wrapped synthesize generator; (4) retire fusil's JIT subsystem to `notworking/`.

## Appendix: how to regenerate the samples

Driver venv needs `python-ptrace`; target is any 3.16 JIT build. (`fusil_np_verify` has ptrace.)
```
DRV=~/venvs/fusil_np_verify/bin/python; TGT=~/venvs/jit_cpython_venv/bin/python
PYTHONPATH=$PWD $DRV fuzzers/fusil-python-threaded --jit-fuzz --jit-target-uop=ALL \
  --source-output-path=/tmp/seed.py --classes-number=0 --functions-number=1 \
  --methods-number=0 --objects-number=0 --sessions=1 --python=$TGT \
  --no-jit-external-references --no-threads --no-async --no-numpy \
  --jit-loop-iterations=300 --modules=encodings.ascii --only-generate
```
Swap in `--jit-mode=synthesize|variational|legacy` (drop `--jit-target-uop`) to see the other
shapes. Install lafleur in the driver venv to get real evil objects (else the `[!!!] ASTMutator
not available` degraded path).
</content>
