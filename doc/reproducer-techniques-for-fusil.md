# Adapting cext-review-toolkit reproducer techniques to fusil

*Analysis date: 2026-06-30. Source catalog:
`~/projects/cext-review-toolkit/docs/reproducer-techniques.md` (32 techniques). Goal: find
techniques fusil can adopt as fuzzing inputs — especially new **tricky objects** — building on
the proven success of `set_nomemory` OOM injection (`--oom-fuzz`).*

## How fusil uses "tricky objects" today

The Python fuzzer injects hostile arguments through `ArgumentGenerator`
(`fusil/python/argument_generator.py`). Predefined hostile values live in
`fusil/python/samples/` and are surfaced by name via `fusil/python/tricky_weird.py`:

- **`weird_classes.py`** — subclasses of every builtin container/number/bytes type
  (`weird_list`, `weird_dict`, `weird_int`, …) under a `WeirdBase` metaclass with a *random*
  `__hash__` and an `__eq__` that returns `False`, plus no-op/odd-return overrides of
  `append`/`get`/`read`/`keys`/etc. Plus `FrameModifier` (a `__del__` that rewrites a caller
  frame local — a JIT-era trick).
- **`tricky_objects.py`** — odd builtin instances (self-referential `SimpleNamespace`, cyclic
  list, capsule, mappingproxy, recursive function/lambda, a descriptor, a metaclass that
  denies `__signature__` and rewrites `__mro_entries__`, a frame/traceback).
- **`tricky_typing.py`** — every `type` from abc/builtins/collections/typing + a giant `Union`.
- **`tricky_numpy.py`**, h5py objects, template strings — domain-specific.

A generator method (`genTrickyObjects`, `genWeirdClass`, …) is registered into the
`simple`/`hashable`/`complex` generator tuples; each emits a reference like
`tricky_objects['name']` or `weird_instances['name']` into the generated script. **Adding a new
tricky object is therefore cheap:** add it to a sample module, register its name in
`tricky_weird.py`, add a one-line `genX` method, and append that method to the relevant
generator tuple(s). fusil already optionally imports a `genStateful*`/`genLying*` family from
`lafleur.mutator` when lafleur is installed (`argument_generator.py:40-66`), so the slot for
"stateful bomb objects" already exists in spirit.

The other proven mode is **global allocator coercion**: `--oom-fuzz` arms
`_testcapi.set_nomemory` (Technique 18) and `--oom-seq` sweeps a *windowed* failure so a
corrupted allocation in one call is tripped over by a later call (the stale-state class that
found OOM-0036). This "make a normally-rare failure deterministic, process-globally" shape is
the template the best new techniques below follow.

## Coverage cross-reference

| # | Technique | fusil status | Opportunity |
| --- | --- | --- | --- |
| 1 | Metaclass hides `__name__`/`__module__`… | ✗ | **New tricky object** (MED) |
| 2 | Stateful `__hash__` (raises on Nth) | ~ random hash, not raising | **New tricky object** (LOW) |
| 3 | `__eq__` that raises | ~ returns False, not raises | **New tricky object** (LOW) |
| 4 | Descriptor `__get__` raises | partial (TrickyDescriptor returns self) | **New tricky object** (LOW) |
| 5 | Builtin subclass w/ malicious methods | ~ weird_classes no-op, don't raise | **Extend** weird_classes (LOW) |
| 5b/21 | Mischievous file-like objects | ✗ (h5py does files, not generic) | **New tricky object** (MED) |
| 6 | `__del__` side effects | partial (FrameModifier) | **Extend** (LOW) |
| 7 | `__index__`/`__int__`/`__float__` raises | ✗ | **New tricky object** (LOW) |
| 8 | Iterator fails mid-iteration | ✗ | **New tricky object** (LOW) |
| 9 | `__len__` lies or raises | ✗ | **New tricky object** (LOW) |
| 10 | Out-of-range / boundary indices | ~ numeric boundaries in weird_classes | **Extend** (LOW) |
| 11 | Mutating callback (clears container) | ✗ | New tricky object (HARD — needs container ref) |
| 12 | Weakref callback during sensitive op | ✗ | New tricky object (MED) |
| 13 | `__repr__`/`__str__` raises | ✗ | **New tricky object** (LOW) |
| 14 | `__bool__` raises | ✗ | **New tricky object** (LOW) |
| 15 | Buffer protocol abuse | partial (genBufferObject exists) | Extend (HARD) |
| 16/17 | refleak / tracemalloc measurement | ✗ (fusil is crash-focused) | Off-mission (detection, not input) |
| 18 | `set_nomemory` OOM injection | ✓ `--oom-fuzz` | Done (prolific) |
| 19 | Stateful metaclass hash (type-keyed dict) | ✗ | New tricky object (MED) |
| 20 | `str` subclass in `sys.modules` | ✗ | New harness option (MED, niche) |
| 22 | Callback mutates caller state | ✗ | New tricky object (HARD) |
| 23/27/31 | System-malloc fault (libfiu/LD_PRELOAD) | ✗ | **New mode — reaches foreign allocators** (HIGH) |
| 24 | RSS growth leak monitoring | ✗ | Off-mission (detection) |
| 25 | SystemError probe (PyCFunction contract) | ~ WatchStdout catches SystemError | **Lightweight new mode** (LOW-MED) |
| 26 | Cyclic-GC threshold coercion `(1,1,1)` | ✗ | **New global knob — cheap, high value** (LOW) |
| 28 | ctypes struct-field probe | ✗ | Off-mission (niche leak detection) |
| 29 | MRO unbound-method bypass | ✗ | Off-mission (immutability audit) |
| 30 | `python -O` assert-strip probe | ✗ | New run-variant (LOW, modest value) |
| 32 | TSan triage on 3.14t | ✗ (fusil does FT fuzzing, manual triage) | Off-mission (triage methodology) |

`✓` = covered, `~` = partially covered, `✗` = not covered.

---

## Recommendations, prioritized

### A. The "exception-bomb object" family — biggest ROI, lowest effort

> **STATUS: IMPLEMENTED.** `fusil/python/samples/bomb_objects.py` — the targeted family
> (`HashBomb`, `EqBomb`, `IndexBomb`, `LenBomb`, `LyingLen`, `ReprBomb`, `FailingIterator`)
> plus a metaclass-driven **`SuperBomb`** (every protocol slot raises a *random* exception on
> first use or after a *random* delay — spray-and-pray). Delays and (for SuperBomb) exception
> types are randomised per instance to walk a wide slice of program state. Wired into all three
> argument pools via `ArgumentGenerator.genBombObject` (weight `BOMB_WEIGHT`); tested in
> `tests/python/test_bomb_objects.py`.

This is the direct analogue of the OOM success at the *protocol* level. `set_nomemory` makes
**allocations** fail deterministically; an exception-bomb object makes a **dunder callback**
fail deterministically — exercising the huge class of C code that calls a Python protocol slot
(`__hash__`, `__eq__`, `__index__`, `__len__`, `__bool__`, `__repr__`, iteration, `__get__`)
and then does an unguarded `PyErr_Clear()` or assumes success. These are Techniques 2, 3, 7, 8,
9, 13, 14 and they all collapse into one small, parameterized family.

The key refinement, mirroring `--oom-seq`'s windowed failure: make the bomb **stateful /
delayed** — succeed on the first N calls, then raise. The cross-call "succeeded during
insert, fails during lookup" shape is exactly what surfaces swallowed-`MemoryError` bugs (it's
how Technique 2/19 found the pymongo/bson and msgspec bugs). And raising **`MemoryError`** (not
a generic error) is what makes these catch the *same* unguarded-error-path bug class as the OOM
mode — but reaching sites `set_nomemory` can't (where the failure originates in user code, not
the allocator).

Concrete addition — a new `samples/bomb_objects.py`:

```python
class _Bomb:
    """Base: succeed `delay` times, then raise `exc` from the armed dunder(s)."""
    def __init__(self, delay=0, exc=MemoryError):
        self._n, self._delay, self._exc = 0, delay, exc
    def _fire(self):
        self._n += 1
        if self._n > self._delay:
            raise self._exc("fusil bomb")

class HashBomb(_Bomb):
    def __hash__(self): self._fire(); return 42
    def __eq__(self, other): return self is other

class EqBomb:
    def __eq__(self, other): raise MemoryError("fusil eq bomb")
    def __ne__(self, other): raise MemoryError("fusil ne bomb")
    def __hash__(self): return 0
    def __iter__(self): return iter(())   # pass "is it a sequence?" pre-checks
    def __len__(self): return 0

class IndexBomb(_Bomb):
    def __index__(self): self._fire(); return 1
    def __int__(self): self._fire(); return 1
    def __float__(self): self._fire(); return 1.0

class LenBomb:
    def __len__(self): raise MemoryError("fusil len bomb")
    def __iter__(self): return iter([1, 2, 3])

class LyingLen:
    def __len__(self): return 1_000_000        # over-allocation
    def __iter__(self): return iter([1, 2, 3])

class FailingIterator:
    """Yields a few items then raises mid-iteration (extend/update partial-mutation)."""
    def __init__(self, n=3, fail=RuntimeError): self._i, self._n, self._fail = 0, n, fail
    def __iter__(self): return self
    def __next__(self):
        if self._i >= self._n: raise self._fail("fusil iter bomb")
        self._i += 1; return self._i
    def __len__(self): return self._n          # trip the pre-allocation path

class ReprBomb:
    def __repr__(self): raise MemoryError("fusil repr bomb")
    def __str__(self): raise RuntimeError("fusil str bomb")

class BoolBomb:
    def __bool__(self): raise RuntimeError("fusil bool bomb")
```

Wire each as a `genBomb*` returning e.g. `["HashBomb(delay=1)"]` (constructed inline so each
call gets a fresh, freshly-armed instance — important: a module-level singleton would stay
"fired"). Add them to the `simple`/`complex` (and `hashable`, for `HashBomb`) tuples. Because
they're constructed per-call, the `delay` can even be randomized per emission, giving the same
"sweep a range of windows" coverage `--oom-seq-randomize` gives. **Effort: LOW. Risk: LOW**
(opt-in via the generator tuples; output guarded by the golden test once added to the default
set, or behind a flag). This is the recommended first implementation.

### B. Cyclic-GC threshold coercion — a cheap global knob like `set_nomemory` (Technique 26)

`gc.set_threshold(1, 1, 1)` forces a gen-0 collection on essentially every tracked allocation,
turning rare "GC fires while an object is tracked but half-initialized" races (`tp_traverse`
reading a NULL field) into deterministic crashes. This is the same *shape* as the OOM win — a
one-line global coercion that massively amplifies a latent error class — and it composes with
everything else fusil already generates. Add a `--gc-aggressive` flag that emits
`import gc; gc.set_threshold(1, 1, 1)` near the top of the generated script (next to the OOM
harness). Pairs especially well with class-instantiation fuzzing and the bomb objects above.
**Effort: LOW. Risk: LOW.** Strong second pick.

### C. Mischievous file-like objects (Techniques 5b / 21)

A small set of file-like bombs — `read()` returning the wrong type, `read()` succeeding once
then raising (delayed failure, the most productive), `fileno()` raising while the object stays
callable — targets the very common "try fd, fall back to `.read()`" C pattern and mid-parse
error handling. fusil's h5py path exercises real files but nothing generic feeds hostile
file-likes to arbitrary module functions that accept a file argument. Add a `FileBomb` family
to the bomb module and a `genFileBomb` generator. **Effort: MED** (value depends on how often
target functions take file-like args; pairs with a heuristic that prefers it for params named
`file`/`fp`/`path`/`fileobj`). **Risk: LOW.**

### D. Metaclass / descriptor attribute bombs (Techniques 1, 4, 19)

- **Attribute-hiding metaclass** (T1): a class whose metaclass `__getattribute__` raises on
  `__name__`/`__module__`/`__qualname__` — targets unchecked `PyObject_GetAttrString(Py_TYPE
  (obj), …)` flowing into `strcmp`/`PyUnicode_AsUTF8`. fusil already passes types as arguments
  (`tricky_typing`), so a `HiddenNameType` slots in naturally.
- **Bomb descriptor** (T4): a descriptor whose `__get__` raises `KeyboardInterrupt`/
  `MemoryError`, injected into a class dict — targets unguarded `PyErr_Clear` in getattr
  fallbacks. fusil already has `TrickyDescriptor`; add a raising variant.
- **Stateful metaclass hash** (T19): a type whose metaclass `__hash__` succeeds at
  registration then fails after arming — targets `PyDict_GetItem` on type-keyed registries.

**Effort: MED** (each is a distinct object; T19 needs the "register then arm" two-phase
emission). **Risk: LOW.** Good third tranche after A/B.

### E. SystemError contract probe as a light mode (Technique 25)

fusil already *detects* `SystemError` (`WatchStdout` matches it, and `--oom-fuzz` explicitly
surfaces `[OOM] SystemError`). What it doesn't do is *systematically* call every module
function with deliberately-malformed args specifically to trip the
`PyErr_SetString(...); Py_RETURN_NONE;` contract violation and assert zero SystemErrors. fusil
already passes hostile args, so much of this happens incidentally; a focused `--contract-probe`
mode (call each function with positional garbage and bad kwargs, flag any SystemError) would
make it deterministic and fast. **Effort: LOW-MED. Risk: LOW.** Modest incremental value over
what incidental fuzzing already finds.

### F. System-malloc fault injection via libfiu / LD_PRELOAD (Techniques 23 / 27 / 31)

This is the strategic, higher-effort complement to `set_nomemory`. `set_nomemory` only hooks
CPython's allocator domains; it **cannot** reach `malloc`/`calloc`/`realloc` inside foreign C
libraries an extension links (HDF5, libzstd, libxml2, …). libfiu (`LD_PRELOAD` +
`fiu_posix_preload.so`) does, with call-site-specific targeting (`from_stack_of`). For fusil's
mission of crashing C-extension modules, this opens a genuinely new bug surface that the OOM
mode structurally can't see — the error/cleanup paths of the C libraries extensions wrap.
**Effort: HIGH** (libfiu build + `LD_PRELOAD`/`PYTHONMALLOC=malloc` plumbing in the process
launcher; subprocess isolation fusil already has). Technique 31's libfiu-free `LD_PRELOAD`
shim (`mallocfault.c`) is a lighter-weight alternative needing only a one-time `gcc`. **Risk:
MED** (env/launcher changes; the "bricks the interpreter under unconditional enable" footgun
must be handled with scoped arming, exactly as fusil already disarms `set_nomemory` outside the
window). Recommend as a separate project after A–D, *if* foreign-allocator coverage is a goal —
it's the natural "OOM mode, part 2."

### G. `python -O` assert-strip variant (Technique 30)

Running the generated script under `-O` strips Python-level `assert`s; diffing `-O` vs default
behavior surfaces asserts-used-as-validation. For fusil's C-crash focus this is modest (C
`assert()` depends on build-time `NDEBUG`, not `-O`), but it's nearly free: occasionally launch
the child interpreter with `-O`. **Effort: LOW. Risk: LOW. Value: modest.** Nice-to-have.

### Off-mission (catalogued, not recommended for fusil)

Leak-measurement harnesses (T16 refcount, T17 tracemalloc, T24 RSS, T28 ctypes struct probe)
are *detection* methodologies for a leak-hunting workflow, not fuzzing inputs — fusil is
crash-focused and its keep/drop logic is signal-based, so these belong in a separate leak-mode
tool if ever wanted. MRO bypass (T29) is an immutability audit. TSan triage (T32) is a
free-threaded race-interpretation methodology (fusil *does* free-threaded fuzzing, but
automating TSan verdict interpretation is a triage tool, not a generator change).

---

## Suggested implementation order

1. **A — exception-bomb object family** (`samples/bomb_objects.py` + generators). Highest
   ROI, lowest risk, directly extends the proven unguarded-error-path bug class to protocol
   slots `set_nomemory` can't reach. Make the bombs stateful/delayed (the `--oom-seq` insight).
2. **B — `--gc-aggressive`** (`gc.set_threshold(1,1,1)`). One-line global coercion, composes
   with everything.
3. **C/D — file-like bombs + metaclass/descriptor/stateful-hash bombs.** Same mechanism,
   broader protocol coverage.
4. **E — `--contract-probe`** SystemError mode (small, mostly already incidental).
5. **F — libfiu/LD_PRELOAD malloc fault** as "OOM mode part 2" reaching foreign allocators —
   the high-effort strategic item, only if C-library coverage is a goal.
6. **G — `-O` run variant** as a cheap nice-to-have.

Each new tricky object is independently testable: add it, regenerate the golden snapshot
intentionally (or gate behind a flag and verify via a before/after harness under a pinned
`PYTHONHASHSEED`, exactly as the OOM/feat harnesses already do), confirm the emitted script
parses, and dry-run with `--only-generate` against a real module.
