# Writing fusil plugins

Plugins extend the fusil **Python fuzzer** without modifying its core. They are the
supported way to teach fusil about a specific library (how to build its objects, what
hostile inputs to feed it, which names to skip) and to add whole fuzzing modes — the
mechanism the in-tree h5py and cereggii support was moved out into.

Two reference plugins live in sibling repos and are worth reading alongside this guide:

- **`fusil-h5py-plugin`** (`github.com/devdanzin/fusil_h5py_plugin`) — argument generator +
  definitions + instance dispatcher + class handler + a `--fuzz-h5py` option.
- **`fusil-cereggii-plugin`** (`github.com/devdanzin/fusil_cereggii_plugin`) — tricky-object
  argument generators + definitions + a dedicated **fuzzing mode** + blacklist/whitelist.
- **`fusil-numpy-plugin`** (`github.com/devdanzin/fusil_numpy_plugin`) — the simplest example,
  and the one that is **not target-gated**: it injects tricky numpy arrays into *every* run
  when installed (condition = "not `--no-numpy`"), because numpy values are useful hostile
  inputs for any C extension. It was extracted verbatim from the core.

## How discovery works

Plugins are ordinary installed packages that expose a `register` callable in the
**`fusil.plugins`** entry-point group. In `pyproject.toml`:

```toml
[project.entry-points."fusil.plugins"]
myplugin = "fusil_myplugin:register"
```

At `Application` startup, `PluginManager.discover_and_load_plugins()` imports every such
entry point and calls `register(manager)` once. A plugin that raises during import or
`register()` is reported to stderr and skipped — it never aborts fusil startup. Install a
plugin into the **same environment as fusil** (`pip install -e .` from a checkout); to
disable it, uninstall it.

> The plugin's `register()` runs in the **parent** fusil process. Anything a plugin wants to
> run inside the fuzzed **child** must be *emitted as source* (see *Definitions* and
> *Fuzzing modes*) — you cannot hand the child a live Python object or callable, because the
> child is a separate interpreter running the generated `source.py`.

## The `register(manager)` contract

```python
def register(manager):
    # Guard on optional deps so a missing target library disables the plugin cleanly
    # instead of breaking fusil.
    try:
        import mylib  # noqa: F401
    except ImportError as err:
        import sys
        print(f"[myplugin] mylib unavailable ({err}); disabled.", file=sys.stderr)
        return

    manager.declare_dependency("mylib")          # advisory; see Dependencies below
    manager.add_cli_option("--fuzz-mylib", action="store_true", default=False,
                           help="Force mylib support on for any target module.")
    manager.add_argument_generator(gen_mylib_obj, "simple", weight=20,
                                   condition=_is_mylib_target)
    manager.add_definitions_provider(provide_mylib_setup)
    manager.add_hook("startup", lambda config: ...)
```

### The activation pattern

Most hooks take a **`condition(config, module_name)`** predicate or should check one
themselves, so the plugin is inert unless its library is the fuzz target. The idiom both
reference plugins use:

```python
def _is_mylib_target(config, module_name) -> bool:
    if getattr(config, "fuzz_mylib", False):   # the plugin's own --fuzz-mylib flag
        return True
    mods = module_name or ""
    return "mylib" in [m.strip() for m in mods.split(",")]
```

`config` is fusil's options object (the parsed CLI). Read plugin-added options off it via
`getattr(config, "fuzz_mylib", False)` — the attribute name is the `--fuzz-mylib` option's
dest. `module_name` may be a single module or a comma-separated list depending on the hook,
so handle both.

## The registration API

Everything below is a method on the `PluginManager` passed to `register()`. The "Consumed
by" column is where the core reads it back, so you can see exactly what each hook feeds.

| Method | Purpose | Consumed by |
| --- | --- | --- |
| `add_cli_option(*args, **kwargs)` | Add a `--flag` (forwarded to `optparse.add_option`). | `Fuzzer.createFuzzerOptions` (own "Plugin Options" group) |
| `add_argument_generator(func, category, weight=1, condition=…)` | A `() -> list[str]` that yields argument *source expressions*. `category` ∈ `simple`/`complex`/`hashable`; `weight` duplicates it in the pool; `condition(config, module)` gates it. | `ArgumentGenerator` value pools |
| `add_definitions_provider(func)` | `func(config, module) -> str \| None`: **source code** injected near the top of every generated script (setup for tricky objects, helper funcs, imports). | `WritePythonCode` (definitions block) |
| `add_instance_dispatcher(func)` | `func(writer, prefix, target_expr, class_hint, depth) -> int \| None`: emit `elif isinstance(target, MyType): …` fuzzing branches for a live instance. Return the indent level to restore (to wrap the generic fallback in `else:`), or `None`. | `WritePythonCode._dispatch_fuzz_on_instance` |
| `add_class_handler(func)` | `func(writer, class_name, class_type, instance_var, prefix) -> bool`: emit specialized instantiation for a class the generic `callFunc` can't build; return `True` to claim it. | `WritePythonCode._fuzz_one_class` |
| `add_fuzzing_mode(name, activation_check, setup_script)` | A whole alternative main-logic generator. `activation_check(config) -> bool`; `setup_script(writer)` emits the entire fuzzing body. | `WritePythonCode` (`get_active_mode`) |
| `add_blacklist_entry(kind, pattern, pattern_type="exact")` | Skip a discovered name. `kind` ∈ `module`/`class`/`function`/`object`/`method`; `pattern_type` `exact` or `glob`. | name filtering in `WritePythonCode` |
| `add_whitelist_entry(kind, pattern, pattern_type="exact")` | Keep a name normally skipped (honoured for `method`, e.g. `__del__`). | method filtering in `WritePythonCode` |
| `add_suppression_entry(pattern, reason=None)` | A regex `re.search`ed against a crash's stdout to drop known/uninteresting **hits** (see `--suppress-hit-regex`, issue #53). | `Fuzzer._suppression_keep_policy` |
| `add_tsan_shared_factory(source, label=None, iterable=True, condition=…)` | A Python **expression** (e.g. `"__import__('cereggii').AtomicDict()"`) spliced into the `--tsan` concurrency-stress region as a shared object hammered from many threads; `iterable=True` also folds `iter(source)` into the shared-iterator op (points op *h* at the target's own `tp_iternext`); `condition(config, module)` gates it. | `WritePythonCode._write_tsan_stress_region` |
| `add_hook(name, func)` | Lifecycle hook; `name` ∈ `startup`/`shutdown`. `startup(config)` runs after option parsing; `shutdown()` at exit. | `Application.setup` / `Application.exit` |
| `declare_dependency(name, required_version=None)` | Advertise a required package/plugin. | `check_dependencies` at startup |
| `declare_incompatibility(name)` | Advertise a conflicting plugin. | `check_dependencies` at startup |

### Argument generators

A generator returns a list of **strings that are valid Python expressions** in the generated
script. It typically hands back a *reference* to a pre-built tricky object (set up by a
definitions provider) rather than an inline literal:

```python
def gen_mylib_obj():
    if not _tricky_names:
        return ["mylib.Thing()"]          # fallback
    return [f"tricky_things['{choice(_tricky_names)}']"]

manager.add_argument_generator(gen_mylib_obj, "simple", weight=20, condition=_is_mylib_target)
```

`weight` is how many times the generator is added to the pool — the cereggii and h5py
plugins use weights of 10–50 to make their objects common when their library is the target.

### Definitions — the setup the child runs

A definitions provider returns source that is spliced into every generated script. This is
where you build the `tricky_things` catalog the argument generators reference, and any
runtime helper functions:

```python
def provide_mylib_setup(config, module_name):
    if not _is_mylib_target(config, module_name):
        return None
    return "\n".join([
        "# --- BEGIN mylib plugin definitions ---",
        mylib_setup_source,          # builds tricky_things = {...} in the child's globals
        "# --- END mylib plugin definitions ---",
    ])
```

### Scenarios

fusil has **no separate "scenario provider" hook** — scenarios are delivered with the two
mechanisms above:

- put the scenario **functions/dicts** in a *definitions provider* (they land in the child's
  `globals()`), and
- add a *fuzzing mode* whose `setup_script` emits a runner that picks and calls them.

Because the child is a separate process, the runner must find scenarios in its own
`globals()` (populated by the definitions) — **do not** `import your_plugin` from inside the
generated script, since the target interpreter (`--python`) may not have the plugin
installed. The cereggii plugin's `cereggii_scenario` mode is the worked example.

## Suppression, blacklists, and dependencies

- **Suppression** (`add_suppression_entry`) drops crashing-session *hits* whose stdout
  matches a regex — the plugin-contributed counterpart of `--suppress-hit-regex`. See
  [`python-fuzzer.md`](python-fuzzer.md) (*Hit suppression*).
- **Blacklist/whitelist** filter discovered *names* by kind (module/class/function/object/
  method), `exact` or `glob`. Use them to skip hang-prone or false-positive methods
  (cereggii blacklists `_rehash`/`wait`, whitelists `__del__`).
- **Dependencies** (`declare_dependency` / `declare_incompatibility`) are advisory: at
  startup `check_dependencies()` reports unmet requirements / conflicts to stderr but does
  **not** abort — pair it with a hard `try/import` guard in `register()` for anything the
  plugin genuinely needs.

## Testing a plugin

Plugins should ship tests (fusil itself is thinly tested; a broken plugin fails silently).
Test `register()` against a stub manager (a `SimpleNamespace`/`Mock` recording the
`add_*` calls) so you don't need fusil's runtime stack, and test the pure argument-generator
/ definitions logic directly. The h5py plugin's `tests/` are a good template. Mirror fusil's
ruff config in the plugin's `pyproject.toml` so moved-out modules stay clean.

## Packaging checklist

```toml
[project]
dependencies = ["fusil", "mylib"]           # plus anything mylib needs

[project.entry-points."fusil.plugins"]
myplugin = "fusil_myplugin:register"

[tool.setuptools]
packages = ["fusil_myplugin", "fusil_myplugin.samples"]   # list sub-packages explicitly
```

Install into fusil's environment (`pip install -e .`), then confirm discovery:

```bash
python -c "import importlib.metadata as m; print([e.name for e in m.entry_points(group='fusil.plugins')])"
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --help   # your --fuzz-* option should appear
```
