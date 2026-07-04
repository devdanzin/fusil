# Code-review findings backlog (Phase 5b)

Produced by a code-review-toolkit pass over the **live tree** (`fusil/` excl. `notworking/`,
`fuzzers/fusil-python-threaded`) on 2026-06-23. Items already fixed in the Phase 5b PR are
marked ✅; the rest are a backlog for the maintainer.

## Fixed in Phase 5b
- ✅ **Real bug — `fatalError()` exited 0.** `application.py` set `self.exit_code = 1` (typo)
  then `exit(self.exitcode)` (still 0), so fatal config/safety errors reported success to
  CI/fleet. Fixed to `self.exitcode = 1`.
- ✅ **Dead code removed** (zero callers anywhere): `config.configparser_to_options`,
  `file_tools.safeMkdir`, `file_tools.dumpFileInfo` (this also drops a `ptrace.linux_proc`
  import from a core module), `python/utils.import_all`, and the unused `DEBUG = False`
  constant in `python/__init__.py`.

## Error handling (silent-failure audit) — backlog
The core runtime is mostly healthy (narrow, well-targeted excepts). Real items:
- **C2 — `Agent.__del__` calls `self.send()` during teardown** (`mas/agent.py`): on
  `KeyboardInterrupt` it tries to `send("application_interrupt")`, but `send()` raises if the
  agent is inactive (the usual case in `__del__`), so Ctrl-C during GC is eaten. Make `__del__`
  best-effort only (no `send()`; guard on `is_active`, fall back to a stderr print).
- **H1 — `python_source.on_session_start` catches `BaseException`** around `loadModule`: swallows
  `KeyboardInterrupt`/`SystemExit` during a slow import. Catch `Exception`; let the base signals
  propagate.
- **H2 — `list_all_modules._process_package` uses `except (ImportError, Exception)`**: redundant
  and aborts the whole discovery pass on any non-ImportError. Decide policy → `except Exception`
  and skip the package.
- **H3 — `utils.remove_logging_pycache`** — ✅ RESOLVED by removal (issue #36). Ran
  unconditionally at startup and mutated the installed stdlib's `logging/__pycache__`, but only
  in the *parent* interpreter — whereas the `--- Logging error ---` spam it targeted comes from
  the `--python` *child* (which defaults to `sys.executable`, so parent==child only when
  `--python` is unset; this campaign always overrides it → the workaround touched the wrong
  interpreter, hence "still happening"). The real trigger is stale/mismatched `logging` bytecode
  in the *target build's* `__pycache__` (a git-checkout/rebuild hazard). Non-destructive fix if
  it recurs: run the child with `PYTHONPYCACHEPREFIX=<scratch>` so it never reads stale in-tree
  `.pyc`. The `reload(logging)` was "unverified necessity" (its own docstring). Removed the
  function + its call in `main()`.
- **H4 — `Application.exit()` runs `deinitX11()` outside the cleanup try**: a non-ptrace error in
  `agents.clear()` skips X11 deinit (leaves X access granted). Move to `finally`.
- **M-series:** `Directory.rmtree_error`/`isEmpty` swallow then degrade silently; `runProject`'s
  `finally` `destroy()` can mask the original exception; `allowCoreDump`/`target_is_asan`/
  `_oom_keep_policy` return sentinels on failure that some callers ignore — add a WARNING where
  the fallback materially changes behavior (cap applied, dir kept).
- **Policy — no exception chaining anywhere.** Re-raises (`config.py`, `process/create.py`,
  `session_directory.py`) drop context. Adopt `raise X from e` for triage-friendly tracebacks.

## Architecture — backlog
- **Benign-but-fragile runtime import cycle** through the package hub:
  `python/__init__ → python_source → write_python_code → argument_generator → import fusil.python`.
  Quick fix: in `argument_generator.py` import `fusil.python.tricky_weird` directly instead of the
  package. (All the JIT/h5py "cycles" are TYPE_CHECKING-only — no action.)
- **God-modules:** `jit/write_jit_code.py` (~2960 LOC) and `write_python_code.py` (~1470 LOC) hold
  most of the generator logic and are the main change-risk. See complexity items.

## Complexity hotspots — backlog (refactor opportunities)
Concentrated entirely in the code generators; core (`application`/`project`/`config`/`session`/
`process`) is clean. The systemic driver is the manual `self.write()/addLevel()/restoreLevel()`
indentation idiom.
- **Enabling change first:** add an indentation **context manager** (`with self.indent():`) to the
  writer base — shrinks/de-risks nearly every generator hotspot. Land with golden-output tests
  (snapshot generated `source.py` for fixed seeds).
- `WritePythonCode._write_main_fuzzing_logic` (cognitive 73) — split per mode/target.
- `WritePythonCode._generate_and_write_call` (9 params) — introduce a `CallSpec` dataclass; extract
  deep-dive/thread/async blocks.
- `WritePythonCode._get_module_members`, `PythonSource.__init__`,
  `ArgumentGenerator._gen_collection_internal` — small, low-risk extractions.
- h5py `_fuzz_one_*_instance` family + `WriteJITCode._generate_variational_scenario` — large but
  mechanical (opt-in paths, lower priority).

## Remaining dead code (coordinated legacy cleanup — defer)
Only reachable from `notworking/` / `examples/` / doctests, so remove together with the legacy
fuzzers (or when they're formally retired): `process/env.py` `EnvVar{Length,Integer,IntegerRange,
Random}`; `file_tools.filenameExtension`; `cmd_help_parser.py`. Also `weird_classes.FrameModifier`
is defined after the registry-population loop so it's never registered — verify intent before
removing. `oom_dedup.classify` / `extract_site_from_bt` and `fixtures.fixture_dir` are test-only
back-compat helpers (keep if the contract matters).

## Test coverage gaps → feeds Phase 6
Strong but narrow (almost all under `fusil/python/`). Highest-value untested units:
`fusil/mas/*` (the message bus — zero tests, highest fan-in), `python/arg_numbers.py` (branchy
parser, doctests don't run), `score.py`/`tools.py` (pure logic), `bytes_generator`/
`unicode_generator`, `aggressivity.py` (state machine), `directory.py` + `session_directory`
keep/rename logic, `blacklists.py` structural guards (+ a likely `_builtin__:set` typo at
`blacklists.py:135`). Also: **`test_doc.py` is broken** (references `fusil.bits`, now in
`notworking/`) so its doctests don't run — fix or retire it and wire into the unittest path.
