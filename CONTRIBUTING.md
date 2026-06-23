# Contributing to fusil

Active development targets **only the Python fuzzer** (`fusil-python-threaded`,
`fusil.python` / `fusil.python.jit`). The legacy fuzzers and non-Python subsystems under
`*/notworking/` are out of scope. Start with `doc/python-fuzzer.md` for an architecture
overview and `CLAUDE.md` for repository orientation.

## Requirements

- **Python 3.13+** (the code uses `types.CapsuleType` and PEP 701 f-strings).
- **`python-ptrace`** — a hard runtime dependency (`fusil.application` imports it at module
  load), so the fuzzer can't even start without it.

## Dev setup

```bash
python3.13 -m venv .venv && . .venv/bin/activate
pip install -e .                 # installs fusil + python-ptrace; adds the
                                 # `fusil-python-threaded` console script
pip install -e '.[numpy,h5py]'   # optional: enable the numpy/h5py argument generators
pip install ruff                 # linter/formatter (CI pins ruff==0.15.18)
```

A real fuzzing run drops the fuzzed child to a dedicated unprivileged `fusil` user; for quick
local runs pass `--unsafe` (runs children as you). **Never** point `--filenames` at files you
care about — fuzzed calls may overwrite them.

## Tests, lint, format

```bash
python -m unittest discover -s tests   # the suite (unittest, NOT pytest)
ruff check fusil/ tests/ fuzzers/fusil-python-threaded
ruff format fusil/ tests/ fuzzers/fusil-python-threaded
```

numpy/h5py-dependent tests skip gracefully when those packages aren't installed. CI
(`.github/workflows/ci.yml`) runs ruff (check + format) and the unittest suite on Python 3.13
and 3.14.

### Writing tests

Prefer **runtime-free** unit tests (no real fuzzing child, no ptrace). Good models:
`tests/test_oom_dedup.py`, `tests/test_process_limits.py`, `tests/test_mas.py`. For tests that
construct `WritePythonCode`, use `tests/python/_test_options.py:make_test_options()` — it
harvests the real option defaults so tests don't rot when new options are added. Seed `random`
in `setUp` for any generator that picks values at random.

## Workflow

- Branch off `main`; keep the test suite green at every commit.
- One concern per pull request. Run `ruff check`, `ruff format`, and the suite before pushing.
- `ruff format` runs as an isolated commit; bulk-reformat commits are listed in
  `.git-blame-ignore-revs` (enable locally with
  `git config blame.ignoreRevsFile .git-blame-ignore-revs`).
- Code generators (`write_python_code.py`, `jit/`, `h5py/`) build target source as strings and
  carry scoped lint ignores in `pyproject.toml`; match the surrounding style.
