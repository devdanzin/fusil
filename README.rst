Fusil (revived: the Python fuzzer)
==================================

This is a revival of Victor Stinner's `fusil` fuzzing framework. **Only the Python
fuzzing path is actively developed and tested** — the ``fusil-python-threaded`` fuzzer and
the ``fusil.python`` / ``fusil.python.jit`` subsystems. Its focus is finding crashes in
CPython itself, C-extension modules, the CPython Tier-2 JIT, and out-of-memory
(allocation-failure) error paths.

The other historical fuzzers (firefox, php, mplayer, …) and non-Python subsystems
(network, file/process mangling, X11, …) are **legacy and out of scope**: they live under
``fuzzers/notworking/`` and ``fusil/notworking/``, may not work as-is, and are kept only so
they remain recoverable. Many links in the old reST docs are stale (some are retrievable via
the WayBack Machine).

Fusil is built on a small multi-agent system: agents communicate by asynchronous messages,
and a per-session score drives the fuzzer's adaptive *aggressivity*. Each session generates a
standalone test script, runs it under the target interpreter as a sandboxed child process
(memory/cpu/process limits, dropped privileges, redirected output), and watches the child for
crash signals (exit signal/code, and stdout/stderr patterns like ``segmentation fault`` /
``Fatal Python error`` / ``AddressSanitizer``).

Website: https://github.com/devdanzin/fusil


Quick start
===========

Fusil requires **Python 3.13+** and ``python-ptrace``. Install it (editable, with the
optional numpy/h5py argument-generator support) and run the Python fuzzer::

    $ pip install -e '.[numpy,h5py]'
    # or from a checkout, without installing:
    $ PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --unsafe --modules json --sessions 5

``--unsafe`` runs the fuzzed child processes as the current user. Without it, fusil expects a
dedicated unprivileged ``fusil`` user/group to drop to (the safe default for real runs).
**Never** point ``--filenames`` at files you care about — fuzzed calls may overwrite them.

See ``fusil/python/__init__.py`` (``createFuzzerOptions``) for the full option list; common
ones include ``--only-c``, ``--jit-fuzz``, ``--oom-fuzz`` / ``--oom-seq``, ``--deep-dive``,
and ``--no-memory-limit``.


Documentation
=============

- **doc/python-fuzzer.md** — how the Python fuzzer works (start here).
- **README_JIT.md** — the JIT fuzzing subsystem design.
- **doc/oom-fuzzing.md**, **doc/oom-sequences.md**, **doc/oom-dedup-plan.md** — OOM injection
  and in-loop crash dedup.
- **CLAUDE.md** — repository/contributor orientation.
- **doc/index.rst** — the original (largely legacy) reST documentation index.


Development
===========

Tests use ``unittest`` (not pytest)::

    $ python -m unittest discover -s tests
    $ ruff check fusil/        # lint
    $ ruff format fusil/       # format

Contributions to any part of fusil are welcome, but active development and CI focus on the
Python fuzzer.
