# fusil Guide

This guide will help you install and use fusil, both locally and on the cloud.

## Installing fusil locally

To install fusil locally, follow these steps:
```bash
git clone https://github.com/devdanzin/fusil
cd fusil
# Activate the virtual environment, then
pip install -e .
```

Then you'll need to create a `fusil` user, under which the fuzzer will run. You can do this using the `adduser` command:
```bash
sudo adduser fusil
```

Installing fusil on the cloud is similar. On the OracleArm machine, fusil is already installed and the `fusil` user is already created.

## Using fusil

fusil must be launched by root user: it will create a new fusil instance and run the fuzzer scripts as the `fusil` user. This is done to ensure that the fuzzer runs with the correct permissions and does not interfere with the system.

The easiest way to use fusil is to launch as a fleet from a root console:
```bash
sudo su  # Switch to root user
export F=/home/opc/projects/fusil/fleet/fleet  # Point this to the fleet executable
export FLEET_CONF=/home/opc/fleet.conf  # Point this to a fleet configuration file
$F up 3  # Launch the fleet with 3 workers
```

A fusil fleet is a collection of workers that run fuzzing jobs in parallel. Configuration sets the fuzzed modules/extensions and many other options. Here's an example configuration file:
```bash
TARGET_PYTHON=/home/danzin/venvs/matrix_venvs/main-debug-gil-nojit-asan/bin/python
GIL_MODES="1"                     # GIL build -> clean ASan UAF/free-stacks
RUNNER_PY=/home/danzin/venvs/matrix_venvs/fusil_debug-ft-nojit_venv/bin/python  # has fusil + ptrace
FUSIL_PY=/home/danzin/projects/fusil/fuzzers/fusil-python-threaded
FLEET_DIR=/home/fusil/runs/fusil-apsw_asan_01

FUSIL_FLAGS="--discover-in-target --modules=apsw --test-private \
--classes-number 25 --methods-number 12 --functions-number 30 --objects-number 20 \
--child-memory-limit-mb 4096 --crash-drain-ms=3000 \
-v --timeout 60 --success=12000 --fast --exitcode-score=1"

INSTANCES=6
MEM_MAX=6G
NICE=10
LOG=file
```

In the OracleArm machine, there are a couple configuration files available in `/home/opc/`. You can use these as a starting point for your own configuration. Here's a concrete example in `/home/opc/fleet_multidict_oom_foreign.conf`:
```bash
TARGET_PYTHON=/home/opc/venvs/new_3.14_venv/bin/python
GIL_MODES="1"                     # allocation-failure paths; deterministic for the gdb resolver
RUNNER_PY=/home/opc/venvs/release_cpython_venv/bin/python
FUSIL_PY=/home/opc/projects/fusil/fuzzers/fusil-python-threaded
CATALOG=/home/opc/projects/cpython-oom-findings/catalog/known_sites.tsv  # CPython sites; apsw/SQLite
                                                                           # crashes won't match -> oomNEW
INGEST=/home/opc/projects/cpython-oom-findings/scripts/ingest.py
FLEET_DIR=/home/fusil/runs/fusil-multidict_oomforeign_04

# Shallow sweep bounds: foreign allocations fault at LOW start indices, so a deep set_nomemory-style
# sweep just burns cycles. Sequences (--oom-seq) matter more here than depth: a failed allocation
# mid-Connection/Cursor lifecycle is exactly the cross-call stale-state class.
FUSIL_FLAGS="--modules=multidict --packages=multidict --test-private \
--classes-number 25 --methods-number 10 --functions-number 25 --objects-number 20 \
--child-memory-limit-mb 4096 \
-v --timeout 60 --success=12000 --fast --exitcode-score=1 \
--oom-fuzz --oom-verbose --oom-foreign --oom-dedup-prune --oom-dedup-catalog=$CATALOG \
--oom-seq --oom-seq-randomize --oom-seq-len 8 --oom-window 16 --oom-max-start 50 "
INSTANCES=6
MEM_MAX=4G
NICE=10
LOG=file
```

Once the fleet is up, you can monitor it using the `$F status` command:
```bash
$F status
```
To stop the fleet, use the `$F down` command:
```bash
$F down
```

The findings will be written to the `$FLEET_DIR` directory. There are many findings in `/home/fusil/runs/fusil-multidict_oomforeign_04`, most of which are uninteresting.
