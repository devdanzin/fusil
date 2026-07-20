# fusil fleet — run many fusil instances and keep them alive

Replaces the manual loop of "cd into a dir, start fusil, check it's still up, eyeball
the results" with three commands. It uses **systemd** (the service manager already on
your Linux box) to start N instances, restart any that die or finish, cap their memory,
and capture their logs — no VMs or containers needed.

## What it gives you

- **One command to start N instances**, each in its own directory, spread across both
  `PYTHON_GIL` modes (they find *different* crashes).
- **Auto-restart**: if an instance crashes or hits `--success` and exits, systemd brings
  it back. This is the "is it still running?" check, done by the OS.
- **A memory cap per instance** (`MemoryMax`) so a runaway child (an OOM-injection sweep, a
  RustPython balloon, …) can't take down the whole machine.
- **`fleet finds`**: surfaces the new-bug-candidate crash dirs across all instances, using the
  labels the in-loop dedup already writes. That's your "anything interesting?" answer.

The tooling is **mode-agnostic** — `status`, `finds`, `triage` and `report` work the same for OOM,
TSan, RustPython and plain runs, because every dedup engine labels a new-bug candidate `<prefix>NEW`
(`oomNEW`/`tsanNEW`/`rustpyNEW`) and an unresolved segv/frame `<prefix>SEGV`/`tsanFRAME`. Run
**`./fleet info`** to see the fleet's auto-detected mode, loaded plugins, target and paths.

## One-time setup

1. Copy this `fleet/` directory onto the fuzzing host (anywhere, e.g. `/home/ubuntu/fleet`).
2. Edit **`fleet.conf`** — set `FUSIL_PY`, `TARGET_PYTHON`, `CATALOG`, `FLEET_DIR`, and the
   `FUSIL_FLAGS` (the defaults match your current command). Make sure `RUNNER_PY` is the
   `python3` from the venv that has fusil installed.
3. `chmod +x fleet fleet-run`

> The `CATALOG` is the dedup snapshot for whichever mode you run — `known_sites.tsv` from
> `cpython-oom-findings` (OOM), `known_races.tsv` from `cpython-tsan-findings` (TSan), or
> `known_panics.tsv` from `rustpython-findings` (RustPython). Regenerate it with the catalog's
> generator; all instances read it read-only, so there's no write contention.

## Daily use

```bash
sudo ./fleet up            # start (nproc-1) instances; or: sudo ./fleet up 8
./fleet info               # mode, plugins, target and paths for this fleet
./fleet status             # per-instance state + crashes kept + NEW candidates
./fleet report             # rich observability: mode/plugins, sessions, throughput, crash taxonomy, health
./fleet report 3           # ...for one instance;  add --watch (live), --html FILE (dashboard), or --json
./fleet finds              # list the new-bug-candidate dirs across the whole fleet
./fleet tail 3             # follow instance 3's output live
sudo ./fleet down          # stop everything
sudo ./fleet restart       # restart all (e.g. after refreshing the catalog)
./fleet triage             # dedupe all instances' crashes (needs INGEST set in fleet.conf)
```

`fleet up` installs `/etc/systemd/system/fusil@.service` and runs `fusil@1 … fusil@N`.
Because systemd `enable`s them, they also come back **after a reboot**.

## How it maps to your old steps

| Old manual step | Now |
|---|---|
| `sudo su`, activate venv, `cd` into a dir, `nohup … &` per instance | `sudo ./fleet up N` |
| check each is still running, restart by hand | systemd `Restart=always` (automatic) |
| eyeball every result dir for something interesting | `./fleet finds` / `./fleet status` |
| `> /dev/null` (logs lost) | per-instance `fusil.out` (or journald); `./fleet tail N` |

## Tuning

- **How many instances?** `up` defaults to `nproc-1`. Memory is usually the limit, not
  CPU — watch `free -h`; if instances get OOM-killed often, lower the count or raise
  `MEM_MAX`. Each instance also runs child interpreters, so it uses more than one core's
  worth at peak.
- **Diversity.** `GIL_MODES="0 1"` alternates instances between free-threaded and
  GIL-on (they find disjoint crashes). Caveat: `PYTHON_GIL=0` is inherited by the
  *runner* python too, so including `0` requires `RUNNER_PY` to be a **free-threaded**
  venv (build one from a free-threaded CPython + `pip install python-ptrace`); a non-FT
  runner fatals with "Disabling the GIL is not supported by this build" (`fleet check`
  catches it). Use `GIL_MODES="1"` if your runner isn't free-threaded.
  To also throw JIT or different module sets into the mix, run a second fleet
  dir with different `FUSIL_FLAGS` (the unit is shared, so use a separate checkout/config
  if you want two profiles at once — or just edit `FUSIL_FLAGS` and `fleet restart`).
- **Logs filling disk.** `fusil.out` is truncated each run start. With `--oom-verbose`
  it can still grow within a run; set `LOG=none` in `fleet.conf` to discard fusil's
  stdout (you still get crash dirs + `session.log` + systemd's start/stop in journald).

## TSan fleets (data-race fuzzing)

To hunt ThreadSanitizer data races instead of OOM crashes, point the fleet at a
free-threaded **`--with-thread-sanitizer`** interpreter and swap the flags in `fleet.conf`:

```sh
TARGET_PYTHON=~/projects/python_build_matrix/builds/debug-ft-nojit-tsan/python
GIL_MODES="0"                                  # --tsan requires free-threading
CATALOG=~/projects/cpython-tsan-findings/catalog/known_races.tsv
FUSIL_FLAGS="--tsan --tsan-dedup-prune --tsan-dedup-catalog=$CATALOG"
```

`fleet check` validates the TSan target and the catalog for you. fusil handles the rest
(`setarch -R`, unlimited `RLIMIT_AS`, `TSAN_OPTIONS`, `DEBUGINFOD_URLS=`, implied `--no-numpy`);
see `doc/tsan-mode-plan.md`. Crash dirs self-label `…-warning_threadsanitizer_data_race-…`
(and their race id / `tsanNEW` / `tsanFRAME` under `--tsan-dedup-catalog`).

**Triage loop** (in the sibling `cpython-tsan-findings` catalog):

```sh
FUSIL_TSAN_DEDUP=../fusil/fusil/python/tsan_dedup.py \
  python3 scripts/ingest.py '<fleet-dir>/inst-*/python*/*'  # bucket by race signature; NEW ones need a report
# NB: `python*`, not `python` -- a restarted instance gets a FRESH project dir (python-2, python-3,
# ...) beside the first one, so `inst-*/python/*` silently ingests only the pre-restart run. On one
# restarted fleet that glob covered 155 of 1585 dirs (10%). Quote the pattern so ingest.py globs it
# itself rather than the shell.
# write reports/TSAN-NNNN-.../meta.json for each new signature, then:
python3 scripts/gen_known_races.py                        # regenerate known_races.tsv; fleet restart picks it up
```

### Un-masking profile (expose the rare tail)

A handful of "gateway" races (itertools.count + the bytes/str/struct/dict/set iterator cursors)
dominate the **first race** of almost every session, so they shadow rarer, more interesting races
— even under `--tsan-no-halt`, they still crowd the vehicle counts. (Analysis:
`cpython-tsan-findings/notes/feature-impact.md`; the filed GenericAlias **crash**, cpython#154043,
is *never* a first race.) To hunt the tail — new object races, the hostile weird-subclass surface,
rare crashers — run a **dedicated** fleet that suppresses the gateways at the TSan level via
`--tsan-suppressions`:

```sh
# Use an ABSOLUTE path -- the fleet runs as root under systemd, so `~` / a $VAR set from your
# login shell expands to /root, not your home, and TSan aborts every session with
# "failed to read suppressions file" (silent: the target never runs, so the fleet finds nothing).
FUSIL_FLAGS="--tsan --tsan-no-halt --tsan-dedup-catalog=$CATALOG \
  --tsan-suppressions=/home/YOU/projects/cpython-tsan-findings/catalog/gateway_suppressions.txt"
```

Root can read a file under your home as long as your home is traversable (`chmod o+x ~`) and the
file is world-readable (it is). If TSan can't open the file it prints
`ThreadSanitizer: failed to read suppressions file '…'` and the child exits without running --
so a suddenly-silent un-masking fleet almost always means a wrong suppressions path; grep an
instance's `fusil.out`/a session `stdout` for that line first.

fusil feeds the file to both `TSAN_OPTIONS=suppressions=…` (so TSan never reports the gateways) and
the in-loop deduper. Sessions whose only races are gateways then exit clean and aren't kept, so the
kept dirs are enriched for the tail and the rare races accumulate the vehicles they need to be
minimized. This is **experiment-only** — keep the standard catalog-building fleet on the plain
`FUSIL_FLAGS` above, since the gateway file is deliberately aggressive (it can also suppress a new
race that merely shares a frame with a gateway function). Prioritize the kept crashes for the
"does it segfault on a plain build?" check with `cpython-tsan-findings/scripts/prioritize.py`.

## Under the hood (so it's not a black box)

- **`fusil@.service.in`** — a systemd *template* unit. `%i` is the instance number;
  `fleet up` fills in the paths/limits and installs it. `systemctl start fusil@3` ⇒ runs
  instance 3.
- **`fleet-run N`** — what each unit actually runs: makes `inst-NN/`, picks the GIL mode
  for instance N, `exec`s fusil there so systemd supervises fusil directly. It also exports
  `PYTHONPYCACHEPREFIX=/tmp/fusil-pycache-root` so the (root) runner interpreter never writes
  `.pyc` into the target build's shared `Lib/` — systemd gives the service a clean env, so a
  shell export before `fleet up` would never reach it, and the interpreter reads the var only at
  startup. (fusil redirects its own module-discovery imports and its downgraded fusil-user
  children to `/tmp/fusil-pycache` in-process.) Keeps the matrix tree free of root-owned `.pyc`
  that would otherwise block `rm`/rebuild.
- **`fleet`** — a thin wrapper over `systemctl` + reads the result dirs for `status`/`finds`.

To see raw systemd state at any time: `systemctl status 'fusil@*'`,
`journalctl -u fusil@3 -e`.
