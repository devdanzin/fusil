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
- **A memory cap per instance** (`MemoryMax`) so a runaway OOM-injection child can't take
  down the whole machine.
- **`fleet finds`**: surfaces the `oomNEW` crash dirs — the new-bug candidates — across
  all instances, using the labels the in-loop dedup already writes. That's your
  "anything interesting?" answer.

## One-time setup

1. Copy this `fleet/` directory onto the fuzzing host (anywhere, e.g. `/home/ubuntu/fleet`).
2. Edit **`fleet.conf`** — set `FUSIL_PY`, `TARGET_PYTHON`, `CATALOG`, `FLEET_DIR`, and the
   `FUSIL_FLAGS` (the defaults match your current command). Make sure `RUNNER_PY` is the
   `python3` from the venv that has fusil installed.
3. `chmod +x fleet fleet-run`

> The `CATALOG` (`known_sites.tsv`) is the dedup snapshot. Generate/refresh it from the
> `cpython-oom-findings` catalog with `gen_known_sites.py`; all instances read it
> read-only, so there's no write contention.

## Daily use

```bash
sudo ./fleet up            # start (nproc-1) instances; or: sudo ./fleet up 8
./fleet status             # per-instance state + crashes kept + NEW candidates
./fleet finds              # list the oomNEW dirs across the whole fleet
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
  GIL-on. To also throw JIT or different module sets into the mix, run a second fleet
  dir with different `FUSIL_FLAGS` (the unit is shared, so use a separate checkout/config
  if you want two profiles at once — or just edit `FUSIL_FLAGS` and `fleet restart`).
- **Logs filling disk.** `fusil.out` is truncated each run start. With `--oom-verbose`
  it can still grow within a run; set `LOG=none` in `fleet.conf` to discard fusil's
  stdout (you still get crash dirs + `session.log` + systemd's start/stop in journald).

## Under the hood (so it's not a black box)

- **`fusil@.service.in`** — a systemd *template* unit. `%i` is the instance number;
  `fleet up` fills in the paths/limits and installs it. `systemctl start fusil@3` ⇒ runs
  instance 3.
- **`fleet-run N`** — what each unit actually runs: makes `inst-NN/`, picks the GIL mode
  for instance N, `exec`s fusil there so systemd supervises fusil directly.
- **`fleet`** — a thin wrapper over `systemctl` + reads the result dirs for `status`/`finds`.

To see raw systemd state at any time: `systemctl status 'fusil@*'`,
`journalctl -u fusil@3 -e`.
