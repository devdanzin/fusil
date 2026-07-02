"""Tests for the fleet reporter (fusil/python/fleet_report.py).

Pure-Python: builds a fixture fleet dir (sidecars + fake labelled crash dirs) and exercises
collection, aggregation, anomaly flags, and rendering with injected time and systemd off.
"""

import json
import os
import sys
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

from fusil.python import fleet_report as fr


def _sidecar(path, **kw):
    data = {
        "schema": 1,
        "gil_mode": "0",
        "pid": 111,
        "run_dir": os.path.basename(os.path.dirname(path)),
        "started_at": 1000.0,
        "updated_at": 1050.0,
        "sessions": 0,
        "crashes": 0,
        "timeouts": 0,
        "cpu_load_kills": 0,
        "modules": {},
    }
    data.update(kw)
    with open(path, "w") as fh:
        json.dump(data, fh)


def _crash(run_dir, name):
    d = os.path.join(run_dir, name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "source.py"), "w").close()


class TestClassify(unittest.TestCase):
    def test_labels_and_kinds(self):
        cases = {
            "_blake2-fatal_python_error-OOM-0043-2": ("_blake2", "fatal_python_error", "OOM-0043"),
            "_curses-exitcode1-oomclean-5": ("_curses", "exitcode1", "oomclean"),
            "email_mime_base-systemerror-oomclean": ("email_mime_base", "systemerror", "oomclean"),
            "json-sigsegv-oomNEW": ("json", "sigsegv", "oomNEW"),
            "mod-exitcode127-oomclean": ("mod", "exitcode127", "oomclean"),
            "weird_name_only": ("weird_name_only", "other", "other"),
        }
        for name, expected in cases.items():
            self.assertEqual(fr.classify_crash_dir(name), expected, name)


class TestCollectAndAggregate(unittest.TestCase):
    def _fleet(self, tmp):
        # inst-01: 2 run dirs (a restart), a sidecar with counts, 2 crash dirs
        r1 = os.path.join(tmp, "inst-01", "python")
        r2 = os.path.join(tmp, "inst-01", "python-2")
        os.makedirs(r1)
        os.makedirs(r2)
        _sidecar(
            os.path.join(r1, "fusil_stats.json"),
            sessions=100,
            crashes=3,
            timeouts=5,
            modules={"json": {"hits": 60, "crashes": 3, "timeouts": 1}},
        )
        _sidecar(
            os.path.join(r2, "fusil_stats.json"),
            sessions=50,
            crashes=1,
            timeouts=2,
            started_at=900.0,
            updated_at=1200.0,
            modules={"sqlite3": {"hits": 50, "crashes": 1, "timeouts": 1}},
        )
        _crash(r1, "json-sigsegv-oomNEW")
        _crash(r2, "sqlite3-exitcode1-oomclean")
        # inst-02: no sidecar, one crash dir (post-hoc only path)
        r = os.path.join(tmp, "inst-02", "python")
        os.makedirs(r)
        _crash(r, "mod-fatal_python_error-OOM-0043")
        return tmp

    def test_collect_instance_merges_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._fleet(tmp)
            r = fr.collect_instance(os.path.join(tmp, "inst-01"), now=2000.0, systemd=False)
            self.assertEqual(r["instance"], 1)
            self.assertEqual(r["sessions"], 150)  # summed across the two run dirs
            self.assertEqual(r["restarts"], 2)
            self.assertEqual(r["kept_crashes"], 2)
            self.assertEqual(r["oomnew"], 1)
            self.assertEqual(r["by_kind"].get("sigsegv"), 1)
            self.assertEqual(r["by_label"].get("oomclean"), 1)
            self.assertEqual(r["modules"]["json"]["hits"], 60)
            self.assertGreater(r["disk_bytes"], 0)

    def test_discover_and_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._fleet(tmp)
            insts = fr.discover_instances(tmp)
            self.assertEqual([fr.instance_number(d) for d in insts], [1, 2])
            report = fr.build_report(tmp, None, systemd=False, now=2000.0)
            agg = report["campaign"]
            self.assertEqual(agg["instances"], 2)
            self.assertEqual(agg["sessions"], 150)  # inst-02 has no sidecar
            self.assertEqual(agg["kept_crashes"], 3)
            self.assertEqual(agg["oomnew"], 1)
            self.assertEqual(agg["by_label"].get("OOM-0043"), 1)

    def test_single_instance_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._fleet(tmp)
            report = fr.build_report(tmp, 2, systemd=False, now=2000.0)
            self.assertEqual(len(report["instances"]), 1)
            self.assertEqual(report["instances"][0]["instance"], 2)

    def test_discover_single_inst_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._fleet(tmp)
            insts = fr.discover_instances(os.path.join(tmp, "inst-01"))
            self.assertEqual(len(insts), 1)


class TestAnomaliesAndRender(unittest.TestCase):
    def test_churn_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            inst = os.path.join(tmp, "inst-03")
            for i in range(6):  # 6 run dirs >= CHURN_RESTARTS
                os.makedirs(os.path.join(inst, "python" if i == 0 else "python-%d" % (i + 1)))
            r = fr.collect_instance(inst, now=2000.0, systemd=False)
            flags = fr.anomalies([r])
            self.assertTrue(any("churn" in reason for _n, reason in flags))

    def test_render_contains_key_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            r1 = os.path.join(tmp, "inst-01", "python")
            os.makedirs(r1)
            _sidecar(
                os.path.join(r1, "fusil_stats.json"),
                sessions=100,
                crashes=2,
                modules={"json": {"hits": 100, "crashes": 2, "timeouts": 0}},
            )
            _crash(r1, "json-sigsegv-oomNEW")
            report = fr.build_report(tmp, None, systemd=False, now=2000.0)
            camp = fr.render(report, None)
            self.assertIn("FUSIL FLEET", camp)
            self.assertIn("HEALTH", camp)
            self.assertIn("oomNEW", camp)
            inst = fr.render(report, 1)
            self.assertIn("fusil instance 1", inst)
            self.assertIn("json", inst)


if __name__ == "__main__":
    unittest.main()
