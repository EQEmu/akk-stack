"""Host-side input identity, result table and path checks. No daemon or candidate execution."""

import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "validation" / "journey"))

import fixture as F  # noqa: E402
import host  # noqa: E402


class Inputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "server").write_bytes(b"server-bytes")
        (self.root / "client").write_bytes(b"client-bytes")
        self.maps = self.root / "maps"
        self.maps.mkdir()
        (self.maps / "qeynos2.map").write_bytes(b"map")
        (self.maps / "qeynos2.wtr").write_bytes(b"wtr")
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **kw):
        base = dict(server=str(self.root / "server"), client=str(self.root / "client"), maps=str(self.maps),
                    server_revision="abc", client_revision=None, allow_unpinned_maps=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_unpinned_maps_refused(self):
        with self.assertRaises(host.UsageError):
            host.stage_inputs(self.args(), self.run_dir)

    def test_identity_recorded_from_inputs(self):
        identity = host.stage_inputs(self.args(allow_unpinned_maps=True), self.run_dir)
        self.assertEqual(identity["server"]["sha256"], hashlib.sha256(b"server-bytes").hexdigest())
        self.assertEqual(identity["server"]["revision"], "abc")
        self.assertFalse(identity["maps"]["files"]["qeynos2.map"]["pinned"])
        self.assertEqual((self.run_dir / "inputs/client").read_bytes(), b"client-bytes")
        for name in host.HARNESS_FILES:
            self.assertTrue((self.run_dir / "harness" / name).is_file())

    def test_missing_inputs(self):
        with self.assertRaises(host.UsageError):
            host.stage_inputs(self.args(server=str(self.root / "nope")), self.run_dir)
        (self.maps / "qeynos2.wtr").unlink()
        with self.assertRaises(host.UsageError):
            second = self.root / "run2"
            second.mkdir()
            host.stage_inputs(self.args(allow_unpinned_maps=True), second)


class Paths(unittest.TestCase):
    def test_source_tree_refused(self):
        with self.assertRaises(host.UsageError):
            host.outside_repo(host.REPO / "runs")
        self.assertEqual(host.outside_repo(Path("/tmp")), Path("/tmp").resolve())

    def test_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            with host.harness_lock(Path(tmp)):
                with self.assertRaises(host.EnvironmentFailure):
                    with host.harness_lock(Path(tmp)):
                        pass
            with host.harness_lock(Path(tmp)):
                pass


class Table(unittest.TestCase):
    def test_order_and_not_run(self):
        pre = {"inputs": {"name": "inputs", "status": "pass"}}
        guest = {"milestones": [{"name": "observer_self_check", "status": "pass"},
                                {"name": "server_start", "status": "fail"}]}
        table = host.milestone_table(guest, pre, True)
        self.assertEqual([m["name"] for m in table], list(F.MILESTONES))
        self.assertEqual(table[1]["status"], "not_run")
        self.assertEqual(table[3]["status"], "fail")
        self.assertEqual(table[-1]["status"], "pass")
        self.assertEqual(host.milestone_table(None, pre, None)[-1]["status"], "not_run")


class Cli(unittest.TestCase):
    def test_usage_exit_writes_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = host.main(["--state-root", tmp, "run", "--server", "/nonexistent", "--client", "/nonexistent",
                              "--maps", tmp, "--output-root", tmp + "/runs"])
            self.assertEqual(code, host.EXIT_USAGE)
            results = list(Path(tmp, "runs").glob("*/result.json"))
            self.assertEqual(len(results), 1)
            result = json.loads(results[0].read_text())
            self.assertEqual(result["first_failed_milestone"], "inputs")
            self.assertEqual(result["exit_code"], host.EXIT_USAGE)
            self.assertEqual(result["milestones"][-1]["status"], "not_run")


if __name__ == "__main__":
    unittest.main()
