import tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from netagent.cli import main

EX = Path(__file__).parent.parent / "examples"


class TestCLI(unittest.TestCase):
    def test_audit_and_topology_end_to_end(self):
        out = Path(tempfile.mkdtemp())
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc = main(["audit", "--rules", str(EX / "rules/baseline.json"), "--inventory", str(EX / "inventory.json"),
                       "--configs", str(EX / "configs"), "--out", str(out / "r.md"), "--fail-on-high"])
            # The inventory includes fw1 without a saved config, so the audit is incomplete.
            self.assertEqual(rc, 1)
            self.assertIn("## Missing configurations", (out / "r.md").read_text())
            self.assertIn("fw1", (out / "r.md").read_text())
            rc = main(["topology", "--neighbors", str(EX / "neighbors"), "--inventory", str(EX / "inventory.json"),
                       "--out", str(out / "topo")])
        self.assertEqual(rc, 0)
        self.assertIn("NO-TELNET", (out / "r.md").read_text())
        self.assertTrue((out / "topo/topology.mmd").exists())

    def test_audit_fails_with_nonzero_code_when_all_configs_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.md"
            err = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(err):
                rc = main(["audit", "--rules", str(EX / "rules/baseline.json"),
                           "--inventory", str(EX / "inventory.json"),
                           "--configs", str(Path(tmp) / "empty"), "--out", str(out)])
            self.assertEqual(rc, 1)
            self.assertIn("missing config", err.getvalue())
            report = out.read_text()
            self.assertIn("## Missing configurations", report)
            for hostname in ("core-sw1", "edge-r1", "fw1"):
                self.assertIn(hostname, report)

    def test_bad_cidr_returns_error_code(self):
        err = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(["discover", "not-a-network"]), 1)
        self.assertIn("error:", err.getvalue())
