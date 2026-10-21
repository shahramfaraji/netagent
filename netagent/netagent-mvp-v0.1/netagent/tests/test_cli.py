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
            self.assertEqual(rc, 2)
            rc = main(["topology", "--neighbors", str(EX / "neighbors"), "--inventory", str(EX / "inventory.json"),
                       "--out", str(out / "topo")])
        self.assertEqual(rc, 0)
        self.assertIn("NO-TELNET", (out / "r.md").read_text())
        self.assertTrue((out / "topo/topology.mmd").exists())

    def test_bad_cidr_returns_error_code(self):
        err = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(["discover", "not-a-network"]), 1)
        self.assertIn("error:", err.getvalue())
