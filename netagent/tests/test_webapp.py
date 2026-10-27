import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from netagent import webapp
    from netagent.webapp import BackupRequest, DiscoverRequest
    from fastapi import HTTPException
except ImportError:
    webapp = None


@unittest.skipIf(webapp is None, "install optional web dependencies with pip install -e '.[web]'")
class TestWebApp(unittest.TestCase):
    def test_health_is_read_only(self):
        self.assertEqual(webapp.health()["status"], "ok")

    def test_inventory_options_are_project_relative(self):
        result = webapp.inventories()
        self.assertTrue(any(item["id"] == "examples/inventory.json" for item in result["items"]))

    def test_summary_reads_inventory_without_network_access(self):
        with patch.object(webapp, "DATA_DIR", Path(tempfile.mkdtemp())):
            result = webapp.summary("examples/mikrotik-inventory.json")
        self.assertEqual(result["device_count"], 1)
        self.assertEqual(result["devices"][0]["hostname"], "mikrotik-28-222")

    def test_operator_actions_fail_closed_without_token(self):
        with patch.dict(os.environ, {"NETAGENT_WEB_TOKEN": ""}, clear=False):
            with self.assertRaises(HTTPException) as error:
                webapp._require_operator_token("anything")
        self.assertEqual(error.exception.status_code, 503)

    def test_operator_token_must_match(self):
        with patch.dict(os.environ, {"NETAGENT_WEB_TOKEN": "test-token-long-enough-123456"}, clear=False):
            with self.assertRaises(HTTPException) as error:
                webapp._require_operator_token("wrong-token")
        self.assertEqual(error.exception.status_code, 401)
        with patch.dict(os.environ, {"NETAGENT_WEB_TOKEN": "test-token-long-enough-123456"}, clear=False):
            self.assertIsNone(webapp._require_operator_token("test-token-long-enough-123456"))

    def test_discovery_uses_mocked_core_and_never_scans_in_test(self):
        class Host:
            ip = "192.0.2.1"
            hostname = "synthetic-device"
            open_ports = [22]
            os_guess = "fixture"
            services = []
            guessed_role = "router"

        with patch.object(webapp, "discover", return_value=[Host()]) as discover:
            result = webapp.run_discovery(DiscoverRequest(cidr="192.0.2.0/30"))
        discover.assert_called_once_with("192.0.2.0/30")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["hosts"][0]["ip"], "192.0.2.1")

    def test_backup_uses_mocked_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(webapp, "DATA_DIR", root), patch.object(
                webapp, "fetch", return_value={"config": "synthetic config\n"}
            ) as fetch:
                result = webapp.run_backup(BackupRequest(
                    inventory="examples/mikrotik-inventory.json",
                    device="mikrotik-28-222",
                    username="fixture-user",
                    password="fixture-password",
                ))
            fetch.assert_called_once()
            self.assertTrue(result["ok"])
            self.assertTrue((root / "configs" / "mikrotik-28-222" / "latest.cfg").is_file())


if __name__ == "__main__":
    unittest.main()
