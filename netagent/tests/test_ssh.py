import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from netagent.credentials import Credential
from netagent.models import Device
from netagent.ssh import connection_params, known_hosts_path, trust_host_key


class FakeKey:
    def __init__(self, raw=b"synthetic-public-key", name="ssh-ed25519"):
        self.raw = raw
        self.name = name

    def get_name(self):
        return self.name

    def asbytes(self):
        return self.raw


class FakeHostKeys(dict):
    last_saved = None

    def load(self, filename):
        return None

    def lookup(self, hostname):
        return self.get(hostname)

    def add(self, hostname, keytype, key):
        self.setdefault(hostname, {})[keytype] = key

    def save(self, filename):
        type(self).last_saved = (filename, dict(self))
        Path(filename).write_text("# mocked known_hosts write\n", encoding="utf-8")


class FakeTransport:
    def __init__(self, address):
        self.address = address
        self.closed = False

    def start_client(self, timeout=10):
        return None

    def get_remote_server_key(self):
        return FakeKey()

    def close(self):
        self.closed = True


class TestSSHTrust(unittest.TestCase):
    def setUp(self):
        self.device = Device("lab-router", "192.0.2.25", "mikrotik_routeros")
        self.cred = Credential("operator", "fixture-password")
        self.temp = tempfile.TemporaryDirectory()
        self.known_hosts = Path(self.temp.name) / "known_hosts"
        FakeHostKeys.last_saved = None

    def tearDown(self):
        self.temp.cleanup()

    def test_connection_params_enforce_strict_host_key_checking(self):
        params = connection_params(self.device, self.cred, known_hosts=self.known_hosts)
        self.assertIs(params["ssh_strict"], True)
        self.assertIs(params["system_host_keys"], False)
        self.assertIs(params["alt_host_keys"], True)
        self.assertEqual(params["alt_key_file"], str(self.known_hosts.resolve()))
        self.assertTrue(self.known_hosts.exists())

    def test_known_hosts_path_supports_environment_override(self):
        with patch.dict(os.environ, {"NETAGENT_KNOWN_HOSTS": str(self.known_hosts)}):
            self.assertEqual(known_hosts_path(), self.known_hosts.resolve())

    def test_tofu_requires_exact_fingerprint_and_saves_only_after_confirmation(self):
        fake_paramiko = ModuleType("paramiko")
        fake_paramiko.HostKeys = FakeHostKeys
        fake_paramiko.Transport = FakeTransport
        key = FakeKey()
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        fingerprint = f"SHA256:{digest}"
        with patch.dict("sys.modules", {"paramiko": fake_paramiko}):
            with self.assertRaisesRegex(RuntimeError, "did not match"):
                trust_host_key(self.device, self.known_hosts, input_fn=lambda _: "wrong", output_fn=lambda _: None)
            self.assertIsNone(FakeHostKeys.last_saved)
            result = trust_host_key(self.device, self.known_hosts, input_fn=lambda _: fingerprint, output_fn=lambda _: None)
        self.assertIn("Trusted SSH host key", result)
        self.assertEqual(FakeHostKeys.last_saved[1]["192.0.2.25"]["ssh-ed25519"].asbytes(), key.asbytes())

    def test_nonstandard_port_uses_known_hosts_bracket_format(self):
        device = Device("lab-router-alt", "192.0.2.25", "mikrotik_routeros", port=2222)
        fake_paramiko = ModuleType("paramiko")
        fake_paramiko.HostKeys = FakeHostKeys
        fake_paramiko.Transport = FakeTransport
        digest = base64.b64encode(hashlib.sha256(FakeKey().asbytes()).digest()).decode().rstrip("=")
        with patch.dict("sys.modules", {"paramiko": fake_paramiko}):
            trust_host_key(device, self.known_hosts, input_fn=lambda _: f"SHA256:{digest}", output_fn=lambda _: None)
        self.assertIn("[192.0.2.25]:2222", FakeHostKeys.last_saved[1])


if __name__ == "__main__":
    unittest.main()
