import os, unittest
from unittest import mock
from netagent.credentials import Credential, get_credential, redact


class TestCredentials(unittest.TestCase):
    def test_repr_and_str_hide_password(self):
        c = Credential("admin", "S3cr3t!", "en4ble")
        for s in (repr(c), str(c)):
            self.assertNotIn("S3cr3t!", s); self.assertNotIn("en4ble", s)

    def test_redact(self):
        c = Credential("admin", "S3cr3t!", "en4ble")
        self.assertEqual(redact("auth S3cr3t! en4ble", c), "auth *** ***")

    @mock.patch.dict(os.environ, {"NETAGENT_USERNAME": "u", "NETAGENT_PASSWORD": "p"}, clear=True)
    def test_env(self):
        self.assertEqual(get_credential(prompt=False).username, "u")

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_no_prompt_without_env_fails(self):
        with self.assertRaises(RuntimeError):
            get_credential(prompt=False)
