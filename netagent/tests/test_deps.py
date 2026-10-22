import contextlib
import io
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from netagent import deps


def _run_ok(command, check=False):
    return subprocess.CompletedProcess(command, 0)


class ConfirmTests(unittest.TestCase):
    def test_no_terminal_means_no_without_prompting(self):
        with patch("netagent.deps._interactive", return_value=False), \
             patch("builtins.input") as ask:
            self.assertFalse(deps.confirm("install?"))
        ask.assert_not_called()

    def test_only_yes_answers_accept(self):
        for answer, expected in (("y", True), ("YES", True), (" yes ", True),
                                 ("", False), ("n", False), ("sure", False)):
            with patch("netagent.deps._interactive", return_value=True), \
                 patch("builtins.input", return_value=answer), \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(deps.confirm("install?"), expected, answer)

    def test_eof_means_no(self):
        with patch("netagent.deps._interactive", return_value=True), \
             patch("builtins.input", side_effect=EOFError), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(deps.confirm("install?"))

    def test_env_var_disables_prompts(self):
        with patch.dict("os.environ", {"NETAGENT_NO_INSTALL": "1"}), \
             patch("netagent.deps.sys.stdin.isatty", return_value=True), \
             patch("netagent.deps.sys.stderr.isatty", return_value=True):
            self.assertFalse(deps._interactive())


class NmapTests(unittest.TestCase):
    def setUp(self):
        deps._declined.clear()

    def test_installed_nmap_is_returned_without_asking(self):
        ask, run = MagicMock(), MagicMock()
        with patch("netagent.deps.shutil.which", return_value="/usr/bin/nmap"):
            self.assertEqual(deps.ensure_nmap(ask, run), "/usr/bin/nmap")
        ask.assert_not_called()
        run.assert_not_called()

    def test_declined_install_runs_nothing_and_is_not_asked_twice(self):
        ask, run = MagicMock(return_value=False), MagicMock()
        with patch("netagent.deps.find_nmap", return_value=None), \
             patch("netagent.deps.nmap_install_command", return_value=["pkg", "install", "nmap"]):
            self.assertIsNone(deps.ensure_nmap(ask, run))
            self.assertIsNone(deps.ensure_nmap(ask, run))
        ask.assert_called_once()
        self.assertIn("pkg install nmap", ask.call_args.args[0])
        run.assert_not_called()

    def test_consented_install_runs_exact_command_then_finds_nmap(self):
        run = MagicMock(side_effect=_run_ok)
        with patch("netagent.deps.find_nmap", side_effect=[None, "/opt/nmap"]), \
             patch("netagent.deps.nmap_install_command", return_value=["pkg", "install", "nmap"]):
            self.assertEqual(deps.ensure_nmap(lambda q: True, run), "/opt/nmap")
        run.assert_called_once_with(["pkg", "install", "nmap"], check=False)

    def test_failed_install_returns_none(self):
        run = MagicMock(return_value=subprocess.CompletedProcess([], 1))
        with patch("netagent.deps.find_nmap", return_value=None), \
             patch("netagent.deps.nmap_install_command", return_value=["pkg", "install", "nmap"]):
            self.assertIsNone(deps.ensure_nmap(lambda q: True, run))

    def test_install_command_that_cannot_start_returns_none(self):
        run = MagicMock(side_effect=FileNotFoundError)
        with patch("netagent.deps.find_nmap", return_value=None), \
             patch("netagent.deps.nmap_install_command", return_value=["pkg", "install", "nmap"]):
            self.assertIsNone(deps.ensure_nmap(lambda q: True, run))

    def test_no_package_manager_returns_none_without_asking(self):
        ask = MagicMock()
        with patch("netagent.deps.find_nmap", return_value=None), \
             patch("netagent.deps.nmap_install_command", return_value=None):
            self.assertIsNone(deps.ensure_nmap(ask, MagicMock()))
        ask.assert_not_called()

    def test_install_commands_per_platform_use_package_managers_only(self):
        def which(names):
            return lambda name: f"/bin/{name}" if name in names else None

        with patch("netagent.deps.sys.platform", "win32"), \
             patch("netagent.deps.shutil.which", which({"winget"})):
            self.assertEqual(deps.nmap_install_command(),
                             ["winget", "install", "--id", "Insecure.Nmap", "--exact"])
        with patch("netagent.deps.sys.platform", "win32"), \
             patch("netagent.deps.shutil.which", which(set())):
            self.assertIsNone(deps.nmap_install_command())
        with patch("netagent.deps.sys.platform", "darwin"), \
             patch("netagent.deps.shutil.which", which({"brew"})):
            self.assertEqual(deps.nmap_install_command(), ["brew", "install", "nmap"])
        with patch("netagent.deps.sys.platform", "linux"), \
             patch("netagent.deps.os.geteuid", return_value=0, create=True), \
             patch("netagent.deps.shutil.which", which({"apt-get"})):
            self.assertEqual(deps.nmap_install_command(), ["apt-get", "install", "-y", "nmap"])
        with patch("netagent.deps.sys.platform", "linux"), \
             patch("netagent.deps.os.geteuid", return_value=1000, create=True), \
             patch("netagent.deps.shutil.which", which({"sudo", "dnf"})):
            self.assertEqual(deps.nmap_install_command(), ["sudo", "dnf", "install", "-y", "nmap"])
        with patch("netagent.deps.sys.platform", "linux"), \
             patch("netagent.deps.os.geteuid", return_value=1000, create=True), \
             patch("netagent.deps.shutil.which", which({"apt-get"})):
            self.assertIsNone(deps.nmap_install_command())  # not root and no sudo


class NetmikoTests(unittest.TestCase):
    def setUp(self):
        deps._declined.clear()

    def test_present_package_needs_no_prompt(self):
        ask = MagicMock()
        with patch("netagent.deps.importlib.util.find_spec", return_value=object()):
            self.assertTrue(deps.ensure_netmiko(ask, MagicMock()))
        ask.assert_not_called()

    def test_declined_install_runs_nothing(self):
        run = MagicMock()
        with patch("netagent.deps.importlib.util.find_spec", return_value=None):
            self.assertFalse(deps.ensure_netmiko(lambda q: False, run))
        run.assert_not_called()

    def test_consented_install_uses_this_interpreters_pip(self):
        run = MagicMock(side_effect=_run_ok)
        with patch("netagent.deps.importlib.util.find_spec", side_effect=[None, object()]):
            self.assertTrue(deps.ensure_netmiko(lambda q: True, run))
        command = run.call_args.args[0]
        self.assertEqual(command[1:], ["-m", "pip", "install", deps.NETMIKO_REQUIREMENT])
        self.assertEqual(command[0], deps.sys.executable)

    def test_failed_pip_install_returns_false(self):
        run = MagicMock(return_value=subprocess.CompletedProcess([], 1))
        with patch("netagent.deps.importlib.util.find_spec", return_value=None):
            self.assertFalse(deps.ensure_netmiko(lambda q: True, run))


class IntegrationTests(unittest.TestCase):
    def test_nmap_scan_offers_install_when_missing(self):
        from netagent import discovery

        with patch("netagent.discovery.shutil.which", return_value=None), \
             patch("netagent.discovery.ensure_nmap", return_value=None) as ensure:
            with self.assertRaises(FileNotFoundError):
                discovery.nmap_scan("192.0.2.0/30")
        ensure.assert_called_once()


if __name__ == "__main__":
    unittest.main()
