from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import health
import manager as m


class CommandTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.key = root / "identity"
        self.key.touch()
        for attr, value in (("DATA", root), ("STATE", root / "registry.sqlite3")):
            edit = patch.object(m, attr, value)
            edit.start()
            self.addCleanup(edit.stop)
        self.enter(patch.object(cli.os, "geteuid", return_value=0))
        self.enter(patch.object(m, "local_endpoint", return_value=dict(
            host="127.0.0.1", ip="127.0.0.1", dashboard=True, machine_id="0"*32)))

    def enter(self, edit):
        result = edit.start()
        self.addCleanup(edit.stop)
        return result

    def command(self, line):
        stream = StringIO()
        with redirect_stdout(stream):
            status = cli.main(line.split())
        return status, stream.getvalue()

    def enroll(self):
        with patch.object(m, "endpoint_identity", return_value="1"*32):
            return self.command(f"-vps -add -ip 127.0.0.2 -sshkey {self.key}")

    def test_fresh_reports_are_idempotent_and_plain(self):
        for cmd in ("-vps", "-tunnel", "-vps -tunnel"):
            status, report = self.command(cmd)
            self.assertEqual(status, 0)
            self.assertIn("LOCAL", report)
            self.assertIn("EXAMPLES", report)
            self.assertNotIn("\x1b", report)
        self.assertEqual(list(m.load()["servers"]), ["1"])
        self.assertEqual(m.load()["tunnels"], {})

    def test_enroll_duplicate_remove_by_ip_monotonic_ids(self):
        self.assertIn("registered", self.enroll()[1])
        self.assertIn("already registered", self.enroll()[1])
        self.assertEqual(self.command("-vps -remove -ip 127.0.0.2")[0], 0)
        self.enroll()
        self.assertEqual(set(m.load()["servers"]), {"1", "3"})

    def test_failed_enrollment_leaves_only_local(self):
        with patch.object(m, "endpoint_identity", side_effect=RuntimeError("SSH timed out")):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                self.command(f"-vps -add -ip 127.0.0.2 -sshkey {self.key}")
        self.assertEqual(list(m.load()["servers"]), ["1"])

    def test_tunnel_addresses_and_mode_are_normalized(self):
        self.enroll()
        with patch.object(cli.socket, "gethostbyname", return_value="127.0.0.1"), patch.object(m, "new_tunnel", return_value="5") as create:
            status, output = self.command("-tunnel -add -local iran.example -remote 127.0.0.2 -local-port 18443 -remote-port 443 -mode reverse")
        self.assertEqual(status, 0)
        self.assertIn("Tunnel 5", output)
        self.assertEqual(create.call_args.args[1:], ("1", "2", 18443, 443, "Reverse"))
        self.assertEqual(create.call_args.kwargs["bind"], "127.0.0.1")

    def test_combined_report_checks_remote_only_and_continues_on_failure(self):
        self.enroll()
        with patch.object(m, "execute", side_effect=RuntimeError("SSH timed out")) as run, patch.object(m, "port_status", return_value={"free": True}):
            status, output = self.command("-vps -tunnel")
        run.assert_called_once()
        self.assertEqual(status, 1)
        self.assertIn("SSH timed out", output)
        self.assertIn("TUNNEL TEST", output)
        self.assertIn("EXAMPLES", output)

    def test_active_service_without_listener_is_failed(self):
        state = m.load()
        tunnel = dict(phase="ready", local_id="1", remote_id="1")
        state["tunnels"]["1"] = tunnel
        with patch.object(m, "service_state", return_value="UP"), patch.object(m, "listener_matches", return_value=False):
            status = health.status(state, tunnel)
        self.assertEqual(health.check(state, "1", status)[0], "FAIL")

    def test_help_is_independent_of_registry(self):
        with patch.object(m, "load", side_effect=AssertionError):
            self.assertIn("-sshkey", self.command("-vps -h")[1])
            self.assertIn("-mode", self.command("-tunnel -h")[1])
