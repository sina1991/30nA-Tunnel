"""Deterministic regression tests. No host services or accounts are modified."""
from contextlib import contextmanager
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import manager as m


def response(value="", code=0):
    return CompletedProcess([], code, value.encode(), b"")


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        for name, value in (("DATA", self.data), ("STATE", self.data / "state.json")):
            patched = patch.object(m, name, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.state = dict(schema=1, local_id="1", servers={
            "1": dict(host="91.216.217.244", user="root", dashboard=True),
            "2": dict(host="uk5.30na.top", user="root"),
            "3": dict(host="gr02.30na.top", user="root")}, tunnels={}, checks={})

    def tunnel(self, kind="Reverse", local="1", remote="2"):
        return dict(local_id=local, remote_id=remote, kind=kind, listen=6677,
                    target=443, bind="0.0.0.0", unit="nt-example.service",
                    account="nt-example", phase="ready")

    def test_migrate_legacy_forward_and_reverse(self):
        (self.data / "servers.db").write_text("2|uk5.30na.top|root\n3|gr02.30na.top|root\n")
        (self.data / "tunnels.db").write_text("1|443|2|443|443|0.0.0.0\n")
        (self.data / "reverse.json").write_text(json.dumps({
            "4": dict(server="3", kind="Reverse", listen=6677, target=443,
                      bind="0.0.0.0", account="stm-r-old")}))
        with patch.object(m, "host_address", return_value="91.216.217.244"):
            state = m.load()
        self.assertEqual(state["local_id"], "1")
        self.assertEqual(state["tunnels"]["1"]["unit"], "ssh-tunnel-1.service")
        self.assertEqual(state["tunnels"]["4"]["unit"], "stm-r-old.service")
        self.assertEqual(m.load(), state)
        self.assertEqual((self.data / "tunnels.db").read_text(), "1|443|2|443|443|0.0.0.0\n")

    def test_migrate_pairs_with_dashboard_as_target(self):
        (self.data / "servers.db").write_text("1|uk5.30na.top|root\n")
        (self.data / "pairs.json").write_text(json.dumps({
            "7": dict(server=None, local_id="1", dashboard_target={"host":"91.216.217.244"},
                      kind="Forward", listen=6677, target=443, bind="0.0.0.0", account="stm-r-pair")}))
        with patch.object(m, "host_address", return_value="91.216.217.244"):
            state = m.load()
        self.assertEqual(state["local_id"], "2")
        self.assertEqual(state["tunnels"]["7"]["remote_id"], "2")
        self.assertEqual(state["tunnels"]["7"]["local_id"], "1")

    def test_failed_import_keeps_original_files(self):
        (self.data / "servers.db").write_text("invalid")
        with self.assertRaises(ValueError):
            m.load()
        self.assertFalse(m.STATE.exists())
        self.assertEqual((self.data / "servers.db").read_text(), "invalid")

    def test_atomic_write_permissions_and_replace(self):
        m.save(self.state)
        self.assertEqual(os.stat(m.STATE).st_mode & 0o777, 0o600)
        self.state["sequence"] = 12
        m.save(self.state)
        self.assertEqual(m.load()["sequence"], 12)
        self.assertEqual(list(self.data.glob("state.json.*")), [])

    def test_both_directions_and_all_endpoint_orders(self):
        for kind, local, remote in [("Forward","1","2"), ("Reverse","1","2"),
                                    ("Forward","2","3"), ("Reverse","3","2"),
                                    ("Forward","2","1"), ("Reverse","2","1")]:
            tunnel = self.tunnel(kind, local, remote)
            client, server = m.participants(self.state, tunnel)
            expected = (local, remote) if kind == "Forward" else (remote, local)
            self.assertIs(client, self.state["servers"][expected[0]])
            self.assertIs(server, self.state["servers"][expected[1]])

    def test_command_has_pinned_key_and_keepalive(self):
        for kind, flag in (("Forward","-L"), ("Reverse","-R")):
            command = m.tunnel_command(self.state, self.tunnel(kind))
            self.assertIn(flag, command)
            self.assertIn("0.0.0.0:6677:127.0.0.1:443", command)
            self.assertIn("ExitOnForwardFailure=yes", command)
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("IdentitiesOnly=yes", command)

    def test_custom_ssh_port(self):
        self.state["servers"]["2"]["ssh_port"] = 2222
        command = m.tunnel_command(self.state, self.tunnel("Forward"))
        self.assertEqual(command[command.index("-p")+1], "2222")

    def test_service_has_control_group_shutdown(self):
        definition = m.service_definition(self.state, self.tunnel())
        self.assertIn("KillMode=control-group", definition)
        self.assertIn("Restart=always", definition)

    def test_occupied_port_reports_owner_without_changes(self):
        self.state["tunnels"] = {}
        with patch.object(m, "confirm_distinct"), patch.object(m, "port_status",
                return_value={"free":False,"detail":"in use"}), patch.object(m, "listeners",
                return_value='users:(("ssh",pid=100))'), patch.object(m,"provision") as provision:
            with self.assertRaisesRegex(ValueError, "pid=100"):
                m.new_tunnel(self.state, "1", "2", 6677, 443, "Reverse")
        provision.assert_not_called()
        self.assertFalse(m.STATE.exists())

    def test_duplicate_managed_port_reports_id(self):
        self.state["tunnels"]["4"] = self.tunnel()
        with patch.object(m, "confirm_distinct"):
            with self.assertRaisesRegex(ValueError, "tunnel 4"):
                m.new_tunnel(self.state, "1", "2", 6677, 443, "Forward")

    def test_other_local_vps_can_use_same_port(self):
        self.state["tunnels"]["4"] = self.tunnel()
        with patch.object(m, "confirm_distinct"), patch.object(m, "ensure_free"), patch.object(m, "start_tunnel"):
            tid = m.new_tunnel(self.state, "3", "2", 6677, 443, "Forward")
        self.assertEqual(tid, "5")

    def test_invalid_mode_port_and_identical_endpoint(self):
        for args in [("1","2",0,443,"Forward"), ("1","2",12,443,"Bad"), ("1","1",12,443,"Reverse")]:
            with self.assertRaises(ValueError):
                m.new_tunnel(self.state, *args)

    def test_provision_creates_directory_before_writing_key(self):
        calls = []
        def execute(endpoint, args, **kwargs):
            calls.append((endpoint, args))
            if "ssh_host_ed25519_key.pub" in " ".join(args):
                return response("ssh-ed25519 AAAA host")
            if "ssh-keygen" in " ".join(args):
                return response("ssh-ed25519 AAAA client")
            if "-T" in args:
                return response("maxsessions 0\ndisableforwarding no\npubkeyauthentication yes\n"
                    "authorizedkeysfile /etc/ssh/nt-example.keys\nauthenticationmethods publickey\n"
                    "gatewayports clientspecified\nallowtcpforwarding remote\npermitlisten 0.0.0.0:6677")
            if args == ["hostname", "-I"]:
                return response("178.83.45.184")
            return response()
        with patch.object(m,"execute",side_effect=execute):
            m.provision(self.state, self.tunnel())
        self.assertEqual(calls[0][1][:4], ["install","-d","-m","0700"])
        self.assertIs(calls[0][0], self.state["servers"]["2"])
        self.assertIs(calls[2][0], self.state["servers"]["1"])

    def test_failed_create_rolls_back(self):
        with patch.object(m,"confirm_distinct"), patch.object(m,"ensure_free"),              patch.object(m,"start_tunnel",side_effect=RuntimeError("SSH rejected")),              patch.object(m,"remove_tunnel",side_effect=lambda state, tid: state["tunnels"].pop(tid)) as remove:
            with self.assertRaisesRegex(RuntimeError,"rolled back"):
                m.new_tunnel(self.state,"1","2",6677,443,"Reverse")
        remove.assert_called_once()
        self.assertFalse(self.state["tunnels"])

    def test_cleanup_failure_keeps_record_and_sequence(self):
        with patch.object(m,"confirm_distinct"), patch.object(m,"ensure_free"),              patch.object(m,"start_tunnel",side_effect=RuntimeError("setup")),              patch.object(m,"remove_tunnel",side_effect=RuntimeError("peer offline")):
            with self.assertRaisesRegex(RuntimeError,"Cleanup pending"):
                m.new_tunnel(self.state,"1","2",6677,443,"Reverse")
        self.assertEqual(m.load()["tunnels"]["1"]["phase"],"cleanup")
        self.assertEqual(m.load()["sequence"],1)

    def test_delete_stops_service_then_checks_port_then_removes_files(self):
        tunnel = self.tunnel()
        self.state["tunnels"]["4"] = tunnel
        events = []
        def execute(endpoint, args, **kwargs):
            events.append(args)
            if "LoadState" in args:
                return response("loaded")
            if "is-active" in args:
                return response("inactive",3)
            if args[0] == "id":
                return response("",1)
            return response()
        with patch.object(m,"execute",side_effect=execute), patch.object(m,"wait_port_free",
                side_effect=lambda *args:events.append(["PORT_FREE"])):
            m.remove_tunnel(self.state,"4")
        stop = next(i for i,args in enumerate(events) if "--now" in args)
        free = events.index(["PORT_FREE"])
        delete = next(i for i,args in enumerate(events) if args[0]=="rm")
        self.assertLess(stop, free)
        self.assertLess(free, delete)
        self.assertNotIn("4",m.load()["tunnels"])

    def test_delete_failure_keeps_tunnel_and_resources(self):
        self.state["tunnels"]["4"] = self.tunnel()
        with patch.object(m,"execute",return_value=response("not-found")) as execute,              patch.object(m,"wait_port_free",side_effect=RuntimeError("still occupied")):
            with self.assertRaisesRegex(RuntimeError,"still occupied"):
                m.remove_tunnel(self.state,"4")
        self.assertEqual(m.load()["tunnels"]["4"]["phase"],"deleting")
        self.assertFalse(any(call.args[1][0]=="rm" for call in execute.call_args_list))

    def test_delete_retry_when_unit_already_gone(self):
        self.state["tunnels"]["4"] = self.tunnel()
        with patch.object(m,"execute",side_effect=lambda endpoint,args,**kw:
                response("not-found") if "LoadState" in args else response("",1) if args[0]=="id" else response()),              patch.object(m,"wait_port_free"):
            m.remove_tunnel(self.state,"4")
        self.assertFalse(m.load()["tunnels"])

    def test_cascade_matches_both_endpoints(self):
        self.state["tunnels"] = {"1":self.tunnel(local="2",remote="3"),
                                 "2":self.tunnel(local="1",remote="2"),
                                 "3":self.tunnel(local="1",remote="3")}
        with patch.object(m,"remove_tunnel",side_effect=lambda state,tid:state["tunnels"].pop(tid)) as remove:
            m.remove_server(self.state,"2")
        self.assertEqual([call.args[1] for call in remove.call_args_list],["1","2"])
        self.assertEqual(set(m.load()["tunnels"]),{"3"})

    def test_cascade_failure_retains_vps(self):
        self.state["tunnels"]["4"] = self.tunnel()
        with patch.object(m,"remove_tunnel",side_effect=RuntimeError("peer offline")):
            with self.assertRaisesRegex(RuntimeError,"VPS retained"):
                m.remove_server(self.state,"2")
        self.assertIn("2",self.state["servers"])

    def test_dashboard_cannot_be_deleted(self):
        with self.assertRaisesRegex(ValueError,"cannot be removed"):
            m.remove_server(self.state,"1")

    def test_all_tests_continue_after_failure_and_persist(self):
        self.state["tunnels"] = {"1":self.tunnel("Forward"),"2":self.tunnel(),"3":self.tunnel()}
        with patch.object(m,"service_state",return_value="UP"), patch.object(m,"execute",
                side_effect=[RuntimeError("offline"), response(), response(), response(), response()]),              patch.object(m,"listener_matches",return_value=True), patch.object(m,"tcp_path",return_value=True):
            self.assertFalse(m.test_all(self.state))
        self.assertFalse(m.load()["checks"]["1"]["ssh"])
        self.assertTrue(m.load()["checks"]["3"]["tcp"])

    def test_active_tests_skip_down_and_report_unknown(self):
        self.state["tunnels"] = {str(i):self.tunnel() for i in range(1,4)}
        with patch.object(m,"service_state",side_effect=["UP","DOWN","UNKNOWN"]),              patch.object(m,"test_tunnel",return_value=dict(ssh=True,listener=True,tcp=True)) as check:
            self.assertFalse(m.test_all(self.state,active_only=True))
        self.assertEqual(check.call_count,1)
        self.assertIn("3",m.load()["checks"])

    def test_failed_target_is_not_reported_as_ok(self):
        with patch.object(m,"execute",return_value=response()), patch.object(m,"service_state",return_value="UP"),              patch.object(m,"listener_matches",return_value=True), patch.object(m,"tcp_path",return_value=False):
            self.state["tunnels"]["1"]=self.tunnel()
            self.assertFalse(m.passed(m.test_tunnel(self.state,"1")))

    def test_numbered_selection_reprompts(self):
        with patch("builtins.input",side_effect=["","bad","9","2"]):
            self.assertEqual(m.select_id(self.state["servers"],"VPS"),"2")

    def test_port_default_validation_and_mode(self):
        with patch("builtins.input",side_effect=["","443  "]):
            self.assertEqual(m.input_port("Remote Port",22),22)
            self.assertEqual(m.input_port("Remote Port"),443)
        with patch("builtins.input",side_effect=["0","65536","443"]):
            self.assertEqual(m.input_port("Local Port"),443)
        with patch("builtins.input",side_effect=["","2"]):
            self.assertEqual(m.select_mode(),"Reverse")

    def test_discovery_recovers_unregistered_project_unit(self):
        def execute(endpoint,args,**kwargs):
            if "list-units" in args and endpoint["host"] == "91.216.217.244":
                return response("ssh-tunnel-3.service loaded active running SSH Tunnel")
            if "ExecStart" in args:
                return response("{ path=/usr/bin/ssh ; argv[]=/usr/bin/ssh -N -T -L "
                                "0.0.0.0:6677:127.0.0.1:443 root@uk5.30na.top ; ignore_errors=no ; }")
            return response()
        with patch.object(m,"execute",side_effect=execute), patch.object(m,"same_address",side_effect=lambda a,b:a==b):
            m.discover_services(self.state)
            m.discover_services(self.state)
        self.assertEqual(len(self.state["tunnels"]),1)
        tunnel=next(iter(self.state["tunnels"].values()))
        self.assertEqual(tunnel["unit"],"ssh-tunnel-3.service")
        self.assertEqual(tunnel["listen"],6677)
        self.assertEqual((tunnel["local_id"],tunnel["remote_id"]),("1","2"))

    def test_discovery_never_imports_unrelated_service(self):
        with patch.object(m,"execute",return_value=response("postgres.service loaded active running")):
            m.discover_services(self.state)
        self.assertFalse(self.state["tunnels"])

    def test_temporary_service_expires_and_does_not_restart(self):
        tunnel=dict(self.tunnel(),temporary=True)
        unit=m.service_definition(self.state,tunnel)
        self.assertIn("RuntimeMaxSec=60",unit)
        self.assertIn("Restart=no",unit)

    def test_management_public_key_registration_is_idempotent(self):
        import subprocess
        key=self.data/"key"
        subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(key)],check=True)
        program=m.PUBLIC_REGISTER.replace("/root/.ssh",str(self.data/"ssh"))
        public=key.with_suffix(".pub").read_bytes()
        subprocess.run([sys.executable,"-c",program],input=public,check=True)
        authorized=self.data/"ssh/authorized_keys"
        authorized.write_bytes(b"restrict "+authorized.read_bytes())
        subprocess.run([sys.executable,"-c",program],input=public,check=True)
        self.assertEqual(authorized.read_bytes(),b"restrict "+public)
        self.assertEqual(authorized.stat().st_mode&0o777,0o600)

    def test_fresh_vps_uses_zip_key_and_installs_before_python(self):
        (self.data/"revision").write_text("a"*40)
        (self.data/"install.sh").write_text("# test installer")
        (self.data/"manager.py").write_bytes(b"installed code")
        installed = False
        commands = []
        def execute(endpoint,args,**kwargs):
            nonlocal installed
            commands.append(args)
            if args[0] == "python3" and not installed:
                raise AssertionError("Python requested on a fresh VPS")
            if args[0] == "bash":
                self.assertTrue(endpoint["bootstrap"])
                installed=True
                return response("Installed")
            if args == ["cat","/etc/machine-id"]:
                return response("dashboard" if endpoint.get("dashboard") else "fresh-vps")
            if args == ["cat",str(self.data/"manager.py")]:
                return response("installed code")
            return response()
        def register(endpoint):
            self.assertTrue(installed)
            self.assertTrue(endpoint["bootstrap"])
        with patch.object(m,"BASE",self.data), patch("pathlib.Path.is_file",return_value=True),              patch.object(m,"execute",side_effect=execute), patch.object(m,"run",return_value=response()) as run,              patch.object(m,"register_management",side_effect=register),              patch("builtins.input",side_effect=["178.83.46.45",""]):
            m.enroll_server(self.state)
        initial=run.call_args_list[0].args[0]
        self.assertIn("/root/.ssh/30na_windows",initial)
        self.assertNotIn("/root/.ssh/30na_tunnel_manager",initial)
        self.assertIn("StrictHostKeyChecking=accept-new",initial)
        self.assertIn("root@178.83.46.45",initial)
        self.assertTrue(installed)
        self.assertLess(next(i for i,args in enumerate(commands) if args[0]=="bash"),
                        next(i for i,args in enumerate(commands) if args[0]=="python3"))
        fresh=self.state["servers"]["4"]
        self.assertNotIn("bootstrap",fresh)
        self.assertEqual(fresh["host"],"178.83.46.45")

    def test_failed_bootstrap_does_not_register_vps(self):
        with patch("pathlib.Path.is_file",return_value=True), patch.object(m,"run",
                side_effect=RuntimeError("Connection refused")),              patch("builtins.input",side_effect=["178.83.46.45","22"]):
            with self.assertRaisesRegex(RuntimeError,"Connection refused"):
                m.enroll_server(self.state)
        self.assertEqual(set(self.state["servers"]),{"1","2","3"})

    def test_timeout_does_not_print_remote_program(self):
        import subprocess
        with patch.object(m.subprocess,"run",side_effect=subprocess.TimeoutExpired(["ssh","secret program"],30)):
            with self.assertRaises(RuntimeError) as error:
                m.run(["ssh","secret program"])
        self.assertIn("30 seconds",str(error.exception))
        self.assertNotIn("secret program",str(error.exception))

    def test_menu_has_only_approved_actions(self):
        self.assertIn("3. Tunnel Test",m.MENUS["tunnel"])
        self.assertNotIn("Enable"," ".join(m.MENUS.values()))
        self.assertNotIn("Disable"," ".join(m.MENUS.values()))
        self.assertNotIn("Forward"," ".join(m.MENUS.values()))

    def test_orphan_creation_cleanup_on_restart(self):
        self.state["tunnels"]={"1":self.tunnel(),"2":dict(self.tunnel(),phase="creating"),
                               "3":dict(self.tunnel(),temporary=True)}
        with patch.object(m,"remove_tunnel") as remove:
            m.recover_pending(self.state)
        self.assertEqual([call.args[1] for call in remove.call_args_list],["2","3"])


if __name__ == "__main__":
    unittest.main()
