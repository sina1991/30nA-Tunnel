"""Validate generated configuration with the installed OpenSSH and systemd parsers."""
from pathlib import Path
from unittest.mock import patch
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import manager as m


@unittest.skipUnless(shutil.which("sshd"), "OpenSSH server required")
class ConfigTests(unittest.TestCase):
    def test_generated_forward_and_reverse_sshd_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            host=root/"host"
            subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(host)],check=True)
            state=dict(servers={"1":{"host":"localhost"},"2":{"host":"localhost"}},tunnels={})
            for kind in ("Forward","Reverse"):
                tunnel=dict(local_id="1",remote_id="2",kind=kind,account="nt-config",
                            bind="0.0.0.0",listen=6677,target=443)
                def execute(endpoint,args,**kwargs):
                    if args[0]=="cat":
                        return subprocess.CompletedProcess(args,0,host.with_suffix(".pub").read_bytes(),b"")
                    if args[0]=="hostname":
                        return subprocess.CompletedProcess(args,0,b"127.0.0.1",b"")
                    if args[0]=="sh" and "ssh-keygen" in args[2]:
                        return subprocess.CompletedProcess(args,0,host.with_suffix(".pub").read_bytes(),b"")
                    if args[0]=="/usr/sbin/sshd":
                        command=[shutil.which("sshd"),"-f",str(root/"sshd.conf"),*args[1:]]
                        return subprocess.run(command,check=True,capture_output=True)
                    return subprocess.CompletedProcess(args,0,b"",b"")
                def write(endpoint,path,content,mode="0600"):
                    if path.endswith(".conf"):
                        (root/"sshd.conf").write_text(f"HostKey {host}\nUsePAM no\n"+content)
                with patch.object(m,"execute",side_effect=execute),patch.object(m,"write_remote",side_effect=write),patch.object(m,"save"):
                    m.provision(state,tunnel)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd parser required")
    def test_generated_systemd_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            state=dict(servers={"1":{"host":"localhost"},"2":{"host":"localhost"}})
            tunnel=dict(local_id="1",remote_id="2",kind="Reverse",account="nt-config",
                        bind="0.0.0.0",listen=6677,target=443)
            unit=Path(directory)/"nt-config.service"
            unit.write_text(m.service_definition(state,tunnel))
            subprocess.run(["systemd-analyze","verify",str(unit)],check=True,capture_output=True)
            tunnel["temporary"]=True
            unit.write_text(m.service_definition(state,tunnel))
            self.assertIn("Restart=no",unit.read_text())
            self.assertIn("RuntimeMaxSec=60",unit.read_text())
            subprocess.run(["systemd-analyze","verify",str(unit)],check=True,capture_output=True)


if __name__=="__main__":
    unittest.main()
