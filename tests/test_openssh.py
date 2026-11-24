"""Real OpenSSH data-plane tests on loopback.

Systemd is represented by a process supervisor because CI may lack systemd.
Host account creation is represented by restricted keys for the current user.
SSH authentication, -L/-R, host-key pinning, TCP traffic and port release are real.
"""
from contextlib import ExitStack
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
import getpass
import os
import shutil
import shlex
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import manager as m


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1",0))
        return stream.getsockname()[1]


def wait_for(predicate, timeout=5):
    limit = time.monotonic() + timeout
    while time.monotonic() < limit:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out")


def result(value="",code=0):
    return CompletedProcess([],code,value.encode(),b"")


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(8192)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@unittest.skipUnless(shutil.which("sshd") and shutil.which("ssh") and shutil.which("ss"),
                     "OpenSSH and iproute2 are required")
class OpenSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.daemons = []
        self.services = {}
        self.streams = []
        self.stack = ExitStack()
        self.addCleanup(self.close)
        self.user = getpass.getuser()
        self.key = self.base/"admin"
        subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(self.key)],check=True)
        self.servers = {}
        for sid in ("1","2","3"):
            directory = self.base/sid
            directory.mkdir()
            host = directory/"host"
            subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(host)],check=True)
            (directory/"authorized").write_bytes(self.key.with_suffix(".pub").read_bytes())
            port = free_port()
            config=directory/"sshd.conf"
            config.write_text(
                f"Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\n"
                f"AuthorizedKeysFile {directory}/authorized\nStrictModes no\n"
                "UsePAM no\nPasswordAuthentication no\nPermitRootLogin yes\n"
                "GatewayPorts clientspecified\nAllowTcpForwarding yes\n")
            stream=(directory/"sshd.log").open("wb")
            self.streams.append(stream)
            daemon=subprocess.Popen([shutil.which("sshd"),"-De","-f",str(config)],stderr=stream)
            self.daemons.append(daemon)
            wait_for(lambda: self.can_connect(port) or daemon.poll() is not None)
            if daemon.poll() is not None:
                self.fail((directory/"sshd.log").read_text())
            self.servers[sid]=dict(host="127.0.0.1",user=self.user,ssh_port=port,label=sid)
        self.known = self.base/"known"
        self.known.write_text("".join(f"[127.0.0.1]:{endpoint['ssh_port']} "
                    + " ".join((self.base/sid/"host.pub").read_text().split()[:2])+"\n"
                    for sid,endpoint in self.servers.items()))
        self.state=dict(schema=1,local_id="1",servers=self.servers,tunnels={},checks={})
        self.echo=EchoServer(("127.0.0.1",0),Echo)
        self.thread=threading.Thread(target=self.echo.serve_forever,daemon=True)
        self.thread.start()
        self.target=self.echo.server_address[1]
        self.stack.enter_context(patch.object(m,"BASE",self.base))
        self.stack.enter_context(patch.object(m,"DATA",self.base/"data"))
        self.stack.enter_context(patch.object(m,"STATE",self.base/"data/state.json"))
        self.real_execute=m.execute
        self.real_command=m.tunnel_command
        self.stack.enter_context(patch.object(m,"execute",side_effect=self.execute))
        self.stack.enter_context(patch.object(m,"provision",side_effect=self.provision))
        self.stack.enter_context(patch.object(m,"tunnel_command",side_effect=self.command))
        self.stack.enter_context(patch.object(m,"confirm_distinct"))
        (self.base/"data").mkdir()

    @staticmethod
    def can_connect(port):
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.2):
                return True
        except OSError:
            return False

    def close(self):
        for process,stream in self.services.values():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            stream.close()
        for process in self.daemons:
            process.terminate()
            process.wait(timeout=5)
        if hasattr(self,"echo"):
            self.echo.shutdown()
            self.echo.server_close()
        self.stack.close()
        for stream in self.streams:
            stream.close()

    def command(self,state,tunnel):
        command=self.real_command(state,tunnel)
        command[1:1]=["-F","/dev/null"]
        _,server=m.participants(state,tunnel)
        command[-1]=f"{self.user}@{server['host']}"
        return command

    def provision(self,state,tunnel):
        _,server=m.participants(state,tunnel)
        key=self.base/"data"/(tunnel["account"]+".key")
        subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(key)],check=True)
        known = key.with_suffix(".key.hosts")
        known.write_text(f"[127.0.0.1]:{server['ssh_port']} "
            + " ".join((self.base/server["label"]/"host.pub").read_text().split()[:2])+"\n")
        if tunnel["kind"]=="Reverse":
            restriction=f'permitlisten="{tunnel["bind"]}:{tunnel["listen"]}"'
        else:
            restriction=f'permitopen="127.0.0.1:{tunnel["target"]}"'
        with (self.base/server["label"]/"authorized").open("a") as stream:
            stream.write(f"restrict,port-forwarding,{restriction} "+key.with_suffix(".key.pub").read_text())

    def execute(self,endpoint,args,**kwargs):
        args=list(map(str,args))
        check=kwargs.get("check",True)
        if args[0]=="systemctl":
            action=args[1]
            unit=args[-1]
            service=self.services.get(unit)
            if action=="daemon-reload" or action=="reload":
                return result()
            if action=="show":
                return result("loaded" if (self.base/unit).exists() else "not-found")
            if action=="is-active":
                return result("active" if service and service[0].poll() is None else "inactive",0 if service and service[0].poll() is None else 3)
            if action in ("enable","start"):
                line=next(line for line in (self.base/unit).read_text().splitlines() if line.startswith("ExecStart="))
                stream=(self.base/(unit+".log")).open("wb")
                process=subprocess.Popen(shlex.split(line.partition("=")[2]),stderr=stream)
                self.services[unit]=(process,stream)
                return result()
            if action=="disable":
                if service and service[0].poll() is None:
                    service[0].terminate()
                    service[0].wait(timeout=5)
                return result()
        if args[0]=="rm" and "/etc/systemd/system/" in args[-1]:
            args[-1]=str(self.base/Path(args[-1]).name)
        if args[0]=="rm" and "/etc/ssh/" in " ".join(args):
            return result()
        if args[0]=="id":
            return result("",1)
        if args[0]=="/usr/sbin/sshd":
            return result()
        if args[0]=="journalctl":
            unit=args[args.index("-u")+1]
            return result((self.base/(unit+".log")).read_text())
        if args[0]=="sh" and kwargs.get("data") and "ExecStart=" in kwargs["data"].decode():
            # write_remote receives the path as the penultimate argument.
            path=self.base/Path(args[-2]).name
            path.write_bytes(kwargs["data"])
            return result()
        # All other commands cross a real authenticated SSH connection.
        ssh=["ssh","-F","/dev/null",*m.SSH_OPTIONS,"-i",str(self.key),
             "-o","IdentitiesOnly=yes","-o",f"UserKnownHostsFile={self.known}",
             "-p",str(endpoint["ssh_port"]),f"{self.user}@127.0.0.1",shlex.join(args)]
        return m.run(ssh,**kwargs)

    def echo_through(self,port):
        with socket.create_connection(("127.0.0.1",port),timeout=3) as connection:
            message=os.urandom(4096)
            connection.sendall(message)
            received=b""
            while len(received)<len(message):
                received+=connection.recv(8192)
            self.assertEqual(received,message)

    def exercise(self,kind,local="1",remote="2"):
        port=free_port()
        tid=m.new_tunnel(self.state,local,remote,port,self.target,kind)
        self.echo_through(port)
        self.assertTrue(m.passed(m.test_tunnel(self.state,tid)))
        m.remove_tunnel(self.state,tid)
        self.assertTrue(m.port_status(self.servers[local],port)["free"])
        self.assertNotIn(tid,m.load()["tunnels"])
        return port

    def test_forward_payload_health_delete_and_reuse(self):
        port=self.exercise("Forward")
        tid=m.new_tunnel(self.state,"1","2",port,self.target,"Reverse")
        self.echo_through(port)
        m.remove_tunnel(self.state,tid)
        self.assertTrue(m.port_status(self.servers["1"],port)["free"])

    def test_reverse_payload_health_delete_and_reuse(self):
        port=self.exercise("Reverse")
        tid=m.new_tunnel(self.state,"1","2",port,self.target,"Forward")
        self.echo_through(port)
        m.remove_tunnel(self.state,tid)

    def test_peer_to_peer_forward(self):
        self.exercise("Forward","2","3")

    def test_peer_to_peer_reverse(self):
        self.exercise("Reverse","3","2")

    def test_all_active_tunnels(self):
        for kind in ("Forward","Reverse"):
            m.new_tunnel(self.state,"1","2",free_port(),self.target,kind)
        self.assertTrue(m.test_all(self.state,active_only=True))
        for tid in list(self.state["tunnels"]):
            m.remove_tunnel(self.state,tid)

    def test_unrelated_occupied_port_is_preserved(self):
        with self.assertRaisesRegex(ValueError,"occupied"):
            m.new_tunnel(self.state,"1","2",self.target,443,"Reverse")
        self.assertTrue(self.can_connect(self.target))
        self.assertFalse(self.state["tunnels"])

    def test_stopped_target_fails_tcp_health(self):
        tid=m.new_tunnel(self.state,"1","2",free_port(),free_port(),"Reverse")
        result=m.test_tunnel(self.state,tid)
        self.assertTrue(result["listener"])
        self.assertFalse(result["tcp"])
        m.remove_tunnel(self.state,tid)

    def test_ssh_process_restart_keeps_tunnel_config(self):
        tid=m.new_tunnel(self.state,"1","2",free_port(),self.target,"Reverse")
        tunnel=self.state["tunnels"][tid]
        m.unit_action(self.state,tunnel,["disable","--now"])
        m.wait_port_free(self.servers["1"],tunnel)
        old=self.services.pop(tunnel["unit"])
        old[1].close()
        m.unit_action(self.state,tunnel,["enable","--now"])
        wait_for(lambda:self.can_connect(tunnel["listen"]))
        self.echo_through(tunnel["listen"])
        m.remove_tunnel(self.state,tid)


if __name__=="__main__":
    unittest.main()
