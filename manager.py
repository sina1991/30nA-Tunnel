#!/usr/bin/env python3
"""30nA-TUNNEL: two-endpoint OpenSSH TCP forwarding and terminal dashboard."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import fcntl
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time

BASE = Path("/opt/tunnel-manager")
DATA = BASE / "data"
VERSION = "2.0.0-rc.1"
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
ERRORS = (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError)
SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=15",
               "-o", "ServerAliveCountMax=2"]
STATE = DATA / "state.json"


def run(args, *, check=True, data=None, timeout=30):
    stream = {"stdin": subprocess.DEVNULL} if data is None else {"input": data}
    result = subprocess.run(args, **stream, capture_output=True, timeout=timeout)
    if check and result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(detail or f"{args[0]} exited with code {result.returncode}")
    return result


def text(result):
    return result.stdout.decode(errors="replace").strip()


def atomic_write(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def locked():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (DATA / "manager.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def ssh_command(endpoint):
    args = ["ssh", *SSH_OPTIONS, "-p", str(endpoint.get("ssh_port", 22))]
    for filename in ("30na_tunnel_manager", "30na_windows"):
        key = Path("/root/.ssh") / filename
        if key.is_file():
            args += ["-i", str(key)]
    args += ["-o", "IdentitiesOnly=yes"]
    return [*args, f"{endpoint.get('user', 'root')}@{endpoint['host']}"]


def execute(endpoint, args, **kwargs):
    if endpoint.get("dashboard"):
        return run(args, **kwargs)
    return run([*ssh_command(endpoint), shlex.join(list(map(str, args)))], **kwargs)


def save(state):
    atomic_write(STATE, json.dumps(state, indent=2) + "\n")


def host_address():
    addresses = text(run(["hostname", "-I"], check=False)).split()
    return next((address for address in addresses if "." in address), socket.gethostname())


def migrate():
    """Import all existing databases once, keeping legacy units and key paths."""
    servers = {}
    server_db = DATA / "servers.db"
    if server_db.exists():
        for line in server_db.read_text().splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) != 3 or not parts[0].isdigit() or not HOST.fullmatch(parts[1]):
                raise ValueError("Invalid legacy servers.db. Original files were preserved.")
            sid, host, user = parts
            servers[sid] = dict(host=host, user=user, ssh_port=22)
    local_id = "1" if "1" not in servers else str(max(map(int, servers), default=0) + 1)
    servers[local_id] = dict(host=host_address(), user="root", ssh_port=22, dashboard=True)
    tunnels = {}
    forward_db = DATA / "tunnels.db"
    if forward_db.exists():
        for line in forward_db.read_text().splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) != 6:
                raise ValueError("Invalid legacy tunnels.db. Original files were preserved.")
            tid, name, sid, listen, target, bind = parts
            tunnels[tid] = dict(name=name, server=sid, listen=int(listen),
                                target=int(target), bind=bind, kind="Forward")
    for filename in ("reverse.json", "pairs.json"):
        path = DATA / filename
        if path.exists():
            tunnels.update(json.loads(path.read_text()))
    for tid, tunnel in tunnels.items():
        if not tid.isdigit() or not 1 <= tunnel["listen"] <= 65535 or not 1 <= tunnel["target"] <= 65535:
            raise ValueError("Invalid legacy tunnel. Original files were preserved.")
        target = tunnel.get("dashboard_target")
        tunnel["remote_id"] = local_id if target else tunnel.get("server")
        tunnel["local_id"] = tunnel.get("local_id") or local_id
        tunnel["legacy"] = True
        tunnel["unit"] = (f"{tunnel['account']}.service" if tunnel.get("account")
                          else f"ssh-tunnel-{tid}.service")
        tunnel["phase"] = "ready"
    checks_path = DATA / "checks.json"
    checks = json.loads(checks_path.read_text()) if checks_path.exists() else {}
    return dict(schema=1, servers=servers, local_id=local_id, tunnels=tunnels, checks=checks)


def load():
    if STATE.exists():
        state = json.loads(STATE.read_text())
        if state.get("schema") != 1:
            raise ValueError("Unsupported state version.")
        return state
    state = migrate()
    save(state)
    return state


def endpoints(state, tunnel):
    try:
        return state["servers"][tunnel["local_id"]], state["servers"][tunnel["remote_id"]]
    except KeyError as error:
        raise ValueError("Tunnel endpoint is missing from the VPS registry.") from error


def participants(state, tunnel):
    local, remote = endpoints(state, tunnel)
    return (local, remote) if tunnel["kind"] == "Forward" else (remote, local)


def unit_action(state, tunnel, action, check=True):
    client, _ = participants(state, tunnel)
    return execute(client, ["systemctl", *action, tunnel["unit"]], check=check)


def service_state(state, tunnel):
    result = unit_action(state, tunnel, ["is-active"], check=False)
    value = text(result)
    return {"active": "UP", "inactive": "DOWN", "failed": "DOWN", "activating": "STARTING",
            "deactivating": "STOPPING"}.get(value, "UNKNOWN")


def listeners(endpoint, port):
    return text(execute(endpoint, ["ss", "-H", "-ltnp", f"sport = :{port}"]))


PORT_PROBE = """
import errno, json, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((sys.argv[1], int(sys.argv[2])))
except OSError as error:
    print(json.dumps(dict(free=False, detail=str(error), code=error.errno)))
else:
    print(json.dumps(dict(free=True, port=s.getsockname()[1])))
finally:
    s.close()
"""


def port_status(endpoint, port, bind="0.0.0.0"):
    return json.loads(text(execute(endpoint, ["python3", "-c", PORT_PROBE, bind, str(port)])))


def ensure_free(endpoint, port, bind="0.0.0.0"):
    result = port_status(endpoint, port, bind)
    if not result["free"]:
        owners = listeners(endpoint, port)
        raise ValueError(f"Port {port} on {endpoint['host']} is occupied.\n"
                         f"{owners or result['detail']}\n"
                         "Remove its tunnel before using this port again.")
    return result["port"]


def endpoint_identity(endpoint):
    return text(execute(endpoint, ["cat", "/etc/machine-id"]))


def confirm_distinct(local, remote):
    if endpoint_identity(local) == endpoint_identity(remote):
        raise ValueError("Local VPS and Remote VPS refer to the same machine.")


def write_remote(endpoint, path, content, mode="0600"):
    execute(endpoint, ["sh", "-ec",
            'umask 077; cat > "$1.tmp"; chmod "$2" "$1.tmp"; mv "$1.tmp" "$1"',
            "sh", path, mode], data=content.encode())


def provision(state, tunnel):
    """Provision per-tunnel authentication on its actual SSH client and server."""
    client, server = participants(state, tunnel)
    account = tunnel["account"]
    key = f"{BASE}/data/{account}.key"
    execute(client, ["install", "-d", "-m", "0700", str(DATA)])
    execute(server, ["install", "-d", "-m", "0755", "/etc/ssh/sshd_config.d"])
    host_key = text(execute(server, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"])).split()
    if len(host_key) < 2 or host_key[0] != "ssh-ed25519":
        raise RuntimeError("The SSH server needs an Ed25519 host key.")
    hostname = server["host"]
    port = server.get("ssh_port", 22)
    known_host = hostname if port == 22 else f"[{hostname}]:{port}"
    write_remote(client, key + ".hosts", f"{known_host} {host_key[0]} {host_key[1]}\n")
    public = text(execute(client, ["sh", "-ec",
        'test -f "$1" || ssh-keygen -q -t ed25519 -N "" -f "$1"; chmod 600 "$1"; cat "$1.pub"',
        "sh", key])).split()
    if len(public) < 2 or public[0] != "ssh-ed25519" or not re.fullmatch(r"[A-Za-z0-9+/=]+", public[1]):
        raise RuntimeError("Could not validate the tunnel public key.")

    # Account is unique and is recorded before any side effects for retryable cleanup.
    execute(server, ["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
                     "--shell", "/usr/sbin/nologin", "--password", "*", account])
    tunnel["resources"] = True
    save(state)
    if tunnel["kind"] == "Reverse":
        restriction = f'permitlisten="{tunnel["bind"]}:{tunnel["listen"]}"'
        forward = f"    AllowTcpForwarding remote\n    PermitListen {tunnel['bind']}:{tunnel['listen']}\n"
    else:
        restriction = f'permitopen="127.0.0.1:{tunnel["target"]}"'
        forward = f"    AllowTcpForwarding local\n    PermitOpen 127.0.0.1:{tunnel['target']}\n"
    authorized = f"/etc/ssh/{account}.keys"
    write_remote(server, authorized,
                 f"restrict,port-forwarding,{restriction} {public[0]} {public[1]}\n", "0644")
    write_remote(server, f"/etc/ssh/sshd_config.d/{account}.conf",
                 f"Match User {account}\n"
                 f"    AuthorizedKeysFile {authorized}\n"
                 "    PasswordAuthentication no\n"
                 "    KbdInteractiveAuthentication no\n"
                 "    AuthenticationMethods publickey\n"
                 "    MaxSessions 0\n"
                 "    GatewayPorts clientspecified\n" + forward +
                 "Match all\n", "0644")
    execute(server, ["/usr/sbin/sshd", "-t"])
    client_ip = text(execute(client, ["hostname", "-I"])).split()[0]
    effective = text(execute(server, ["/usr/sbin/sshd", "-T", "-C",
                     f"user={account},host={client['host']},addr={client_ip}"])).splitlines()
    expected = ["maxsessions 0", "disableforwarding no", "pubkeyauthentication yes",
                f"authorizedkeysfile {authorized}", "authenticationmethods publickey",
                "gatewayports clientspecified",
                "allowtcpforwarding " + ("remote" if tunnel["kind"] == "Reverse" else "local")]
    expected.append((f"permitlisten {tunnel['bind']}:{tunnel['listen']}" if tunnel["kind"] == "Reverse"
                     else f"permitopen 127.0.0.1:{tunnel['target']}"))
    for setting in expected:
        if setting not in effective:
            raise RuntimeError(f"Conflicting sshd policy on {server['host']}: {setting}")
    execute(server, ["systemctl", "reload", "ssh"])


def tunnel_command(state, tunnel):
    _, server = participants(state, tunnel)
    key = f"{BASE}/data/{tunnel['account']}.key"
    direction = "-L" if tunnel["kind"] == "Forward" else "-R"
    return ["/usr/bin/ssh", "-NT", *SSH_OPTIONS,
            "-o", "IdentitiesOnly=yes", "-i", key,
            "-o", f"UserKnownHostsFile={key}.hosts",
            "-o", "ExitOnForwardFailure=yes", "-p", str(server.get("ssh_port", 22)),
            direction, f"{tunnel['bind']}:{tunnel['listen']}:127.0.0.1:{tunnel['target']}",
            f"{tunnel['account']}@{server['host']}"]


def service_definition(state, tunnel):
    # All interpolated values originate in validated hostnames, integers and generated names.
    command = shlex.join(tunnel_command(state, tunnel)).replace("%", "%%")
    return f"""[Unit]
Description=30nA Tunnel {tunnel['kind']} {tunnel['listen']}
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart={command}
Restart={"no" if tunnel.get("temporary") else "always"}
{"RuntimeMaxSec=60" if tunnel.get("temporary") else ""}
RestartSec=3
KillMode=control-group
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
"""


def listener_matches(endpoint, tunnel):
    result = listeners(endpoint, tunnel["listen"])
    processes = ('"sshd",pid=', '"sshd-session",pid=') if tunnel["kind"] == "Reverse" else ('"ssh",pid=',)
    return bool(result) and any(process in result for process in processes)


def start_tunnel(state, tunnel):
    local, _ = endpoints(state, tunnel)
    client, _ = participants(state, tunnel)
    provision(state, tunnel)
    write_remote(client, f"/etc/systemd/system/{tunnel['unit']}",
                 service_definition(state, tunnel), "0644")
    execute(client, ["systemctl", "daemon-reload"])
    unit_action(state, tunnel, ["start"] if tunnel.get("temporary") else ["enable", "--now"])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if service_state(state, tunnel) == "UP" and listener_matches(local, tunnel):
            tunnel["phase"] = "ready"
            save(state)
            return
        time.sleep(0.3)
    journal = text(execute(client, ["journalctl", "-u", tunnel["unit"], "-n", "8", "--no-pager"], check=False))
    raise RuntimeError(f"Tunnel did not acquire port {tunnel['listen']}.\n{journal}")


def new_tunnel(state, local_id, remote_id, listen, target, kind, bind="0.0.0.0", temporary=False):
    local, remote = state["servers"][local_id], state["servers"][remote_id]
    if kind not in ("Forward", "Reverse") or not 1 <= listen <= 65535 or not 1 <= target <= 65535:
        raise ValueError("Invalid tunnel type or TCP port.")
    if local_id == remote_id:
        raise ValueError("Select two different VPSs.")
    confirm_distinct(local, remote)
    for tid, existing in state["tunnels"].items():
        if existing["local_id"] == local_id and existing["listen"] == listen:
            raise ValueError(f"Port {listen} is assigned to tunnel {tid}. Remove tunnel {tid} first.")
    ensure_free(local, listen, bind)
    tid = str(max(state.get("sequence", 0), max(map(int, state["tunnels"]), default=0)) + 1)
    state["sequence"] = int(tid)
    account = "nt-" + secrets.token_hex(8)
    tunnel = dict(local_id=local_id, remote_id=remote_id, listen=listen, target=target,
                  bind=bind, kind=kind, account=account, unit=account + ".service", phase="creating", temporary=temporary)
    state["tunnels"][tid] = tunnel
    save(state)
    try:
        start_tunnel(state, tunnel)
    except (KeyboardInterrupt, *ERRORS) as error:
        tunnel["phase"] = "cleanup"
        tunnel["error"] = str(error) or "Creation interrupted"
        save(state)
        try:
            remove_tunnel(state, tid)
        except ERRORS as cleanup:
            raise RuntimeError(f"Setup failed: {error}\nCleanup pending for tunnel {tid}: {cleanup}") from error
        raise RuntimeError(f"Setup failed and was rolled back: {error}") from error
    return tid


def wait_port_free(endpoint, tunnel):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if port_status(endpoint, tunnel["listen"], tunnel["bind"])["free"]:
            return
        time.sleep(0.3)
    raise RuntimeError(f"Port {tunnel['listen']} on {endpoint['host']} is still occupied.\n"
                       f"{listeners(endpoint, tunnel['listen'])}\n"
                       "Tunnel remains registered for cleanup retry.")


def remove_tunnel(state, tid):
    tunnel = state["tunnels"][tid]
    local, _ = endpoints(state, tunnel)
    client, server = participants(state, tunnel)
    tunnel["phase"] = "deleting"
    save(state)
    # Stop and verify even if the unit file has already been removed.
    loaded = text(execute(client, ["systemctl", "show", "-p", "LoadState", "--value", tunnel["unit"]]))
    if loaded != "not-found":
        unit_action(state, tunnel, ["disable", "--now"])
        if service_state(state, tunnel) in ("UP", "STARTING", "STOPPING"):
            raise RuntimeError("The SSH service did not stop.")
    wait_port_free(local, tunnel)
    execute(client, ["rm", "-f", f"/etc/systemd/system/{tunnel['unit']}"])
    execute(client, ["systemctl", "daemon-reload"])
    if tunnel.get("account"):
        account = tunnel["account"]
        # Old Forward units did not own a tunnel SSH account.
        if not tunnel.get("legacy") or tunnel["kind"] == "Reverse":
            execute(server, ["rm", "-f", f"/etc/ssh/sshd_config.d/{account}.conf",
                             f"/etc/ssh/{account}.keys"])
            execute(server, ["/usr/sbin/sshd", "-t"])
            execute(server, ["systemctl", "reload", "ssh"])
            if execute(server, ["id", account], check=False).returncode == 0:
                execute(server, ["userdel", account])
        key = f"{BASE}/data/{account}.key"
        execute(client, ["rm", "-f", key, key + ".pub", key + ".hosts",
                         f"{BASE}/data/{account}.hosts"])
    del state["tunnels"][tid]
    state["checks"].pop(tid, None)
    save(state)


SOCKETS = """
import json, subprocess, sys
result = subprocess.run(['ss', '-Hnt', 'state', 'established', 'sport = :' + sys.argv[1]],
                        check=True, capture_output=True, text=True)
rows = []
for line in result.stdout.splitlines():
    parts = line.split()
    if len(parts) >= 4 and '127.0.0.1:' in line:
        rows.append(parts[-2:])
print(json.dumps(rows))
"""


def target_sockets(endpoint, port):
    return {tuple(pair) for pair in json.loads(text(execute(endpoint, ["python3", "-c", SOCKETS, str(port)])))}


HOLD = """
import socket, sys, time
with socket.create_connection((sys.argv[1], int(sys.argv[2])), 3) as connection:
    time.sleep(3)
"""


def tcp_path(state, tunnel):
    local, remote = endpoints(state, tunnel)
    baseline = target_sockets(remote, tunnel["target"])
    with ThreadPoolExecutor(max_workers=1) as pool:
        probe = pool.submit(execute, local, ["python3", "-c", HOLD,
                            "127.0.0.1" if tunnel["bind"] == "0.0.0.0" else tunnel["bind"],
                            str(tunnel["listen"])], check=False)
        observed = False
        while not probe.done():
            if target_sockets(remote, tunnel["target"]) - baseline:
                observed = True
                break
            time.sleep(0.15)
        result = probe.result()
    return observed and result.returncode == 0


def test_tunnel(state, tid):
    tunnel = state["tunnels"][tid]
    result = dict(ssh=False, listener=False, tcp=False,
                  checked=time.strftime("%Y-%m-%d %H:%M:%S %Z"))
    try:
        local, remote = endpoints(state, tunnel)
        execute(local, ["true"])
        execute(remote, ["true"])
        result["listener"] = listener_matches(local, tunnel)
        result["ssh"] = service_state(state, tunnel) == "UP" and result["listener"]
        if result["ssh"]:
            result["tcp"] = tcp_path(state, tunnel)
    except ERRORS as error:
        result["error"] = str(error)
    state["checks"][tid] = result
    save(state)
    return result


def passed(result):
    return not result.get("error") and all(result.get(key) for key in ("ssh", "listener", "tcp"))


def test_all(state, active_only=False):
    good = checked = unavailable = 0
    print("ID   MODE      SSH    LISTENER  TCP    RESULT")
    for tid, tunnel in list(state["tunnels"].items()):
        try:
            status = service_state(state, tunnel)
            if active_only and status == "UNKNOWN":
                raise RuntimeError("Service state unavailable")
            if active_only and status != "UP":
                print(f"{tid:<4} {tunnel['kind']:<9} skipped ({status})")
                continue
            checked += 1
            result = test_tunnel(state, tid)
            good += int(passed(result))
            print(f"{tid:<4} {tunnel['kind']:<9} {word(result['ssh']):<6} "
                  f"{word(result['listener']):<9} {word(result['tcp']):<6} {word(passed(result))}", flush=True)
            if result.get("error"):
                print(f"     {result['error']}", flush=True)
        except ERRORS as error:
            unavailable += 1
            state["checks"][tid] = dict(ssh=False, listener=False, tcp=False, error=str(error),
                                        checked=time.strftime("%Y-%m-%d %H:%M:%S %Z"))
            save(state)
            print(f"{tid}: FAIL — {error}", flush=True)
    print(f"{good}/{checked} passed; {unavailable} unavailable.")
    return good == checked and unavailable == 0


def color(value, code):
    if sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ:
        return f"\033[{code}m{value}\033[0m"
    return str(value)


def word(ok):
    return color("OK", "32") if ok else color("FAIL", "31")


def clear_screen():
    if sys.stdout.isatty() and os.environ.get("TERM") != "dumb":
        print("\033[2J\033[H", end="", flush=True)


def select_id(records, label):
    if not records:
        print(f"No {label} configured.")
        return None
    while True:
        value = input(f"{label} ID [{', '.join(sorted(records, key=int))}; 0 Back]: ").strip()
        if value == "0":
            return None
        if value in records:
            return value
        print("Choose a numbered item from the table.")


def input_port(label, default=None):
    while True:
        hint = f"Enter = {default}" if default is not None else "e.g. 28000"
        value = input(f"{label} [{hint}]: ").strip()
        if not value and default is not None:
            return default
        if value.isascii() and value.isdecimal() and 1 <= int(value) <= 65535:
            return int(value)
        print("Enter a port number between 1 and 65535.")


def select_mode():
    while True:
        value = input("Mode [1 Forward, 2 Reverse, 0 Back]: ").strip()
        if value == "0":
            return None
        if value in ("1", "2"):
            return "Forward" if value == "1" else "Reverse"
        print("Choose 1, 2, or 0.")


def select_endpoints(state):
    print(color("SELECT VPS", "1;36"))
    for sid, endpoint in state["servers"].items():
        suffix = " (this VPS)" if endpoint.get("dashboard") else ""
        print(f"{sid}. {endpoint['host']}{suffix}")
    local_id = select_id(state["servers"], "Local VPS")
    if local_id is None:
        return None
    others = {sid: endpoint for sid, endpoint in state["servers"].items() if sid != local_id}
    remote_id = select_id(others, "Remote VPS")
    if remote_id is None:
        return None
    return local_id, remote_id


def add_tunnel(state):
    pair = select_endpoints(state)
    if pair is None:
        return
    local_id, remote_id = pair
    listen = input_port("Local Port")
    target = input_port("Remote Port", 443)
    kind = select_mode()
    if kind is None:
        return
    tid = new_tunnel(state, local_id, remote_id, listen, target, kind)
    print(color(f"Tunnel {tid} is UP.", "1;32"))
    print(f"Listener: {state['servers'][local_id]['host']}:{listen}")
    print(f"Target:   {state['servers'][remote_id]['host']}:127.0.0.1:{target}")


PUBLIC_REGISTER = r"""
import pathlib, subprocess, sys
key = sys.stdin.buffer.read()
parts = key.decode().split()
if len(parts) < 2 or parts[0] != 'ssh-ed25519':
    raise SystemExit('Invalid management public key')
home = pathlib.Path('/root/.ssh')
home.mkdir(mode=0o700, exist_ok=True)
authorized = home / 'authorized_keys'
if authorized.is_symlink():
    raise SystemExit('Refusing symlink authorized_keys')
existing = authorized.read_bytes() if authorized.exists() else b''
fingerprint = subprocess.run(['ssh-keygen','-lf','-'], input=key,
                             check=True, capture_output=True).stdout.split()[1]
listed = subprocess.run(['ssh-keygen','-lf','-'], input=existing,
                        capture_output=True).stdout.splitlines()
if not any(len(line.split()) > 1 and line.split()[1] == fingerprint for line in listed):
    with authorized.open('ab') as stream:
        if existing and not existing.endswith(b'\n'):
            stream.write(b'\n')
        stream.write(key.rstrip(b'\n') + b'\n')
authorized.chmod(0o600)
"""


def register_management(endpoint):
    if endpoint.get("dashboard"):
        return
    public = Path("/root/.ssh/30na_tunnel_manager.pub").read_bytes()
    execute(endpoint, ["python3", "-c", PUBLIC_REGISTER], data=public)
    # Confirm access without any interactive agent before calling a VPS ready.
    command = ["env", "-u", "SSH_AUTH_SOCK", "ssh", *SSH_OPTIONS,
               "-i", "/root/.ssh/30na_tunnel_manager", "-o", "IdentitiesOnly=yes",
               "-p", str(endpoint.get("ssh_port", 22)),
               f"{endpoint.get('user','root')}@{endpoint['host']}", "true"]
    run(command)


def enroll_server(state):
    host = input("VPS address [e.g. gr02.30na.top]: ").strip()
    if not HOST.fullmatch(host):
        raise ValueError("Enter an IPv4 address or a DNS hostname.")
    port = input_port("SSH Port", 22)
    endpoint = dict(host=host, ssh_port=port, user="root")
    manager_key = Path("/root/.ssh/30na_tunnel_manager")
    if not manager_key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(manager_key)])
    if execute(endpoint, ["true"], check=False).returncode:
        command = ["ssh-copy-id", "-p", str(port), "-i", str(manager_key) + ".pub",
                   "-o", "ConnectTimeout=8"]
        admin_key = Path("/root/.ssh/30na_windows")
        if admin_key.exists():
            command += ["-o", f"IdentityFile={admin_key}"]
        subprocess.run([*command, f"root@{host}"], check=True, timeout=120)
    register_management(endpoint)
    machine = endpoint_identity(endpoint)
    if machine == endpoint_identity(state["servers"][state["local_id"]]):
        raise ValueError("The dashboard VPS is already registered.")
    for sid, current in state["servers"].items():
        current_machine = current.get("machine_id")
        if current.get("dashboard"):
            current_machine = endpoint_identity(current)
        if current_machine == machine and current["host"] != host:
            raise ValueError(f"This VPS is already registered as {sid} ({current['host']}).")
    revision = (BASE / "revision").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Reinstall the project to register its revision.")
    print("Installing 30nA-TUNNEL on the VPS...", flush=True)
    result = execute(endpoint, ["bash", "-s", "--", "--peer", revision],
                     data=(BASE / "install.sh").read_bytes(), timeout=900)
    print(text(result))
    if execute(endpoint, ["cat", str(BASE / "manager.py")]).stdout != (BASE / "manager.py").read_bytes():
        raise RuntimeError("The peer did not install the selected version.")
    sid = next((key for key, server in state["servers"].items()
                if server["host"] == host and server.get("ssh_port", 22) == port), None)
    sid = sid or str(max(map(int, state["servers"]), default=0) + 1)
    endpoint["machine_id"] = machine
    state["servers"][sid] = endpoint
    save(state)
    print(f"VPS {sid} installed and registered.")


def remove_server(state, sid):
    if sid == state["local_id"]:
        raise ValueError("The current dashboard VPS cannot be removed.")
    related = [tid for tid, tunnel in state["tunnels"].items()
               if sid in (tunnel["local_id"], tunnel["remote_id"])]
    for tid in related:
        try:
            remove_tunnel(state, tid)
        except ERRORS as error:
            raise RuntimeError(f"VPS retained. Tunnel {tid} cleanup failed: {error}") from error
    del state["servers"][sid]
    save(state)
    print(f"VPS {sid} and {len(related)} tunnel(s) removed.")


def vps_test(state):
    print("1. Check connections from this terminal to all VPSs")
    print("2. Test a tunnel between two VPSs")
    print("0. Back")
    choice = input("Select > ").strip()
    if choice == "0":
        return
    if choice == "1":
        for sid, endpoint in state["servers"].items():
            try:
                execute(endpoint, ["true"])
                print(f"{sid}. {endpoint['host']}  {word(True)}")
            except ERRORS as error:
                print(f"{sid}. {endpoint['host']}  {word(False)}  {error}")
        return
    if choice != "2":
        raise ValueError("Choose 1, 2, or 0.")
    pair = select_endpoints(state)
    if pair is None:
        return
    local_id, remote_id = pair
    listen = input_port("Local test port", 0)
    target = input_port("Remote service port", 22)
    kind = select_mode()
    if kind is None:
        return
    local = state["servers"][local_id]
    listen = ensure_free(local, listen, "127.0.0.1")
    # Uses exactly the same provisioning, data path, cleanup and port-release checks.
    tid = new_tunnel(state, local_id, remote_id, listen, target, kind, bind="127.0.0.1", temporary=True)
    try:
        result = test_tunnel(state, tid)
        print(f"SSH {word(result['ssh'])}  LISTENER {word(result['listener'])}  TCP {word(result['tcp'])}")
        if result.get("error"):
            print(result["error"])
    finally:
        remove_tunnel(state, tid)
        print(f"Temporary tunnel removed. Port {listen} released.")


def dashboard(state):
    clear_screen()
    local = state["servers"][state["local_id"]]
    print(color(f"30nA-TUNNEL {VERSION}", "1;36"))
    print(f"{socket.gethostname()}  ·  {local['host']}  ·  {time.strftime('%H:%M')}")
    print(color("\nVPS", "1;36"))
    print(f"{'ID':<4} {'HOST':<30} {'SSH':<12} DNS CHECK")
    with ThreadPoolExecutor(max_workers=min(8, len(state["servers"]))) as pool:
        jobs = {sid: pool.submit(execute, endpoint, ["true"], check=False)
                for sid, endpoint in state["servers"].items()}
        for sid, endpoint in state["servers"].items():
            try:
                ok = jobs[sid].result().returncode == 0
                status = "LOCAL" if endpoint.get("dashboard") else ("OK" if ok else "FAIL")
            except ERRORS:
                status = "UNKNOWN"
            # getent is bounded so an unavailable resolver cannot hang the UI.
            try:
                resolved = execute(local, ["getent", "ahostsv4", endpoint["host"]], check=False, timeout=3)
                dns = "OK" if resolved.returncode == 0 else "FAIL"
            except ERRORS:
                dns = "UNKNOWN"
            print(f"{sid:<4} {endpoint['host']:<30} {color(status, '32' if status in ('LOCAL','OK') else '31'):<21} "
                  f"{dns} ({time.strftime('%H:%M')})")
    print(color("\nTUNNELS", "1;36"))
    print(f"{'ID':<4} {'MODE':<9} {'LOCAL VPS:PORT':<29} {'REMOTE VPS:PORT':<29} {'STATE':<12} TEST")
    for tid, tunnel in state["tunnels"].items():
        try:
            listener, target = endpoints(state, tunnel)
            status = service_state(state, tunnel)
            phase = tunnel.get("phase", "ready")
            if phase != "ready":
                status = phase.upper()
            result = state["checks"].get(tid)
            checked = word(passed(result)) if result else "—"
            if result:
                checked += " " + result.get("checked", "")
            print(f"{tid:<4} {tunnel['kind']:<9} "
                  f"{listener['host'] + ':' + str(tunnel['listen']):<29} "
                  f"{target['host'] + ':' + str(tunnel['target']):<29} "
                  f"{color(f'{status:<12}', '32' if status == 'UP' else '33')} {checked}")
        except ERRORS as error:
            print(f"{tid}  {color('UNKNOWN', '31')}  {error}")
    if not state["tunnels"]:
        print("No tunnels configured.")


MENUS = {
    "home": "1. VPS\n2. Tunnel\n0. Exit",
    "vps": "1. Add New VPS\n2. Remove VPS\n3. VPS Test\n0. Back",
    "tunnel": "1. Add Tunnel\n2. Remove Tunnel\n3. Tunnel Test\n0. Back",
}


def cli():
    section = "home"
    try:
        while True:
            with locked():
                state = load()
            dashboard(state)
            print(color("\n" + section.upper(), "1;37"))
            print(MENUS[section])
            choice = input("Select > ").strip()
            if choice == "0":
                if section == "home":
                    clear_screen()
                    return
                section = "home"
                continue
            if section == "home" and choice in ("1", "2"):
                section = "vps" if choice == "1" else "tunnel"
                continue
            dashboard(state)
            try:
                if choice not in ("1", "2", "3") or section == "home":
                    raise ValueError("Choose one of the numbered options.")
                with locked():
                    state = load()
                    if section == "vps":
                        if choice == "1":
                            enroll_server(state)
                        elif choice == "2":
                            sid = select_id({key: value for key, value in state["servers"].items()
                                             if key != state["local_id"]}, "VPS")
                            if sid is not None:
                                remove_server(state, sid)
                        else:
                            vps_test(state)
                    elif choice == "1":
                        add_tunnel(state)
                    elif choice == "2":
                        tid = select_id(state["tunnels"], "Tunnel")
                        if tid is not None:
                            remove_tunnel(state, tid)
                            print(f"Tunnel {tid} removed. Local port released.")
                    else:
                        test_all(state, active_only=True)
            except ERRORS as error:
                print(color(f"Error: {error}", "31"))
            input("\nEnter to return > ")
    except (EOFError, KeyboardInterrupt):
        return


def same_address(left, right):
    if left == right:
        return True
    try:
        left_ips = {row[4][0] for row in socket.getaddrinfo(left, None, socket.AF_INET)}
        right_ips = {row[4][0] for row in socket.getaddrinfo(right, None, socket.AF_INET)}
        return bool(left_ips & right_ips)
    except socket.gaierror:
        return False


def discover_services(state):
    """Recover known project units left out of an older database after failed removal."""
    known = set()
    for tunnel in state["tunnels"].values():
        try:
            client, _ = participants(state, tunnel)
            known.add((client["host"], client.get("ssh_port", 22), tunnel["unit"]))
        except ERRORS:
            continue
    for client_id, client in state["servers"].items():
        try:
            listing = text(execute(client, ["systemctl", "list-units", "--all", "--type=service",
                           "--plain", "--no-legend", "--no-pager", "ssh-tunnel-*",
                           "stm-r-*", "nt-*", "gr02-iran-reverse.service"]))
            units = {line.split()[0] for line in listing.splitlines() if line.split()}
            for unit in sorted(units):
                if not re.fullmatch(r"(?:ssh-tunnel-[0-9]+|stm-r-[a-z0-9]+|nt-[a-z0-9]+|gr02-iran-reverse)\.service", unit):
                    continue
                if (client["host"], client.get("ssh_port", 22), unit) in known:
                    continue
                command = text(execute(client, ["systemctl", "show", "-p", "ExecStart", "--value", unit]))
                match = re.search(r"argv\[\]=(.*?);", command)
                if not match:
                    continue
                args = shlex.split(match.group(1).strip())
                if not args or args[0] != "/usr/bin/ssh":
                    continue
                flag = "-R" if "-R" in args else "-L" if "-L" in args else None
                if flag is None:
                    continue
                bind, listen, target_host, target = args[args.index(flag) + 1].split(":")
                if bind not in ("0.0.0.0", "127.0.0.1") or target_host != "127.0.0.1":
                    continue
                if not listen.isdecimal() or not target.isdecimal():
                    continue
                destination = args[-1].split("@")
                if len(destination) != 2:
                    continue
                destination_user, host = destination
                ssh_port = int(args[args.index("-p") + 1]) if "-p" in args else 22
                server_id = next((sid for sid, endpoint in state["servers"].items()
                                  if endpoint.get("ssh_port",22) == ssh_port and same_address(endpoint["host"], host)), None)
                if server_id is None or server_id == client_id:
                    continue
                local_id, remote_id = ((client_id,server_id) if flag == "-L" else (server_id,client_id))
                tid = str(max(state.get("sequence",0), max(map(int,state["tunnels"]),default=0))+1)
                tunnel = dict(local_id=local_id,remote_id=remote_id,kind="Forward" if flag=="-L" else "Reverse",
                              listen=int(listen),target=int(target),bind=bind,unit=unit,phase="ready",
                              legacy=not destination_user.startswith("nt-"), recovered=True)
                if destination_user.startswith(("nt-","stm-r-")):
                    tunnel["account"] = destination_user
                state["tunnels"][tid] = tunnel
                state["sequence"] = int(tid)
                save(state)
                print(f"Recovered service {unit} as tunnel {tid} on port {listen}.", flush=True)
        except ERRORS as error:
            print(f"Service discovery on {client['host']}: {error}", flush=True)


def recover_pending(state):
    for tid, tunnel in list(state["tunnels"].items()):
        if tunnel.get("phase", "ready") != "ready" or tunnel.get("temporary"):
            try:
                remove_tunnel(state, tid)
                print(f"Recovered tunnel {tid}; port released.", flush=True)
            except ERRORS as error:
                print(f"Tunnel {tid} needs cleanup retry: {error}", flush=True)


def main():
    if os.geteuid() != 0:
        sys.exit("Run as root.")
    os.umask(0o077)
    try:
        if sys.argv[1:] in (["--health"], ["--migrate"]):
            with locked():
                state = load()
                if sys.argv[1:] == ["--health"]:
                    recover_pending(state)
                    if not test_all(state):
                        sys.exit(1)
        elif not sys.argv[1:]:
            with locked():
                state = load()
                discover_services(state)
                recover_pending(state)
            cli()
        else:
            sys.exit("Usage: 30na-tunnel.sh")
    except ERRORS as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
