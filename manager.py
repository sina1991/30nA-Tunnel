#!/usr/bin/env python3
"""30nA-TUNNEL: two-endpoint OpenSSH TCP forwarding and terminal dashboard."""
from contextlib import contextmanager
from contextlib import closing
import ipaddress
import sqlite3
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
import time

BASE = Path("/var/lib/30na")
DATA = BASE / "data"
DEFAULT_KEY = "/root/.ssh/30na_windows"
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
ERRORS = (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError)
SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=15",
               "-o", "ServerAliveCountMax=2"]
STATE = DATA / "registry.sqlite3"


def run(args, *, check=True, data=None, timeout=30):
    stream = {"stdin": subprocess.DEVNULL} if data is None else {"input": data}
    try:
        result = subprocess.run(args, **stream, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Operation timed out after {timeout} seconds.") from error
    if check and result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(detail or f"{args[0]} exited with code {result.returncode}")
    return result


def text(result):
    return result.stdout.decode(errors="replace").strip()


@contextmanager
def locked():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (DATA / "manager.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def ssh_command(endpoint):
    args = ["ssh", *SSH_OPTIONS, "-p", str(endpoint.get("ssh_port", 22))]
    args += ["-i", endpoint.get("key", DEFAULT_KEY)]
    args += ["-o", "IdentitiesOnly=yes"]
    return [*args, f"{endpoint.get('user', 'root')}@{endpoint['host']}"]


def execute(endpoint, args, **kwargs):
    if endpoint.get("dashboard"):
        return run(args, **kwargs)
    try:
        return run([*ssh_command(endpoint), shlex.join(list(map(str, args)))], **kwargs)
    except RuntimeError as error:
        raise RuntimeError(f"SSH {endpoint['host']}:{endpoint.get('ssh_port', 22)} — {error}") from error


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
import json, socket, sys
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
    for row in result.splitlines():
        fields = row.split()
        if len(fields) >= 4 and fields[3] in (f"{tunnel['bind']}:{tunnel['listen']}", f"*:{tunnel['listen']}"):
            if any(process in row for process in processes):
                return True
    return False


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
    except (KeyboardInterrupt,) + ERRORS as error:
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
    query = execute(client, ["systemctl", "show", "-p", "LoadState", "--value", tunnel["unit"]], check=False)
    loaded = text(query)
    if loaded != "not-found" and (query.returncode or not loaded):
        raise RuntimeError(f"Unable to verify unit {tunnel['unit']} on {client['host']}.")
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



def save(state):
    DATA.mkdir(parents=True, mode=0o700, exist_ok=True)
    with closing(sqlite3.connect(STATE)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS registry (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)")
        db.execute("INSERT OR REPLACE INTO registry VALUES (1, ?)", (json.dumps(state),))


def local_endpoint():
    ips = []
    for value in text(run(["hostname", "-I"])).split():
        address = ipaddress.ip_address(value)
        if address.version == 4 and not address.is_loopback:
            ips.append(value)
    if not ips:
        raise ValueError("No local IPv4 address found.")
    ip = os.environ.get("THIRTYNA_LOCAL_IPV4") or ips[0]
    if ip not in ips:
        raise ValueError("THIRTYNA_LOCAL_IPV4 must be assigned on this host.")
    if len(ips) > 1 and not os.environ.get("THIRTYNA_LOCAL_IPV4"):
        print("Local IPv4 addresses:", ", ".join(ips))
        ip = input(f"Local IPv4 [e.g. {ip}]: ").strip()
        if ip not in ips:
            raise ValueError("Choose a listed IPv4 address.")
    peer = dict(host=ip, ip=ip, dashboard=True, machine_id=Path("/etc/machine-id").read_text().strip())
    name = socket.getfqdn().lower()
    if "." in name and name != ip and HOST.fullmatch(name):
        try:
            if socket.gethostbyname(name) == ip:
                peer["domain"] = name
        except socket.gaierror:
            pass
    return peer


def load():
    if STATE.exists():
        with closing(sqlite3.connect(STATE)) as db:
            row = db.execute("SELECT body FROM registry WHERE id=1").fetchone()
        if row:
            state = json.loads(row[0])
            if state.get("schema") != 1:
                raise ValueError("Unsupported registry version")
            return state
    state = dict(schema=1, local_id="1", servers={"1": local_endpoint()}, tunnels={}, checks={})
    save(state)
    return state
