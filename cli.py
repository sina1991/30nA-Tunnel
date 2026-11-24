"""Command dispatcher for 30na on Ubuntu."""
import argparse
from collections import Counter
import ipaddress
import os
from pathlib import Path
import socket
import sqlite3
import sys

import health
import manager as m


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return number


def resolve(state, value):
    records = state["servers"]
    if value in records:
        return value
    for sid, peer in records.items():
        if value.lower() in (peer["host"].lower(), peer.get("ip"), peer.get("domain", "").lower()):
            return sid
    try:
        ip = socket.gethostbyname(value)
    except OSError:
        ip = None
    if ip:
        for sid, peer in records.items():
            if ip == peer.get("ip"):
                return sid
    raise ValueError(f"Unknown VPS: {value}. Run 30na -vps.")


def enroll(state, args):
    host = args.domain or str(ipaddress.IPv4Address(args.ip))
    if not m.HOST.fullmatch(host):
        raise ValueError("Invalid VPS address")
    key = Path(args.sshkey).expanduser().resolve()
    if not key.is_file():
        raise ValueError(f"SSH private key file missing: {key}")
    ip = socket.gethostbyname(host)
    endpoint = dict(host=host, ip=ip, domain=args.domain or "", ssh_port=args.ssh_port, key=str(key))
    machine = m.endpoint_identity(endpoint)
    if len(machine) != 32 or any(char not in "0123456789abcdef" for char in machine):
        raise ValueError("SSH responded but returned an invalid machine ID")
    for sid, peer in state["servers"].items():
        if peer.get("machine_id") == machine:
            if args.domain and ip == peer.get("ip"):
                peer["domain"] = host
                m.save(state)
            print(f"VPS {sid} already registered.")
            return
        if peer["host"] == host or peer["ip"] == ip:
            raise ValueError(f"Address already registered to VPS {sid} with different machine ID")
    sid = str(max(state.get("vps_sequence", 1), max(map(int, state["servers"]))) + 1)
    state["vps_sequence"] = int(sid)
    state["servers"][sid] = dict(endpoint, machine_id=machine)
    m.save(state)
    print(f"VPS {sid} registered: {host} ({ip})")


def heading(title):
    print(m.color("\n" + title, "1;36"))


def badge(value):
    code = {"OK": "32", "UP": "32", "FAIL": "31", "DOWN": "31", "NO LISTENER": "31"}.get(value, "33")
    return m.color(value, code)


def inventory(state):
    heading("VPS")
    print("ID    IPv4             HOST                         ROLE")
    for sid, peer in state["servers"].items():
        role = "LOCAL" if peer.get("dashboard") else "REMOTE"
        print(f"{sid:<5} {peer['ip']:<16} {(peer.get('domain') or peer['host']):<28} {role}")


def snapshot(state):
    states = {}
    for tid, tunnel in state["tunnels"].items():
        try:
            states[tid] = health.status(state, tunnel)
        except m.ERRORS:
            states[tid] = "UNKNOWN"
    return states


def tunnels(state, states):
    heading("TUNNELS")
    print("ID    MODE      LOCAL VPS:PORT              REMOTE VPS:PORT             STATE / LAST TEST")
    for tid, tunnel in state["tunnels"].items():
        local, remote = m.endpoints(state, tunnel)
        ingress = f"{local['host']}:{tunnel['listen']}"
        target = f"{remote['host']}:{tunnel['target']}"
        last = state["checks"].get(tid, {})
        print(f"{tid:<5} {tunnel['kind']:<9} {ingress:<27} {target:<27} "
              f"{badge(states[tid])} / {last.get('result', '—')} {last.get('checked', '')}")
    if not states:
        print("No managed tunnels.")


def vps_tests(state, ids):
    heading("SSH FROM THIS MANAGER")
    counts = Counter()
    for sid in ids:
        peer = state["servers"][sid]
        if peer.get("dashboard"):
            continue
        try:
            m.execute(peer, ["true"])
            outcome, detail = "OK", ""
        except m.ERRORS as error:
            outcome, detail = "FAIL", str(error)
        counts[outcome] += 1
        print(sid, peer["host"], badge(outcome), detail, flush=True)
    print(f"VPS checked: {sum(counts.values())} | OK {counts['OK']} | FAIL {counts['FAIL']}")
    return not counts["FAIL"]


def tunnel_tests(state, ids, states, active_only):
    heading("TUNNEL TEST")
    counts = Counter()
    for tid in ids:
        current = states[tid]
        if active_only and current == "DOWN":
            counts["SKIPPED"] += 1
            print(tid, "SKIPPED", current)
            continue
        outcome, detail = health.check(state, tid, current)
        counts[outcome] += 1
        print(tid, badge(outcome), detail, state["checks"][tid]["checked"], flush=True)
    print(" | ".join(f"{key} {counts[key]}" for key in ("OK", "FAIL", "UNVERIFIED", "SKIPPED")))
    return not (counts["FAIL"] or counts["UNVERIFIED"])


def examples(state, modules):
    heading("EXAMPLES")
    peers = [sid for sid in state["servers"] if sid != state["local_id"]]
    if "-vps" in modules or not peers:
        print("30na -vps -add -ip 203.0.113.10")
        if peers:
            print(f"30na -vps -remove -id {peers[0]}")
            print(f"30na -vps -remove -ip {state['servers'][peers[0]]['ip']}")
    if "-tunnel" in modules and peers:
        local = state["servers"][state["local_id"]]
        remote = state["servers"][peers[0]]
        assigned = {t["listen"] for t in state["tunnels"].values() if t["local_id"] == state["local_id"]}
        for mode, first in (("reverse", 18443), ("forward", 15443)):
            candidate = first
            while candidate <= 65535 and (candidate in assigned or
                    not m.port_status(local, candidate, local["ip"])["free"]):
                candidate += 1
            if candidate <= 65535:
                origin = local.get("domain") or local["ip"]
                destination = remote["host"] if mode == "forward" else peers[0]
                print(f"30na -tunnel -add -local {origin} -remote {destination} "
                      f"-local-port {candidate} -remote-port 443 -mode {mode}")
    if "-tunnel" in modules and state["tunnels"]:
        print(f"30na -tunnel -remove -id {next(iter(state['tunnels']))}")


def report(state, modules):
    m.clear_screen()
    print(m.color("30nA", "1;35"), socket.gethostname(), state["servers"][state["local_id"]]["ip"])
    states = snapshot(state) if "-tunnel" in modules else {}
    if "-vps" in modules:
        inventory(state)
    if "-tunnel" in modules:
        tunnels(state, states)
        if "-vps" not in modules:
            inventory(state)
    ok = True
    if "-vps" in modules:
        ok = vps_tests(state, state["servers"])
    if len(modules) == 2:
        ok = tunnel_tests(state, states, states, True) and ok
    examples(state, modules)
    return ok


def parser_for(module, action):
    p = argparse.ArgumentParser(prog=f"30na {module} {action}", allow_abbrev=False)
    if action == "-test":
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("-id")
        group.add_argument("-all", action="store_true")
    elif action == "-remove":
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("-id")
        if module == "-vps":
            group.add_argument("-ip", type=ipaddress.IPv4Address)
    elif module == "-vps":
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("-ip")
        group.add_argument("-domain")
        p.add_argument("-ssh-port", type=port, default=22)
        p.add_argument("-sshkey", default=m.DEFAULT_KEY)
    else:
        for option in ("-local", "-remote"):
            p.add_argument(option, required=True)
        for option in ("-local-port", "-remote-port"):
            p.add_argument(option, required=True, type=port)
        p.add_argument("-mode", choices=("forward", "reverse"), required=True)
    return p


def vps_action(state, action, args):
    if action == "-add":
        enroll(state, args)
    elif action == "-remove":
        sid = resolve(state, args.id or str(args.ip))
        m.remove_server(state, sid)
    else:
        ids = state["servers"] if args.all else [resolve(state, args.id)]
        return vps_tests(state, ids)
    return True


def tunnel_action(state, action, args):
    if action == "-add":
        local, remote = resolve(state, args.local), resolve(state, args.remote)
        tid = m.new_tunnel(state, local, remote, args.local_port, args.remote_port,
                           args.mode.title(), bind=state["servers"][local]["ip"])
        print(f"Tunnel {tid} started.")
    elif action == "-remove":
        if args.id not in state["tunnels"]:
            raise ValueError(f"Unknown tunnel ID: {args.id}")
        m.remove_tunnel(state, args.id)
        print(f"Tunnel {args.id} removed. Ingress port released.")
    else:
        if not args.all and args.id not in state["tunnels"]:
            raise ValueError(f"Unknown tunnel ID: {args.id}")
        ids = state["tunnels"] if args.all else [args.id]
        return tunnel_tests(state, ids, snapshot(state), args.all)
    return True


MODULES = {"-vps": vps_action, "-tunnel": tunnel_action}


def main(argv):
    if not argv or argv == ["-h"]:
        print("30na " + " | ".join(MODULES) + "\n30na -vps -tunnel\nUse MODULE -h for command examples.")
        return 0
    module, *rest = argv
    if module not in MODULES:
        raise ValueError("Unknown module. Run 30na -h.")
    if rest == ["-h"]:
        for action in ("-add", "-remove", "-test"):
            parser_for(module, action).print_usage()
        return 0
    combined = rest == ["-tunnel"] and module == "-vps"
    interactive = module == "-tunnel" and rest == ["-add"]
    if rest and not combined and not interactive:
        action = rest[0]
        if action not in ("-add", "-remove", "-test"):
            raise ValueError(f"Unknown action. Run 30na {module} -h.")
        args = parser_for(module, action).parse_args(rest[1:])
    if os.geteuid() != 0:
        raise ValueError("Run as root on the manager.")
    with m.locked():
        state = m.load()
        if not rest or combined:
            success = report(state, argv)
        else:
            if interactive:
                if len(state["servers"]) < 2:
                    raise ValueError("Add a remote VPS first: 30na -vps -add -ip ADDRESS")
                m.clear_screen()
                pair = m.select_endpoints(state)
                if not pair:
                    return 0
                listen = m.input_port("Local port")
                target = m.input_port("Remote port", 443)
                mode = m.select_mode()
                if not mode:
                    return 0
                action = "-add"
                args = argparse.Namespace(local=pair[0], remote=pair[1], local_port=listen,
                                          remote_port=target, mode=mode)
            success = MODULES[module](state, action, args)
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except m.ERRORS + (sqlite3.Error, EOFError) as exc:
        sys.exit(f"Error: {exc}")
    except KeyboardInterrupt:
        sys.exit(130)
