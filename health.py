"""Bounded application-level observations from the selected ingress host."""
from datetime import datetime, timezone
import manager as m

PROBE = """
import socket, ssl, sys
host, port, target, name = sys.argv[1:]
with socket.create_connection((host, int(port)), timeout=4) as sock:
    try:
        if target == '443':
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=name) as tls:
                print('OK TLS handshake ' + tls.version())
        elif sock.recv(1):
            print('OK Application data received')
        else:
            print('UNVERIFIED Peer closed without application data')
    except (OSError, ValueError):
        print('UNVERIFIED No recognizable application response')
"""


def status(state, tunnel):
    if tunnel["phase"] != "ready":
        return "PENDING"
    service = m.service_state(state, tunnel)
    if service == "UP" and not m.listener_matches(m.endpoints(state, tunnel)[0], tunnel):
        return "NO LISTENER"
    return service


def check(state, tid, current):
    tunnel = state["tunnels"][tid]
    local, remote = m.endpoints(state, tunnel)
    try:
        if current != "UP":
            verdict = "UNVERIFIED State unavailable" if current in ("UNKNOWN", "PENDING") else "FAIL Tunnel is " + current
        elif not m.listeners(remote, tunnel["target"]):
            verdict = "FAIL No destination listener"
        else:
            host = local["host"] if tunnel["bind"] == "0.0.0.0" else tunnel["bind"]
            result = m.execute(local, ["python3", "-c", PROBE, host, str(tunnel["listen"]),
                                       str(tunnel["target"]), remote["host"]], check=False)
            if result.returncode == 255:
                verdict = "UNVERIFIED SSH connection lost"
            elif result.returncode:
                verdict = "FAIL Ingress connection failed"
            else:
                verdict = m.text(result)
                if not verdict.startswith(("OK ", "UNVERIFIED ")):
                    verdict = "UNVERIFIED Unexpected probe response"
    except m.ERRORS as error:
        verdict = "UNVERIFIED " + str(error)
    outcome, _, detail = verdict.partition(" ")
    state["checks"][tid] = dict(result=outcome, detail=detail,
                                checked=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    m.save(state)
    return outcome, detail
