"""Explicit disposable CI runner test: real accounts, sshd and systemd units."""
from pathlib import Path
import socket
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import health
import manager as m


def exercise():
    with m.locked():
        state = m.load()
        if state["tunnels"] or len(state["servers"]) != 1:
            raise RuntimeError("Expected a disposable, fresh manager")
        # Both roles share the runner. The tunnel transport still uses sshd.
        state["servers"]["2"] = dict(host="127.0.0.1", ip="127.0.0.1", dashboard=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        try:
            for mode in ("Forward", "Reverse"):
                with patch.object(m, "confirm_distinct"):
                    tid = m.new_tunnel(state, "1", "2", port, 22, mode, bind="127.0.0.1")
                try:
                    tunnel = state["tunnels"][tid]
                    assert health.status(state, tunnel) == "UP"
                    with socket.create_connection(("127.0.0.1", port), 5) as connection:
                        assert connection.recv(64).startswith(b"SSH-")
                    m.unit_action(state, tunnel, ["restart"])
                finally:
                    m.remove_tunnel(state, tid)
                assert m.port_status(state["servers"]["1"], port, "127.0.0.1")["free"]
        finally:
            if not state["tunnels"]:
                del state["servers"]["2"]
                m.save(state)


if __name__ == "__main__":
    exercise()
