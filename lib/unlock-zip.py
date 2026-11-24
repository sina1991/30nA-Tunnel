import errno
import os
from pathlib import Path
import pty
import select
import signal
import sys
import termios
import time

password = Path(os.environ["STM_PASSWORD_FILE"]).read_bytes().rstrip(b"\n")
pid, terminal = pty.fork()
if pid == 0:
    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    finally:
        os._exit(127)

deadline = time.monotonic() + 60
pending = b""
sent = False
reaped = False
try:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([terminal], [], [], remaining)[0]:
            raise RuntimeError("ZIP extraction timed out")
        try:
            chunk = os.read(terminal, 4096)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        pending = (pending + chunk)[-8192:]
        if b"Enter password" in pending:
            if sent:
                raise RuntimeError("ZIP tool rejected the supplied password")
            settings = termios.tcgetattr(terminal)
            settings[3] &= ~termios.ECHO
            termios.tcsetattr(terminal, termios.TCSANOW, settings)
            os.write(terminal, password + b"\n")
            pending = b""
            sent = True
    _, status = os.waitpid(pid, 0)
    reaped = True
    sys.exit(0 if sent and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 else 1)
except (OSError, RuntimeError) as error:
    print(f"ZIP extraction failed: {error}", file=sys.stderr)
    sys.exit(1)
finally:
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
    os.close(terminal)
