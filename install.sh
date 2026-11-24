#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPO="https://github.com/sina1991/30nA-Tunnel.git"
BRANCH="main"
BASE="/opt/tunnel-manager"
ZIP=/root/30na-SSH-Backup.zip
PASSWORD_CONFIG=/root/.30na-tunnel-passwords
peer="${1:-}"
revision="${2:-}"

[[ $EUID == 0 ]] || { echo "Run this installer as root." >&2; exit 1; }
if [[ -n "$peer" ]]; then
    [[ "$peer" == --peer && "$revision" =~ ^[0-9a-f]{40}$ && $# == 2 ]] || exit 2
elif [[ ! -f "$ZIP" ]]; then
    echo "Place the backup at $ZIP and run again." >&2
    exit 1
fi
[[ -d /run/systemd/system ]] || { echo "Ubuntu with systemd is required." >&2; exit 1; }

TMP="$(mktemp -d)"
PASSWORD_TMP=""
agent_started=""
timer_active=""
updating=""
backup=""
cleanup() {
    local result=$?
    trap - EXIT
    if [[ "$result" != 0 && -n "$updating" && -n "$backup" ]]; then
        echo "Installation failed. Restoring application files from $backup." >&2
        for file in manager.py install.sh 30na-tunnel.sh tunnel.sh health-check.sh revision README.md; do
            if [[ -f "$backup/code/$file" ]]; then
                cp -p "$backup/code/$file" "$BASE/$file"
            else
                rm -f "$BASE/$file"
            fi
        done
        if [[ -d "$backup/code/lib" ]]; then
            cp -a "$backup/code/lib" "$BASE/"
        fi
        if [[ -f "$backup/data/state.json" ]]; then
            cp -p "$backup/data/state.json" "$BASE/data/state.json"
        else
            rm -f "$BASE/data/state.json"
        fi
        for unit in tunnel-health-check.service tunnel-health-check.timer; do
            if [[ -f "$backup/$unit" ]]; then
                cp -p "$backup/$unit" "/etc/systemd/system/$unit"
            else
                rm -f "/etc/systemd/system/$unit"
            fi
        done
        systemctl daemon-reload || true
    fi
    if [[ -n "$timer_active" ]]; then
        systemctl start tunnel-health-check.timer || true
    fi
    if [[ -n "$agent_started" ]]; then ssh-agent -k >/dev/null || true; fi
    [[ -z "$PASSWORD_TMP" ]] || rm -rf -- "$PASSWORD_TMP"
    rm -rf -- "$TMP"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# No shell evaluation is used when reading the password file.
if [[ -z "$peer" ]]; then
    if [[ -L "$PASSWORD_CONFIG" || ( -e "$PASSWORD_CONFIG" && ! -f "$PASSWORD_CONFIG" ) ]]; then
        echo "Invalid password file: $PASSWORD_CONFIG" >&2
        exit 1
    fi
    PASSWORD_TMP="$(mktemp -d /dev/shm/30na-password.XXXXXXXX)"
    if [[ ! -e "$PASSWORD_CONFIG" ]]; then
        if ! command -v nano >/dev/null; then
            apt-get update >"$TMP/nano.log" 2>&1 &&
                apt-get install -y nano >>"$TMP/nano.log" 2>&1 ||
                { cat "$TMP/nano.log" >&2; exit 1; }
        fi
        printf 'zip-pass="Input Here"\n' > "$PASSWORD_TMP/config"
        echo "Set zip-pass in nano. Ctrl+X, Y, Enter saves and closes."
        nano -I "$PASSWORD_TMP/config" </dev/tty >/dev/tty
        config_input="$PASSWORD_TMP/config"
    else
        config_input="$PASSWORD_CONFIG"
    fi
    chmod 600 "$config_input"
    if ! awk '
        NR == 1 && /^zip-pass="[^"]+"$/ && $0 != "zip-pass=\"Input Here\"" {
            password=substr($0, 11, length($0)-11)
        }
        END {if (NR != 1 || password == "") exit 1; print password}
    ' "$config_input" >"$PASSWORD_TMP/zip-password"; then
        echo "Edit $config_input and enter one line: zip-pass=\"your password\"" >&2
        exit 1
    fi
fi

echo "Installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
if ! {
    apt-get update &&
    apt-get install -y curl git openssh-client openssh-server p7zip-full python3 iproute2 util-linux coreutils nano
} >"$TMP/packages.log" 2>&1; then
    cat "$TMP/packages.log" >&2
    exit 1
fi

echo "Downloading 30nA-TUNNEL..."
for attempt in 1 2 3; do
    if git -c http.version=HTTP/1.1 clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$TMP/repo" >"$TMP/git.log" 2>&1; then
        break
    fi
    rm -rf -- "$TMP/repo"
    if [[ "$attempt" == 3 ]]; then cat "$TMP/git.log" >&2; exit 1; fi
    sleep "$attempt"
done
if [[ -n "$revision" && "$(git -C "$TMP/repo" rev-parse HEAD)" != "$revision" ]]; then
    for attempt in 1 2 3; do
        if git -c http.version=HTTP/1.1 -C "$TMP/repo" fetch --quiet --depth 1 origin "$revision"; then break; fi
        [[ "$attempt" != 3 ]] || exit 1
        sleep "$attempt"
    done
    git -C "$TMP/repo" checkout --quiet --detach "$revision"
fi
git -C "$TMP/repo" rev-parse HEAD >"$TMP/revision"
for file in install.sh 30na-tunnel.sh tunnel.sh health-check.sh lib/restore-key.sh; do
    bash -n "$TMP/repo/$file"
done
python3 -m py_compile "$TMP/repo/manager.py" "$TMP/repo/lib/unlock-zip.py"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$TMP/repo/tests" -p 'test_manager.py' >"$TMP/tests.log" 2>&1 ||
    { cat "$TMP/tests.log" >&2; exit 1; }

register_public_key() (
    local public_key="$1" authorized="$2" fingerprint
    fingerprint="$(ssh-keygen -lf "$public_key" | awk 'NR==1 {print $2}')"
    [[ -n "$fingerprint" && ! -L "$authorized" ]] || exit 1
    exec 8>"${authorized}.lock"
    flock 8
    touch "$authorized"
    chmod 600 "$authorized"
    if ssh-keygen -lf "$authorized" 2>/dev/null |
        awk -v expected="$fingerprint" '$2==expected {found=1} END {exit !found}'; then
        return
    fi
    if [[ -s "$authorized" && "$(tail -c 1 "$authorized" | wc -l)" == 0 ]]; then
        printf '\n' >>"$authorized"
    fi
    cat "$public_key" >>"$authorized"
)

if [[ -z "$peer" ]]; then
    echo "Validating SSH backup and existing keys..."
    if ! STM_PASSWORD_FILE="$PASSWORD_TMP/zip-password" LC_ALL=C.UTF-8         bash "$TMP/repo/lib/restore-key.sh" "$ZIP" </dev/tty >"$TMP/restore.log"; then
        cat "$TMP/restore.log" >&2
        echo "Check the ZIP password in $PASSWORD_CONFIG." >&2
        exit 1
    fi
    if [[ "$config_input" != "$PASSWORD_CONFIG" ]]; then
        install -m 600 "$config_input" "$PASSWORD_CONFIG"
    fi
    register_public_key /root/.ssh/30na_windows.pub /root/.ssh/authorized_keys
    eval "$(ssh-agent -s)" >/dev/null
    agent_started=yes
    ssh-add /root/.ssh/30na_windows </dev/tty
    if [[ ! -f /root/.ssh/30na_tunnel_manager ]]; then
        ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/30na_tunnel_manager
    fi
fi

install -d -m 0750 "$BASE"
install -d -m 0700 "$BASE/data"
# Serialize with both older health checks and all current database operations.
exec 9>"$BASE/data/manager.lock"
flock 9
exec 7>"$BASE/data/health.lock"
flock 7
if systemctl is-active --quiet tunnel-health-check.timer; then
    timer_active=yes
    systemctl stop tunnel-health-check.timer
fi
systemctl stop tunnel-health-check.service || true

backup="/var/backups/30na-tunnel/$(date -u +%Y%m%dT%H%M%S)-$$"
install -d -m 0700 "$backup/code"
cp -a "$BASE/data" "$backup/data"
for unit in tunnel-health-check.service tunnel-health-check.timer; do
    [[ ! -f "/etc/systemd/system/$unit" ]] || cp -p "/etc/systemd/system/$unit" "$backup/"
done
for file in manager.py install.sh 30na-tunnel.sh tunnel.sh health-check.sh revision README.md; do
    [[ ! -f "$BASE/$file" ]] || cp -p "$BASE/$file" "$backup/code/"
done
[[ ! -d "$BASE/lib" ]] || cp -a "$BASE/lib" "$backup/code/"
updating=yes

install -d -m 0750 "$BASE/lib"
for file in install.sh 30na-tunnel.sh tunnel.sh health-check.sh; do
    install -m 0750 "$TMP/repo/$file" "$BASE/$file"
done
install -m 0640 "$TMP/repo/manager.py" "$BASE/manager.py"
install -m 0640 "$TMP/repo/lib/unlock-zip.py" "$BASE/lib/unlock-zip.py"
install -m 0750 "$TMP/repo/lib/restore-key.sh" "$BASE/lib/restore-key.sh"
install -m 0644 "$TMP/repo/README.md" "$BASE/README.md"
install -m 0640 "$TMP/revision" "$BASE/revision"
# Import migration runs under the locks already held by this process.
NT_PEER="$peer" python3 - <<'PYTHON'
import sys
sys.path.insert(0, "/opt/tunnel-manager")
import manager
state = manager.load()
if not __import__("os").environ.get("NT_PEER"):
    for endpoint in state["servers"].values():
        if endpoint.get("dashboard"):
            continue
        try:
            manager.register_management(endpoint)
        except manager.ERRORS as error:
            print(f"VPS {endpoint['host']} management key pending: {error}", flush=True)
PYTHON

cat > /etc/systemd/system/tunnel-health-check.service <<'UNIT'
[Unit]
Description=30nA Tunnel Health Check
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/bin/bash /opt/tunnel-manager/health-check.sh
UNIT
cat > /etc/systemd/system/tunnel-health-check.timer <<'UNIT'
[Unit]
Description=30nA Tunnel health check every 30 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Unit=tunnel-health-check.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now tunnel-health-check.timer
updating=""
flock -u 7
flock -u 9
ln -sf "$BASE/30na-tunnel.sh" /usr/local/bin/30na-tunnel
echo "30nA-TUNNEL installed. Backup: $backup"
if [[ -z "$peer" ]]; then
    bash "$BASE/30na-tunnel.sh" </dev/tty
fi
