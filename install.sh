#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID != 0 ]]; then
    echo 'Run install.sh as root on the manager.' >&2
    exit 1
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
for file in 30na manager.py health.py cli.py; do
    test -s "$file" || { echo "Missing $file. Run install.sh from the project checkout." >&2; exit 1; }
done
missing=()
for pair in python3:python3 ssh:openssh-client sshd:openssh-server ss:iproute2; do
    command -v "${pair%:*}" >/dev/null || missing+=("${pair#*:}")
done
if (( ${#missing[@]} )); then
    apt-get update -qq
    apt-get install -y --no-install-recommends "${missing[@]}"
fi
install -d -m 0755 /opt/30na /usr/local/bin
install -d -m 0700 /var/lib/30na/data
install -m 0644 cli.py manager.py health.py /opt/30na/
install -m 0755 30na /usr/local/bin/30na
python3 -W error -m compileall -q /opt/30na
/usr/local/bin/30na -vps
