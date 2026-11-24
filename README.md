# 30na · VPS and SSH tunnel management

Run commands as root on the Linux manager. This branch is for acceptance testing.
Ubuntu 22.04 and 24.04 with systemd and OpenSSH are the target platforms.

## Install the review branch
```bash
clear
git clone --branch rewrite/30na-cli --single-branch https://github.com/sina1991/30nA-Tunnel.git 30na-cli
cd 30na-cli
bash install.sh
```
To update this checkout, run `git pull --ff-only` and `bash install.sh`.
A fresh installation lists only this VPS (ID 1). The new registry, application
and units have independent ownership from the previous manager. Ports already
occupied by an existing service remain occupied.

## Register and check a VPS
The manager needs root SSH access with a verified known_hosts entry and a usable
private key (or its unlocked identity in the current SSH agent). For a new host,
verify the host fingerprint against the provider console during the first
interactive login. On the **Linux manager**:
```bash
clear
ssh -i /root/.ssh/30na_windows -o IdentitiesOnly=yes root@gr03.30na.top hostname
30na -vps -add -domain gr03.30na.top -sshkey /root/.ssh/30na_windows
30na -vps
```
Alternatively register by IP after verifying that address's host key:
```bash
30na -vps -add -ip 178.83.46.45
30na -vps -test -all
```
Registration reads the machine ID over SSH. Custom management ports use
`-ssh-port 2222`. At tunnel creation time both endpoints need Python 3,
iproute2, systemd, OpenSSH client/server and an sshd configuration including
/etc/ssh/sshd_config.d/*.conf. Enrollment does not install these on the peer.

## Create, test and remove a tunnel
With Iran as local manager (ID 1) and a registered peer (ID 2):
```bash
30na -tunnel -add -local 1 -remote 2 -local-port 18443 -remote-port 443 -mode reverse
30na -tunnel
30na -vps -tunnel
```
Users connect to the Iran IPv4 on port 18443. The peer opens SSH back to Iran
and delivers traffic to its own 127.0.0.1:443. For Forward, the ingress host
opens SSH to the destination instead. Both VPS selectors accept IDs, addresses
and domain names resolving to registered addresses:
```bash
30na -tunnel -add -local i.30na.top -remote gr04.30na.top -local-port 15443 -remote-port 443 -mode forward
30na -tunnel -test -all
30na -tunnel -remove -id 1
```
Use the IDs in your output. Interactive setup is `30na -tunnel -add`.
Removing a VPS also removes every dependent tunnel in either direction:
```bash
30na -vps -remove -id 2
# Alternative selection by address
30na -vps -remove -ip 178.83.46.45
```
On partial cleanup restore SSH reachability and repeat the removal command.
If creation was interrupted, find the pending ID with `30na -tunnel` and
remove it before retrying. Removing a tunnel verifies release of its ingress
port. The destination service continues running.

## Read the output
UP requires a running unit and a matching ingress listener. Tunnel Test checks
the destination listener and tries a TLS handshake on destination port 443,
or reads application greeting bytes on other ports. TLS here measures traffic
flow, with no certificate-identity assertion. A silent service or one needing
specific SNI, credentials or client payload can show UNVERIFIED. This check
does not authenticate a VPN user. DOWN units are skipped in active-only tests.
Exit 0 indicates success, 1 includes unsuccessful/inconclusive checks, and 2
indicates argparse usage errors. Colors adapt to the terminal; NO_COLOR turns
them off. Use `30na -h` for modules and `30na -tunnel -h` for syntax.

[Architecture](docs/architecture.md) · [AI contributor guide](AGENTS.md)
