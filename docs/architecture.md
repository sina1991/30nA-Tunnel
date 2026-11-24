# 30na CLI architecture

## Installation and identity
A fresh Ubuntu manager registers itself as VPS 1 and starts with zero tunnels.
Use root on the manager. Store inventory and operation checkpoints in SQLite
under /var/lib/30na/data. Serialize operations across CLI processes. Install
under /opt/30na with /usr/local/bin/30na as entry point. Existing v2 units,
registries and keys remain separately owned. An occupied legacy port is reported.

## Commands
|Command|Action|
|---|---|
|30na -h|List modules|
|30na -vps|List inventory, run SSH checks, print examples|
|30na -tunnel|List managed tunnels, health and selectable endpoints, print examples|
|30na -vps -tunnel|List both inventories, test peers and active tunnels, summarize|
|30na -vps -add -ip IP|Register an authenticated IPv4 endpoint|
|30na -vps -add -domain NAME|Register a domain and its IPv4 address|
|30na -vps -remove -id ID or -remove -ip IP|Remove dependent tunnels, then peer|
|30na -vps -test -id ID or -test -all|Run a short authenticated command|
|30na -tunnel -add|Choose local, remote, input port, destination port, mode|
|30na -tunnel -add -local A -remote B -local-port P -remote-port Q -mode MODE|Create and start|
|30na -tunnel -remove -id ID|Stop, clean up, verify port release|
|30na -tunnel -test -id ID or -test -all|Probe ingress and report results|

Each endpoint accepts a registered ID, IP or domain. Enrollment runs a short
command over authenticated SSH; it installs no software. Root, SSH port 22 and
/root/.ssh/30na_windows are defaults. Override with -ssh-port and -sshkey.
Verify the remote host key before enrollment. Management private keys remain
on the manager. The local endpoint cannot be removed.

## Tunnel ownership
Local always denotes public ingress. Remote always hosts 127.0.0.1:Q.
Forward starts ssh -L on Local; Reverse starts ssh -R on Remote. Both peers
may be remote from the manager. Each tunnel owns a random account, scoped
forwarding authorization, dedicated client key and systemd unit. Validate
sshd configuration before reload. The unit starts on boot and restarts on
connection loss. Persist ownership before external changes.
Check bind availability on Local before creation and after removal. On error
retain recoverable state. Remove only owned resources. VPS removal covers both
roles and retains the VPS when dependent cleanup is pending.

## Status and acceptance
UP requires an active unit and expected listener on Local. A traffic test
requires application bytes for OK. A silent or unsupported service reports
UNVERIFIED; a confirmed missing listener or refused destination reports FAIL.
Transport errors identify the endpoint. Each probe has a deadline. Group
checks continue after individual failures. Record the check time and reason.
Use color only on interactive terminals; honor NO_COLOR. Generate examples
from registered endpoints and existing tunnel IDs.
Validate real SSH -L and -R data flow, port reuse, peer-to-peer operation,
foreign-port preservation, restart, partial cleanup and command parsing.
Production acceptance and release require the operator's final approval.
