# Maintaining 30na

## Start a task
Check git status, branch and base commit. Read README.md and
docs/architecture.md before changing the command contract. Use the review
branch for this rewrite. Record actual commands and results in the handoff.
Release, production acceptance and main-branch integration await the owner's
approval.

## Code map
- cli.py owns command dispatch (MODULES), argument parsing, enrollment,
  selectors, interactive setup and terminal reports.
- manager.py owns serialized SQLite snapshots, authenticated execution, port
  checks, scoped OpenSSH credentials and systemd resource lifecycle.
- health.py owns observable states, bounded traffic probes and check history.
- install.sh installs manager-side dependencies and files. The 30na wrapper
  forwards arguments to the installed entry point.
- tests/test_manager.py covers failure and retry invariants. tests/test_cli.py
  covers the command contract. tests/test_openssh.py uses real SSH forwarding
  with a test supervisor. tests/test_config.py exercises native unit parsers.

## Extend the CLI
For a future module such as -unzip, first agree its inputs, actions and
exit codes. Implement it in its own module. Add its handler to the dispatcher
and its own parser/help; keep unrelated commands independent of tunnel state,
root checks and SSH requirements where applicable. Add its runtime files to
the installer. Exercise the installed command, not only a Python function.
Treat -unzip as a future extension until explicitly requested.

## Invariants for every change
Keep ingress/destination roles stable in both modes. Never reassign IDs.
Persist pending ownership before remote mutations and keep it on partial
failure. Retry cleanup through the normal remove command. Never kill a process
by port or adopt foreign units. Store paths and public identity metadata only;
private management keys stay with their owner. Preserve shell argument quoting
and strict host-key checking. Keep output readable with stdout redirected.
Changes to stored data require compatibility tests and an explicit migration.

## Verify and hand off
Run bash -n install.sh, sh -n 30na, python3 -W error -m compileall -q .,
python3 -W error -m unittest discover -s tests -v and git diff --check.
Run with sshd, ss and systemd-analyze installed. Inspect skipped tests. For
lifecycle changes verify Forward, Reverse, peer-to-peer selection, payload,
port reuse, cascade, unreachable peer and preservation of unrelated listeners.
Document the difference between loopback, CI, and operator VPS verification.

Update this guide in the same change whenever commands, module ownership,
installation, state format or verification requirements change. Keep example
commands in README and the architecture contract synchronized.
