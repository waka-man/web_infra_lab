#!/bin/sh
# Download a vulnerable Alpine Linux ISO for the CVE-2026-123158 lab.
#
# Alpine 3.21.9 (released 2026-10-23) is the last 3.21 point release
# BEFORE the *sshole fix (Alpine 3.21.10, 2026-11-05, openssh
# 9.9_p2-r1). Its ISO therefore contains the vulnerable OpenSSH
# 9.9_p2-r0 in the image's package set, and an install from it —
# before any `apk upgrade` — reproduces CVE-2026-123158 on bare
# metal or in a VM, exactly like the web-03 container.
#
# WARNING: the ISO is intentionally vulnerable. Use it only on an
# isolated lab network / VM with no route to the internet, and
# `apk upgrade` (or disable password auth) as soon as you are done.
#
# Usage:
#   ./download-vulnerable-alpine.sh [dest-dir] [arch]
# Defaults: dest-dir=.  arch=x86_64
#
# The ISO is ~280 MB (standard) — it is NOT committed to git.
# Add *.iso to .gitignore if you keep it in this repo directory.
set -eu

DEST="${1:-.}"
ARCH="${2:-x86_64}"
VERSION="3.21.9"
BASE="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/${ARCH}"
ISO="alpine-standard-${VERSION}-${ARCH}.iso"

mkdir -p "$DEST"
cd "$DEST"

echo "Downloading vulnerable Alpine ${VERSION} (${ARCH}) ISO..."
wget -c "${BASE}/${ISO}"
wget -c "${BASE}/${ISO}.sha256"

echo "Verifying SHA-256..."
# The .sha256 file from Alpine contains "<hash>  <filename>" in a
# format sha256sum can check directly.
sha256sum -c "${ISO}.sha256"

echo ""
echo "Downloaded: $(pwd)/${ISO}"
echo ""
echo "Next steps (VM / bare metal, lab network only):"
echo "  1. Boot the ISO in your VM of choice (e.g. virt-manager, VirtualBox, QEMU)."
echo "  2. Install Alpine, set up networking, then:"
echo "       apk add openssh-server"
echo "       rc-service sshd start        # or: rc-service sshd add sshd"
echo "  3. Create the two-account precondition (see web-alpine/README.md §4):"
echo "       adduser -D -s /bin/sh alice   # will get '*' in /etc/shadow"
echo "       adduser -D -s /bin/sh bob && echo 'bob:BobPass-123' | chpasswd"
echo "  4. From your lab host, run the demo:"
echo "       python3 ../web-alpine/sshhole_demo.py <vm-ip> 22 alice 300"
echo "     (sshhole_demo.py is lab-localhost-only by default; for a VM on"
echo "      your lab network, edit ALLOWED_HOSTS or pass the VM IP after"
echo "      adding it there — never point it at a public host.)"
echo ""
echo "Fix when done:  apk upgrade -U -a && rc-service sshd restart"
echo "   (the restart matters — upgrading the package alone does not"
echo "    replace the running sshd)"
