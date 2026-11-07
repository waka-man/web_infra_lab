# web-03 — Alpine + OpenSSH, INTENTIONALLY VULNERABLE to CVE-2026-123158 (*sshole)
#
# WARNING: This image is deliberately built with a vulnerable OpenSSH so
# students can reproduce CVE-2026-123158 in an isolated lab. Do NOT publish
# it, do NOT expose port 22 to the internet, and do NOT use it as a general
# Alpine base. It exists only for the web_infra_lab course.
#
# CVE-2026-123158: OpenSSH sshd before 10.6p2 on musl libc without PAM
# (Alpine's default openssh-server) accepts any 257-1024 byte password for
# an account whose /etc/shadow field is "*" (no password set), provided at
# least one other account has a $5$/$6$ password hash. CVSS 3.1: 8.1 High.
# Fixed in Alpine 3.21 at openssh 9.9_p2-r1 (see web-alpine/README.md).
#
# Why not just `apk add openssh-server`?
#   Alpine's repositories now serve the *fixed* package (9.9_p2-r1 on 3.21),
#   and `apk add openssh-server=9.9_p2-r0` fails because the index only
#   lists r1. The pre-fix r0 .apk files are, however, still present on the
#   Alpine CDN, so this Dockerfile downloads them directly and installs
#   them with `apk add --allow-untrusted`. If Alpine ever removes those
#   orphaned files, the wget below fails loudly and the build stops —
#   which is the correct behaviour for a pinned-vulnerable lab image.
#   The build also verifies the installed version and fails if it is
#   anything other than the pinned vulnerable one.

FROM alpine:3.21

# Vulnerable OpenSSH version. Fixed on Alpine 3.21 is 9.9_p2-r1.
ARG OPENSSH_VERSION=9.9_p2-r0
ARG OPENSSH_REPO=v3.21

# Install the pinned vulnerable OpenSSH packages from the Alpine CDN.
# All sub-packages must be installed together at r0: installing only the
# server pulls openssh-client-default-9.9_p2-r1 from the index, which
# then conflicts (pins =r1) with the r0 packages.
RUN set -eux; \
    arch="$(apk --print-arch)"; \
    mkdir -p /tmp/openssh-pkgs; \
    cd /tmp/openssh-pkgs; \
    for pkg in openssh openssh-client-common openssh-client-default \
               openssh-server-common openssh-server openssh-keygen \
               openssh-sftp-server; do \
        wget -q "https://dl-cdn.alpinelinux.org/alpine/${OPENSSH_REPO}/main/${arch}/${pkg}-${OPENSSH_VERSION}.apk"; \
    done; \
    apk add --allow-untrusted --no-cache ./*.apk; \
    installed="$(apk info -v | sed -n 's/^openssh-server-\([0-9].*\)$/\1/p')"; \
    echo "Installed openssh-server: ${installed}"; \
    if [ "${installed}" != "${OPENSSH_VERSION}" ]; then \
        echo "ERROR: expected vulnerable openssh-server ${OPENSSH_VERSION}, got ${installed}. Refusing to build a patched image for this lab." >&2; \
        exit 1; \
    fi; \
    rm -rf /tmp/openssh-pkgs

# Supporting tools: sudo/doas for the privilege-escalation step,
# shadow for chpasswd/usermod, bash (students come from Ubuntu),
# ca-certificates for HTTPS apk repos.
RUN apk add --no-cache sudo doas shadow bash ca-certificates

# --- Accounts: both shadow states are required by the CVE -------------
# ubuntu  : real $6$ password hash (satisfies "at least one hashed
#           account" precondition; normal password login works).
# alpine  : "*" in /etc/shadow — no password, key-only login. This is
#           the vulnerable account (mirrors the `alpine` user on
#           Alpine's official tiny-cloud images). It can become root
#           via passwordless sudo/doas, which is the impact step.
# root    : ships as root:* in Alpine, but PermitRootLogin
#           prohibit-password (set below) blocks password login to it.
RUN adduser -D -u 1000 -s /bin/bash ubuntu && \
    echo 'ubuntu:pass123' | chpasswd && \
    echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    adduser -D -u 1001 -s /bin/bash alpine && \
    usermod -p '*' alpine && \
    echo 'alpine ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# doas: mirror the tiny-cloud setup (passwordless doas for `alpine`).
RUN echo 'permit nopass alpine as root' > /etc/doas.conf && \
    chmod 400 /etc/doas.conf

# Legitimate key login for the `alpine` account, so students can prove
# that (a) key auth works before/after, and (b) the bypass is specific
# to password auth. The private key is left inside the container at
# /home/alpine/demo_key for the lab — extract it with `docker cp`.
# (Never do this on a real host.)
RUN mkdir -p /home/alpine/.ssh && \
    ssh-keygen -t ed25519 -f /home/alpine/demo_key -N '' -q && \
    cp /home/alpine/demo_key.pub /home/alpine/.ssh/authorized_keys && \
    chown -R alpine:alpine /home/alpine/.ssh /home/alpine/demo_key && \
    chmod 700 /home/alpine/.ssh && \
    chmod 600 /home/alpine/.ssh/authorized_keys /home/alpine/demo_key

# --- sshd configuration: the vulnerable combination -------------------
# PasswordAuthentication yes + no PAM (Alpine's openssh-server is built
# without PAM; do NOT install openssh-server-pam here) is exactly the
# configuration CVE-2026-123158 needs. /var/empty is required for
# sshd privilege separation on Alpine.
RUN mkdir -p /var/empty && \
    sed -ri 's/#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -ri 's/#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && \
    ssh-keygen -A && \
    /usr/sbin/sshd -t

# -e: log to stderr so `docker logs web-03` shows auth attempts live
# (Alpine in a container has no syslog; sshd logs to /var/log/messages
# only when a syslog daemon is running).
CMD ["/usr/sbin/sshd", "-D", "-e"]
