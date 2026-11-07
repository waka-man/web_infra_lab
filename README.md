# Web Infrastructure Lab

This repository provides a lightweight environment to demonstrate web server setup and basic load balancing using Docker containers. The stack consists of two web servers (`web-01` and `web-02`), a load balancer (`lb-01`), and an intentionally vulnerable Alpine host (`web-03`, for CVE-2026-123158 — see below) connected to a custom Docker network. Each service runs Ubuntu 24.04 (web-03: Alpine 3.21) with SSH enabled to allow you to install and configure additional software.

## Requirements

- Docker and Docker Compose installed on your machine
- At least 2 GB of free RAM and a few hundred megabytes of disk space

## Setup

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd web_infra_lab
   ```
2. Bring up the lab environment (builds the images on first run):
   ```bash
   docker compose up -d --build
   ```
3. Verify that the containers are running:
   ```bash
   docker compose ps
   ```
   You should see `web-01`, `web-02`, `lb-01`, and `web-03` online. The services are attached to the `lablan` network with the following addresses:

   | Container | IP            | Exposed Ports |
   |---------- |-------------- |---------------|
   | web-01    | 172.26.0.20   | 2211 (SSH), 8080 (HTTP) |
   | web-02    | 172.26.0.12   | 2212 (SSH), 8081 (HTTP) |
   | lb-01     | 172.26.0.10   | 2210 (SSH), 8082 (HTTP), 4443 (HTTPS) |
   | web-03    | 172.26.0.13   | 2213 (SSH, Alpine — CVE-2026-123158 lab) |

4. Connect to each container using SSH if you prefer an interactive terminal. All containers include an `ubuntu` user with the password `pass123`.
   ```bash
   ssh ubuntu@localhost -p 2211  # web-01
   ssh ubuntu@localhost -p 2212  # web-02
   ssh ubuntu@localhost -p 2210  # lb-01
   ssh ubuntu@localhost -p 2213  # web-03 (Alpine; also has key-only `alpine` user)
   ```

## Nginx Setup on `web-01` and `web-02`

Within each `web-*` container install Nginx and host a small static site. For example:

```bash
sudo apt update && sudo apt install -y nginx
sudo bash -c 'echo "<h1>web-01</h1>" > /var/www/html/index.html'
```

Repeat for `web-02`, modifying the page content so you can tell the two servers apart. After starting Nginx (`sudo systemctl restart nginx`), visit the host ports http://localhost:8080 and http://localhost:8081 to verify the pages load.

## Activity – Configure HAProxy with SSL Termination on `lb-01`

Your task is to configure HAProxy on `lb-01` to load balance HTTPS requests between `web-01` and `web-02` using the **roundrobin** algorithm with SSL termination. The load balancer will handle SSL/TLS encryption while communicating with backend servers over plain HTTP.

### Prerequisites

Before configuring HAProxy, you need a self-signed SSL certificate. Generate one using:

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/ssl/private/ha_proxy_ssl.key \
  -out /etc/ssl/certs/ha_proxy_ssl.crt
```

Combine the certificate and private key into a single PEM file (required by HAProxy):

```bash
sudo cat /etc/ssl/certs/ha_proxy_ssl.crt /etc/ssl/private/ha_proxy_ssl.key | \
  sudo tee /etc/ssl/certs/ha_proxy_ssl.pem > /dev/null
```

Set proper permissions:

```bash
sudo chmod 600 /etc/ssl/certs/ha_proxy_ssl.pem
sudo chown haproxy:haproxy /etc/ssl/certs/ha_proxy_ssl.pem
```

### Steps to Configure HAProxy

1. Install HAProxy inside `lb-01`:
   ```bash
   sudo apt update && sudo apt install -y haproxy
   ```

2. Edit `/etc/haproxy/haproxy.cfg` with the following configuration:
   ```
   global
       log /dev/log    local0
       log /dev/log    local1 notice
       chroot /var/lib/haproxy
       stats socket /run/haproxy/admin.sock mode 660 level admin
       stats timeout 30s
       user haproxy
       group haproxy
       daemon

       # Default SSL material locations
       ca-base /etc/ssl/certs
       crt-base /etc/ssl/private

       # Mozilla intermediate SSL configuration
       ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
       ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
       ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

   defaults
       log     global
       mode    http
       option  httplog
       option  dontlognull
       timeout connect 5000
       timeout client  50000
       timeout server  50000

       errorfile 400 /etc/haproxy/errors/400.http
       errorfile 403 /etc/haproxy/errors/403.http
       errorfile 408 /etc/haproxy/errors/408.http
       errorfile 500 /etc/haproxy/errors/500.http
       errorfile 502 /etc/haproxy/errors/502.http
       errorfile 503 /etc/haproxy/errors/503.http
       errorfile 504 /etc/haproxy/errors/504.http

   frontend balancer_http_in
       bind *:80
       redirect scheme https code 301 if ! { ssl_fc }

   frontend balancer_https_in
       bind *:443 ssl crt /etc/ssl/certs/ha_proxy_ssl.pem
       option forwardfor
       default_backend balancer_http_out

   backend balancer_http_out
       balance roundrobin
       server web-01 web-01:80 check
       server web-02 web-02:80 check
       http-response set-header X-Served-By %[srv_name]
   ```

3. Restart HAProxy to apply your configuration:
   ```bash
   sudo systemctl restart haproxy
   ```

### Understanding the Configuration

- **HTTP to HTTPS Redirect**: The `balancer_http_in` frontend listens on port 80 and redirects all HTTP traffic to HTTPS using a 301 redirect.
- **SSL Termination**: The `balancer_https_in` frontend handles HTTPS on port 443, decrypts the traffic using the certificate, and forwards plain HTTP requests to the backend servers.
- **Load Balancing**: The `balancer_http_out` backend uses roundrobin algorithm to distribute requests between `web-01` and `web-02`.
- **Custom Header**: Each response includes `X-Served-By` header showing which backend server handled the request.
- **SSL Configuration**: Uses Mozilla's intermediate SSL configuration for strong security with TLS 1.2+ support.

### Verifying the Load Balancer

From your host machine, test HTTPS access:
```bash
curl -k https://localhost:4443
```

The `-k` flag bypasses certificate verification (needed for self-signed certificates). To see the `X-Served-By` header:
```bash
curl -k -I https://localhost:4443
```

Test the HTTP to HTTPS redirect:
```bash
curl -I http://localhost:8082
```
You should see a `301` redirect to the HTTPS URL.

Repeated requests should alternate between `web-01` and `web-02`, and the `X-Served-By` header will reveal which server handled each request.

Feel free to experiment with the configuration and explore additional features of HAProxy.

## Activity – CVE-2026-123158 (*sshole) on `web-03` (Alpine)

`web-03` is an Alpine 3.21 host with **OpenSSH 9.9p2-r0** — the version
vulnerable to **CVE-2026-123158**, an OpenSSH password-authentication
bypass on musl systems without PAM (CVSS 8.1). On a musl host with
password logins enabled, an account whose `/etc/shadow` field is `*`
(no password — e.g. a key-only user) accepts **any 257–1024 byte
password**, because musl's `crypt()` returns `"*"` for over-long keys
and sshd compares that to the stored `"*"`. Your Ubuntu hosts
(`web-01`/`web-02`, glibc + PAM) are not affected and serve as the
control group.

> ⚠️ `web-03` is **intentionally vulnerable**. Keep it on the lab
> network only; never expose port 2213 publicly.

Full write-up, root-cause walkthrough, and the instructor
demonstration script (preconditions, bypass, controls, fix, and
detection) are in [`web-alpine/README.md`](web-alpine/README.md).
Quick start:

```bash
docker compose up -d --build web-03
pip install paramiko   # once, on the host
python3 web-alpine/sshhole_demo.py                    # 300 x A -> logged in as alpine, then root
python3 web-alpine/sshhole_demo.py localhost 2213 alpine 256  # rejected (boundary)
python3 web-alpine/sshhole_demo.py localhost 2211 ubuntu 300  # web-01 Ubuntu -> rejected (control)
```

The demo needs **two password attempts on one SSH connection**
(first `"wrong"` primes sshd's salt cache, then the long password) —
`sshhole_demo.py` handles that. To reproduce the bug on bare metal /
in a VM instead, download the vulnerable Alpine 3.21.9 ISO:

```bash
./web-alpine/download-vulnerable-alpine.sh   # wget + SHA-256 verify, ~280 MB
```

Fix (in the container): `docker exec web-03 apk upgrade -U -a &&
docker restart web-03` — the restart matters, upgrading alone does
not replace the running `sshd`. To restore the vulnerable image
after patching: `docker compose up -d --force-recreate web-03`
(`--build` alone will not recreate a running container).

When you are finished with the lab environment, shut it down with:
```bash
docker compose down
```

Enjoy your lightweight web infrastructure lab!
