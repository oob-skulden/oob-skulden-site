---
title: "I Hardened a Grafana Stack From \"Please Hack Me\" to Production-Ready. Here's Every Command I Ran."
date: 2026-02-15T12:00:00-05:00
draft: false
author: "Oob Skulden™"
description: "A complete live hardening session for a Grafana monitoring stack  --  every command, every failure, every fix. 15 vulnerabilities across seven categories, from anonymous access and exposed Prometheus endpoints to plaintext secrets and a single browser tab that broke the rate limiter."
tags:
  - Grafana
  - Prometheus
  - Monitoring Security
  - HAProxy
  - Docker
  - Secrets Management
  - Container Security
  - Homelab
  - Hardening
categories:
  - Security Audits
keywords:
  - grafana hardening guide
  - grafana security audit
  - prometheus security
  - grafana anonymous access
  - grafana secrets management
  - docker container security hardening
  - haproxy tls configuration
  - monitoring stack security
  - homelab grafana hardening
  - grafana production security
  - prometheus exposed endpoints
  - grafana rate limiting
  - openbao secrets grafana
showToc: true
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
---


> **Disclaimer:** All testing was performed against infrastructure owned and operated by the author in a private lab environment. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent laws in other jurisdictions. This content is provided for educational and defensive security research purposes only. Do not test against systems you do not own or have explicit written authorization to test.
>
> This content represents personal educational work conducted in a home lab environment on personal equipment. It does not reflect the views, opinions, or positions of any employer or affiliated organization. All security methodologies are derived from publicly available frameworks, published CVE advisories, and open-source tool documentation. All tools referenced are free, open-source, and publicly available.


---

Your Grafana instance has a weak password. Your Prometheus is wide open. Your exporters are broadcasting your entire infrastructure topology to anyone who asks. And your secrets? Sitting in a plaintext `.env` file with `chmod 644`.

I know this because mine was, too.

This is the complete, unfiltered lab notebook from hardening a Grafana monitoring stack  --  every command, every output, every failure, and the moment a single browser tab broke my rate limiter. No sanitized tutorial energy here. Just the raw reality of taking a stack from "please hack me" to defense-in-depth across seven vulnerability categories in about six hours.

The methodology is dead simple: **one step at a time. Explain. Execute. Validate. Proceed.** That rule got established early, after the very first vulnerability fix went sideways because I tried to combine steps and skip explanations. More on that in a moment.

{{< youtube xNsXRXXgRrQ >}}

---

## The Environment

Four machines across four VLANs:

| Host | IP | VLAN | Role |
|---|---|---|---|
| Grafana-lab | 192.168.75.109 | 75 | Monitoring stack |
| OpenBAO-lab | 192.168.100.182 | 100 | Secrets management & PKI |
| Jump Box | 192.168.50.10 | 50 | Remote validation |
| Authentik-lab | 192.168.80.54 | 80 | Identity provider |

Stack: Grafana 12.3.2, Prometheus, HAProxy 3.0.11, OpenBAO 2.5.0, Docker on Debian 13.

---

## The Starting State (a.k.a. "The Crime Scene")

Before touching anything, here's what `docker-compose.yml` looked like:

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    env_file:
      - .env
    ports:
      - "3000:3000"
    volumes:
      - grafana-storage:/var/lib/grafana
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-storage:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    restart: unless-stopped

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    restart: unless-stopped

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    container_name: blackbox-exporter
    ports:
      - "9115:9115"
    restart: unless-stopped

volumes:
  grafana-storage:
  prometheus-storage:
```

And the `.env` file? A masterclass in what not to do:

```bash
GF_SERVER_ROOT_URL=http://192.168.75.109:3000
GF_AUTH_GENERIC_OAUTH_ENABLED=true
GF_AUTH_GENERIC_OAUTH_NAME=Authentik
GF_AUTH_GENERIC_OAUTH_CLIENT_ID=grafana-client
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=<redacted>
GF_AUTH_GENERIC_OAUTH_SCOPES=openid profile email groups
GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://192.168.80.54:9000/application/o/authorize/
GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://192.168.80.54:9000/application/o/token/
GF_AUTH_GENERIC_OAUTH_API_URL=http://192.168.80.54:9000/application/o/userinfo
GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true
GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN=false
GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=contains(groups[*], 'Grafana Admins') && 'Admin' || 'Viewer'
GF_USERS_ALLOW_SIGN_UP=false
GF_SECURITY_ADMIN_PASSWORD=<redacted>
PROMETHEUS_PASSWORD=<redacted>
```

Let me count the ways this was broken:

- Admin password: trivially guessable
- No TLS  --  everything plaintext HTTP
- Prometheus: no auth, exposed on `0.0.0.0:9090`
- Grafana: exposed on `0.0.0.0:3000`
- All exporters: exposed on `0.0.0.0` (ports 9100, 8080, 9115)
- No session timeouts, no rate limiting
- All secrets in plaintext on disk
- No capability restrictions, no resource limits

Every single vulnerability was wide open. Let's fix them.

[![Before and after architecture showing 15 vulnerabilities closed across the monitoring stack](/images/ep3-before-after.jpg)](/images/ep3-before-after.jpg)

---

## Chapter 1: Default/Weak Credentials (VULN-01)

### The False Start

Full disclosure: the first attempt at this fix went sideways. Steps got combined, explanations got skipped, the approach derailed. The instruction I gave myself was blunt:

> "DUDE, I need to start over. You didn't say that. Moving forward, we are going to do 1 step at a time, verify, and short explanation of what we are doing."

That single moment established the methodology for the entire project. Every chapter that follows exists because of that reset.

### The Actual Fix

**Generate a strong admin password:**

```bash
openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 32 && echo
```

What this does: `openssl rand -base64 48` generates 48 bytes of random data encoded as base64. `tr -dc 'a-zA-Z0-9'` strips everything that isn't alphanumeric. `head -c 32` takes the first 32 characters. You get a password that looks like line noise, which is exactly what you want.

Output: `<redacted>`

**Change the live Grafana admin password via the API:**

This is a subtlety that trips people up. Grafana stores its password in its SQLite database, not the `.env` file. The `.env` entry is only for future container rebuilds. We hit the API first because it needs the *current* password to authenticate  --  if we update `.env` and recreate the container first, we could get a mismatch.

```bash
curl -s -X PUT -u admin:<redacted> -H "Content-Type: application/json" \
  -d '{"oldPassword":"<redacted>","newPassword":"<redacted>","confirmNew":"<redacted>"}' \
  http://127.0.0.1:3000/api/user/password
```

Output: `{"message":"User password changed"}`

**Verify the old password is rejected:**

```bash
curl -s -o /dev/null -w "%{http_code}" -u admin:<redacted> http://127.0.0.1:3000/api/org
```

Output: `401`  --  dead.

**Verify the new password works:**

```bash
curl -s -o /dev/null -w "%{http_code}" -u admin:<redacted> http://127.0.0.1:3000/api/org
```

Output: `200`  --  we're in.

**Update the `.env` file:**

```bash
sed -i 's|^GF_SECURITY_ADMIN_PASSWORD=.*|GF_SECURITY_ADMIN_PASSWORD=<redacted>|' ~/monitoring/.env
```

The `|` delimiter instead of `/` avoids issues if passwords contain slashes. Small thing. Saves you twenty minutes of debugging.

**Verify `.env` permissions didn't change** (because `sed -i` sometimes does that):

```bash
ls -la ~/monitoring/.env
```

Output: `-rw------- 1 oob oob 899 Mar 1 14:52 .env`  --  still 600.

**Check for rogue service accounts** created during the "Break It" phase:

```bash
curl -s -u admin:<redacted> \
  http://127.0.0.1:3000/api/serviceaccounts/search | python3 -m json.tool
```

```json
{
    "totalCount": 0,
    "serviceAccounts": [],
    "page": 1,
    "perPage": 1000
}
```

Zero service accounts. Clean.

**One more: verify `admin:admin` is also rejected:**

```bash
curl -s -o /dev/null -w "%{http_code}" -u admin:admin http://127.0.0.1:3000/api/org
```

Output: `401`

**VULN-01: FIXED.**

*Compliance: NIST IA-5 (Authenticator Management), CIS 5.2 (Unique Passwords), PCI-DSS 8.3.6*

---

## Chapter 2: TLS Encryption with HAProxy (VULN-10)

All traffic to Grafana was unencrypted HTTP. Credentials, session tokens, dashboard data  --  everything transmitted in plaintext. Anyone on the network could capture it with Wireshark.

**Backup first** (always):

```bash
cp ~/monitoring/docker-compose.yml ~/monitoring/docker-compose.yml.backup.$(date +%Y%m%d-%H%M%S)
```

**Install HAProxy:**

```bash
sudo apt update && sudo apt install -y haproxy
```

```bash
haproxy -v
# HAProxy version 3.0.11-1+deb13u2 2026/02/11
```

**Create certificate directory and generate a self-signed TLS certificate:**

```bash
sudo mkdir -p /etc/haproxy/certs

sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /tmp/grafana-key.pem -out /tmp/grafana-cert.pem \
  -subj "/CN=192.168.75.109/O=Oob Skulden Lab/OU=Monitoring"
```

Quick breakdown of the flags:
- `-x509`  --  self-signed certificate, not a CSR
- `-nodes`  --  don't encrypt the private key (HAProxy needs to read it without prompting)
- `-days 365`  --  one year validity
- `-newkey rsa:2048`  --  fresh 2048-bit RSA key

This is temporary. Later it gets replaced with a proper certificate from OpenBAO's PKI engine.

**Combine key and cert for HAProxy** (it expects both in a single `.pem`):

```bash
sudo bash -c "cat /tmp/grafana-cert.pem /tmp/grafana-key.pem > /etc/haproxy/certs/grafana.pem"
```

**Lock down the cert and clean up temp files:**

```bash
sudo chmod 600 /etc/haproxy/certs/grafana.pem
sudo rm -f /tmp/grafana-key.pem /tmp/grafana-cert.pem
```

**Backup the default HAProxy config, then write the real one:**

```bash
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.backup.$(date +%Y%m%d-%H%M%S)
sudo rm /etc/haproxy/haproxy.cfg
```

```bash
sudo tee /etc/haproxy/haproxy.cfg > /dev/null << 'EOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384
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

frontend http_redirect
    bind *:80
    http-request redirect scheme https code 301

frontend https_frontend
    bind *:443 ssl crt /etc/haproxy/certs/grafana.pem
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Frame-Options "DENY"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    http-response set-header Content-Security-Policy "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; connect-src 'self' wss:"
    default_backend grafana_backend

backend grafana_backend
    server grafana 127.0.0.1:3000 check

frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
EOF
```

The security headers deserve a moment:

- **HSTS**  --  tells browsers to always use HTTPS
- **X-Frame-Options DENY**  --  prevents iframe embedding (clickjacking defense)
- **X-Content-Type-Options**  --  prevents MIME sniffing attacks
- **X-XSS-Protection**  --  enables the browser's XSS filter
- **Referrer-Policy**  --  controls what URL info leaks on external links
- **CSP**  --  restricts what scripts and resources the page can load

**Validate and start:**

```bash
sudo /usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl start haproxy && sudo systemctl status haproxy
```

Output: `Active: active (running)`  --  three ports listening: `*:80` (redirect), `*:443` (HTTPS), `127.0.0.1:8404` (stats, localhost only).

[![HAProxy traffic flow showing TLS termination, localhost binding, and rate limiting lesson](/images/ep3-haproxy-flow.jpg)](/images/ep3-haproxy-flow.jpg)

**Test from localhost:**

```bash
curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1/
# 200

curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/
# 301
```

The `-k` flag is critical here  --  without it, curl rejects self-signed certificates and returns `000`, making you think the service is down. Ask me how I know.

### The Bypass Problem

HAProxy was working great. One problem: Grafana was *still directly accessible on port 3000 from the network*, bypassing HAProxy and HTTPS entirely.

From the jump box:

```bash
curl -s -o /dev/null -w "%{http_code}" http://192.168.75.109:3000/login
# 200
```

All that TLS work, and you could just... go around it.

**The fix  --  bind Grafana to localhost only:**

In `docker-compose.yml`, changed:

```yaml
ports:
  - "3000:3000"
```

To:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

```bash
sudo docker compose up -d --force-recreate grafana
```

**Update ROOT_URL to HTTPS:**

```bash
sed -i 's|^GF_SERVER_ROOT_URL=.*|GF_SERVER_ROOT_URL=https://192.168.75.109|' ~/monitoring/.env
```

**Final validation from the jump box:**

```bash
# HTTPS works
curl -sk -o /dev/null -w "%{http_code}" https://192.168.75.109/login
# 200

# Direct port 3000 is dead
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:3000/
# 000
```

**VULN-10: FIXED.**

*Compliance: NIST SC-8 (Transmission Confidentiality), CIS 3.10 (Encrypt Data in Transit), PCI-DSS 4.1*

---

## Chapter 3: Prometheus Authentication (VULN-02)

Prometheus was wide open on port 9090 with no authentication. Anyone on the network could query the entire infrastructure topology  --  container names, IP addresses, resource metrics, job configurations  --  without credentials. It's an attacker's reconnaissance dream.

**Install htpasswd and generate credentials:**

```bash
sudo apt install -y apache2-utils

openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24 && echo
```

Output: `<redacted>`  --  24 characters (shorter than Grafana's 32, this is machine-to-machine).

**Generate the bcrypt hash:**

```bash
htpasswd -nbBC 10 "" "<redacted>" | tr -d ':\n' | sed 's/^://' && echo
```

`-B` = bcrypt, `-C 10` = cost factor 10. The `tr` and `sed` strip formatting artifacts `htpasswd` adds.

Output: `<redacted>`

**Add the password to `.env`:**

```bash
echo 'PROMETHEUS_PASSWORD=<redacted>' >> ~/monitoring/.env
```

**Create the Prometheus auth config:**

```bash
cat > ~/monitoring/prometheus/web-config.yml << 'EOF'
basic_auth_users:
    prometheus: <redacted>
EOF
```

**Critical: Set permissions to 644, NOT 600.**

Here's a gotcha that will eat an hour of your life. Prometheus runs as user `nobody` (UID 65534) inside the container. With `600`, only the file owner can read it  --  `nobody` gets "permission denied" and Prometheus won't start.

644 is acceptable because the file contains a bcrypt hash, not the password. Even if someone reads the hash, they can't reverse it.

```bash
chmod 644 ~/monitoring/prometheus/web-config.yml
```

**Create a Grafana provisioned datasource with credentials:**

```bash
mkdir -p ~/monitoring/grafana/provisioning/datasources

cat > ~/monitoring/grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    basicAuth: true
    basicAuthUser: prometheus
    secureJsonData:
      basicAuthPassword: ${PROMETHEUS_PASSWORD}
    editable: false
EOF
```

The `${PROMETHEUS_PASSWORD}` variable gets resolved from Grafana's environment at startup.

**Four modifications to docker-compose.yml:**

```bash
# 1. Bind Prometheus to localhost
sed -i 's/"9090:9090"/"127.0.0.1:9090:9090"/' docker-compose.yml

# 2. Mount web-config.yml (add to prometheus volumes)
# 3. Add web-config command flag (add to prometheus command)
# 4. Mount Grafana provisioning directory (add to grafana volumes)
```

The prometheus service now includes:

```yaml
volumes:
  - ./prometheus/web-config.yml:/etc/prometheus/web-config.yml:ro
command:
  - '--web.config.file=/etc/prometheus/web-config.yml'
```

And grafana gets:

```yaml
volumes:
  - ./grafana/provisioning:/etc/grafana/provisioning:ro
```

**Recreate and validate:**

```bash
sudo docker compose up -d --force-recreate
```

```bash
# Unauthenticated = rejected
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9090/metrics
# 401

# Authenticated = works
curl -s -o /dev/null -w "%{http_code}" -u prometheus:<redacted> http://127.0.0.1:9090/metrics
# 200

# Blocked from network (jump box)
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:9090/metrics
# 000
```

**Verify the datasource in Grafana** (one datasource, with `basicAuth`, no duplicates):

```bash
curl -s -u admin:<redacted> \
  http://127.0.0.1:3000/api/datasources | python3 -m json.tool
```

Single datasource with `basicAuth: true`, `readOnly: true`. No duplicates. This matters  --  duplicate datasources without `basicAuth` configured will trigger browser `WWW-Authenticate` popups that make you think authentication is broken when it isn't.

**VULN-02: FIXED.**

*Compliance: NIST AC-3, IA-2 (Access Enforcement, Authentication), CIS 6.3, SOC 2 CC6.1*

---

## Chapter 4: Container Hardening + Resource Limits (VULN-09/11)

Grafana ran with all ~35 Linux capabilities enabled and no resource limits. A compromised container could manipulate raw network packets, mount filesystems, debug other processes, and consume all host resources for cryptomining.

**Check the current state:**

```bash
sudo docker inspect grafana --format '{{json .HostConfig.CapDrop}}'
# null

sudo docker inspect grafana --format 'Memory: {{.HostConfig.Memory}} CPU: {{.HostConfig.CpuQuota}}'
# Memory: 0 CPU: 0
```

No capabilities dropped. No resource limits. Wide open.

**Full rewrite of docker-compose.yml** (using `cat` instead of `sed` because `sed` causes YAML corruption  --  learned that the hard way in Phase 5):

```bash
cat > ~/monitoring/docker-compose.yml << 'EOF'
services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    env_file:
      - .env
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
      - DAC_OVERRIDE
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus/web-config.yml:/etc/prometheus/web-config.yml:ro
      - prometheus-storage:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.config.file=/etc/prometheus/web-config.yml'
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    restart: unless-stopped

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    restart: unless-stopped

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    container_name: blackbox-exporter
    ports:
      - "9115:9115"
    restart: unless-stopped

volumes:
  grafana-storage:
  prometheus-storage:
EOF
```

What's new in the Grafana service:

- **`no-new-privileges`**  --  prevents privilege escalation via setuid binaries
- **`cap_drop: ALL`**  --  removes all ~35 Linux capabilities
- **`cap_add`**  --  adds back only the 4 Grafana actually needs: `CHOWN` (change file ownership during startup), `SETGID`/`SETUID` (switch to the grafana user), `DAC_OVERRIDE` (critical for SQLite writes)
- **`deploy: resources`**  --  limits to 1 CPU and 512MB, reserves 0.25 CPU and 128MB

That `DAC_OVERRIDE` capability is a gotcha worth emphasizing: drop it, and Grafana enters a crash loop with "attempt to write a readonly database." The Grafana container's SQLite architecture requires it. Don't try `read_only: true` on the filesystem either  --  same crash, same reason.

**Validate and deploy:**

```bash
sudo docker compose config --quiet && echo "YAML OK"
# YAML OK

sudo docker compose up -d --force-recreate grafana
sleep 5 && sudo docker ps | grep grafana
```

Running, no restart loop.

**Verify hardening applied:**

```bash
sudo docker inspect grafana --format '{{json .HostConfig.CapDrop}}'
# ["ALL"]

sudo docker inspect grafana --format '{{json .HostConfig.CapAdd}}'
# ["CHOWN","DAC_OVERRIDE","SETGID","SETUID"]

sudo docker inspect grafana --format '{{json .HostConfig.SecurityOpt}}'
# ["no-new-privileges"]

sudo docker inspect grafana --format 'Memory: {{.HostConfig.Memory}} CPU: {{.HostConfig.NanoCpus}}'
# Memory: 536870912 CPU: 1000000000
# (536870912 = 512MB, 1000000000 nanocpus = 1 CPU)
```

**VULN-09/11: FIXED.**

*Compliance: NIST SC-39, SC-6 (Process Isolation, Resource Availability), CIS Docker 5.3, 5.25, SOC 2 CC6.1*

---

## Chapter 5: Exporter Lockdown (VULN-03/04)

Three exporters were broadcasting to anyone who asked:

- **Node Exporter** (9100)  --  host OS details, CPU, memory, disk, network
- **cAdvisor** (8080)  --  container configs, environment variables, resource usage
- **Blackbox Exporter** (9115)  --  SSRF attack vector across VLANs

**Prove the problem exists** (from the jump box):

```bash
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:9100/metrics  # 200
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:8080/         # 200
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:9115/metrics  # 200
```

All three wide open from another VLAN. That cAdvisor endpoint? It can leak environment variables from running containers. Think about what's in those variables for a moment.

[![Exporter lockdown showing before/after network exposure and the self-scrape surprise](/images/ep3-exporter-lockdown.jpg)](/images/ep3-exporter-lockdown.jpg)

**The fix - remove port bindings entirely:**

We rewrote `docker-compose.yml`, removing the `ports:` sections from all three exporters. Why remove them entirely instead of binding to `127.0.0.1`? Because there's no reason to access these from the host. Only Prometheus needs them, and it reaches them through Docker's internal network by container name. Less surface area.

```bash
cp ~/monitoring/docker-compose.yml ~/monitoring/docker-compose.yml.backup.$(date +%Y%m%d-%H%M%S)
sudo docker compose config --quiet && echo "YAML OK"
sudo docker compose up -d --force-recreate
sleep 60
```

**Verify from the jump box:**

```bash
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:9100/metrics  # 000
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:8080/         # 000
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://192.168.75.109:9115/metrics  # 000
```

All three dead from the network. `docker ps` confirms  --  exporters show their container port but no `0.0.0.0:` prefix. Not published to the host.

### The Self-Scrape Surprise

**Verify Prometheus can still scrape internally:**

```bash
curl -s -u prometheus:<redacted> http://127.0.0.1:9090/api/v1/targets | \
  python3 -c "import sys,json; data=json.load(sys.stdin); [print(t['labels']['job'], t['health']) for t in data['data']['activeTargets']]"
```

```
blackbox      up
cadvisor      up
grafana       up
node-exporter up
prometheus    down
```

Four up. One down. Prometheus can't scrape *itself*.

The `prometheus` job in `prometheus.yml` was scraping `localhost:9090` but didn't include basic auth credentials. After we added authentication in VULN-02, Prometheus needs credentials to scrape its own metrics endpoint. It was authenticating everyone else out, including itself.

**Fix  --  rewrite prometheus.yml with self-scrape auth:**

```bash
cp ~/monitoring/prometheus/prometheus.yml ~/monitoring/prometheus/prometheus.yml.backup.$(date +%Y%m%d-%H%M%S)

cat > ~/monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    basic_auth:
      username: prometheus
      password: <redacted>
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']

  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']

  - job_name: 'blackbox'
    static_configs:
      - targets: ['blackbox-exporter:9115']
EOF
```

```bash
sudo docker compose config --quiet && echo "YAML OK"
sudo docker compose restart prometheus
sleep 60
```

**All five targets healthy:**

```
blackbox      up
cadvisor      up
grafana       up
node-exporter up
prometheus    up
```

**VULN-03/04: FIXED.**

*Compliance: NIST AC-4, SC-7 (Information Flow, Boundary Protection), CIS 3.3, SOC 2 CC6.6*

---

## Chapter 6: Session Hardening (VULN-06/07)

Grafana sessions lasted 7+ days by default. A disabled user keeps access for a week. No brute-force protection.

**Check the current state:**

```bash
sudo docker exec grafana env | grep -iE "(lifetime|rotation|sign_up)" | sort
```

```
GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true
GF_USERS_ALLOW_SIGN_UP=false
```

No session timeouts configured. Running with defaults: 7-day inactive, 30-day absolute lifetime, no token rotation. Fire someone on Monday, they still have access on Friday.

**Add session hardening variables to `.env`:**

```bash
cat >> ~/monitoring/.env << 'EOF'
GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h
GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h
GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10
EOF
```

What each one does:
- `INACTIVE_LIFETIME=1h`  --  idle sessions expire after 1 hour
- `MAXIMUM_LIFETIME=24h`  --  no session lasts longer than 24 hours, period
- `TOKEN_ROTATION=10`  --  session token changes every 10 minutes, limiting the window if a token is stolen

**Recreate Grafana** (not `restart`  --  `restart` won't read new environment variables):

```bash
cd ~/monitoring && sudo docker compose up -d --force-recreate grafana
```

**Verify:**

```bash
sudo docker exec grafana env | grep -iE "(lifetime|rotation)" | sort
```

```
GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h
GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h
GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10
```

All three loaded.

**VULN-06/07: FIXED.**

*Compliance: NIST AC-11 (Session Lock), AC-12 (Session Termination), SC-23 (Session Authenticity), CIS 6.2*

---

## Chapter 7: Rate Limiting  --  The Easy Part, Then The Hard Part

### The Implementation

Added a stick-table-based rate limiter to HAProxy's `https_frontend`:

```
stick-table type ip size 100k expire 10s store http_req_rate(10s)
http-request track-sc0 src
http-request deny deny_status 429 if { sc_http_req_rate(0) gt 20 }
```

How this works: HAProxy maintains an in-memory database keyed by client IP address, tracking how many HTTP requests each IP makes in a sliding 10-second window. If an IP exceeds the threshold, it gets a `429 Too Many Requests` response. Entries expire after 10 seconds of inactivity. The table can track 100,000 unique IPs simultaneously.

**Initial test from the jump box:**

```bash
for i in $(seq 1 30); do curl -sk -o /dev/null -w "%{http_code} " https://192.168.75.109/login; done && echo
```

```
200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 429 429 429 429 429 429 429 429 429 429
```

First 20 returned 200. Remaining 10 returned 429. Textbook. Rate limiting works perfectly. Ship it.

### Then I Opened a Browser

And everything broke.

Opening `https://192.168.75.109/login` from an actual browser immediately triggered 429 errors. The page couldn't load.

**Root cause  --  from the HAProxy logs:**

```bash
sudo journalctl -u haproxy --no-pager -n 50
```

The logs told the story immediately. Within 2 seconds of loading the page, the browser fired off requests for CSS files, JavaScript bundles, fonts, SVG icons, API calls, plugin settings, and websocket connections. A single Grafana page load generates **40+ requests in under 2 seconds**. By request 21, HAProxy started rejecting JavaScript bundles, fonts, API calls, and even the favicon.

The log lines with `<NOSRV>` and status `429`  --  HAProxy rejected the request without even forwarding it to Grafana. The `PR--` flag on those lines means "denied by protection rule."

### Why `curl` Didn't Catch This

Each `curl` is a single HTTP request. A browser loading Grafana's login page requests the HTML, then parses it and fetches every linked resource  --  JS bundles, CSS files, fonts, images, API endpoints  --  all in parallel. A real browser behaves *fundamentally differently* from `curl`.

This is the most expensive lesson in the entire project: **always test security controls with the actual client, not just CLI tools.**

### The Fix

```bash
sudo sed -i 's/sc_http_req_rate(0) gt 20/sc_http_req_rate(0) gt 100/' /etc/haproxy/haproxy.cfg
sudo /usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

Note: `systemctl reload` over `restart`  --  reload applies config without dropping existing connections. Safer for production.

100 requests per 10 seconds (600/minute) accommodates legitimate browser behavior including OAuth flows, while still blocking automated brute-force tools that generate thousands of requests per minute.

**After the fix**  --  loaded Grafana in the browser, checked logs:

```
Mar 03 14:39:21 ... 200 ... "GET .../public/build/6029.bdcbf27bcdd36812f646.js HTTP/2.0"
Mar 03 14:39:21 ... 200 ... "GET .../public/build/5671.d42d77fa90924a3065ef.js HTTP/2.0"
...
Mar 03 14:39:23 ... 200 ... "GET .../api/search?limit=30&type=dash-db HTTP/2.0"
```

~50 requests. All 200. Zero 429 rejections.

*Compliance: NIST SC-5 (Denial of Service Protection), SI-4 (Information System Monitoring), CIS 13.3, PCI-DSS 6.4*

---

## Chapter 8: OpenBAO Secrets  --  Getting There Is Half the Battle

[![OpenBAO secret injection pipeline from encrypted vault through entrypoint.sh to running Grafana](/images/ep3-secret-pipeline.jpg)](/images/ep3-secret-pipeline.jpg)

The goal: move three plaintext credentials out of `~/monitoring/.env` and into OpenBAO's encrypted KV v2 store.

First problem: figuring out how to actually reach OpenBAO.

```bash
curl -sk -o /dev/null -w "%{http_code}" https://192.168.100.182:8200/v1/sys/health
# 000

curl -sk -o /dev/null -w "%{http_code}" http://192.168.100.182:8200/v1/sys/health
# 000

curl -sk -o /dev/null -w "%{http_code}" https://192.168.100.182/v1/sys/health
# 200
```

OpenBAO's container listens on port 8200, but HAProxy on the OpenBAO host terminates TLS on port 443 and proxies to 8200. The external address is `https://192.168.100.182`  --  no port suffix. Took three tries to figure that out.

This distinction matters:
- **Inside the OpenBAO container** (admin CLI work): `http://127.0.0.1:8200`  --  direct, no HAProxy
- **From Grafana-lab** (entrypoint script): `https://192.168.100.182`  --  through HAProxy, with TLS

Know your own infrastructure's network path. This is a common gotcha when services sit behind reverse proxies.

---

## Chapter 9: OpenBAO Configuration  --  Secrets, Policies, and AppRole

Everything from here happens *inside the OpenBAO container*:

```bash
sudo docker exec -it openbao sh
export BAO_ADDR='http://127.0.0.1:8200'
export BAO_TOKEN='<redacted>'
```

**Confirm KV v2:**

```bash
bao read sys/mounts/secret
```

Output showed `options: map[version:2]`. This matters because v1 and v2 have different API paths. v2 requires `/data/` in the path.

**Store all three secrets:**

```bash
bao kv put secret/grafana/credentials \
  admin_password="<redacted>" \
  oauth_client_secret="<redacted>" \
  prometheus_password="<redacted>"
```

**Verify:**

```bash
bao kv get secret/grafana/credentials
```

All three key-value pairs present with correct values.

**Create the policy:**

```bash
bao policy write grafana-policy - << 'EOF'
path "secret/data/grafana/*" {
    capabilities = ["read"]
}
EOF
```

This creates a policy that allows read access to anything under `secret/data/grafana/` and nothing else. The `/data/` in the path is mandatory for KV v2. The CLI abstracts this away when you type `bao kv get secret/grafana/credentials`, but policies and direct API calls need the full v2 path. This trips up everyone at least once.

**Why not use the root token from Grafana?** Because if the Grafana container were compromised, the attacker would have full access to *everything*  --  all secrets, PKI infrastructure, system configuration. The scoped policy ensures Grafana can only read its own secrets. Least privilege isn't optional.

**Create the AppRole:**

```bash
bao write auth/approle/role/grafana-role \
  token_policies="grafana-policy" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_num_uses=0
```

AppRole is how machines authenticate to OpenBAO. Instead of a human typing a token, Grafana uses a `role_id` (like a username) and `secret_id` (like a password) to get a temporary token.

**Retrieve the credentials:**

```bash
bao read auth/approle/role/grafana-role/role-id
# role_id: <redacted>

bao write -f auth/approle/role/grafana-role/secret-id
# secret_id: <redacted>
```

**Test the AppRole login:**

```bash
bao write auth/approle/login \
  role_id="<redacted>" \
  secret_id="<redacted>"
```

Token issued, `grafana-policy` attached, 1-hour duration. Then verified the scoped token can read the secrets:

```bash
BAO_TOKEN="<redacted>" bao kv get secret/grafana/credentials
```

All three secrets readable. Machine identity is working.

*Compliance: NIST SC-12, SC-28, IA-5 (Cryptographic Key Management, Information at Rest, Authenticator Management), CIS 3.11, SOC 2 CC6.1/CC6.7, PCI-DSS 3.5*

---

## Chapter 10: The Entrypoint Script  --  The python3 Disaster

The plan: create `~/monitoring/entrypoint.sh`  --  a script that runs at container startup, before Grafana launches. It authenticates to OpenBAO, fetches all three secrets, injects them into the environment, and launches Grafana.

### Version 1 (Broken)

The first version used `python3` to parse the JSON response from the OpenBAO API:

```bash
TOKEN=$(curl -sk --request POST \
  --data "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
  ${BAO_ADDR}/v1/auth/approle/login | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
```

Deployed it:

```bash
sudo docker compose up -d --force-recreate grafana
```

Container entered a restart loop:

```bash
docker ps | grep grafana
# STATUS: Restarting (127) 9 seconds ago

sudo docker logs grafana 2>&1 | tail -20
```

Twelve identical lines:

```
/entrypoint.sh: line 12: python3: not found
```

Exit code 127 means "command not found." The Grafana Docker image is based on Alpine Linux. Alpine is a minimal distribution that *does not include python3*. The `python3` binary simply doesn't exist in the container.

The script was written and tested conceptually on the Debian host, where `python3` is available. It was never tested inside the container. The assumption was wrong.

**Lesson: never assume tool availability inside containers.** Alpine-based images are deliberately minimal. Tools you take for granted on a full Linux distribution (`python3`, `jq`, etc.) aren't there. Always verify what's available inside the target container, or write scripts using only POSIX shell builtins and tools guaranteed to be in the base image.

---

## Chapter 11: The Entrypoint Script  --  The Working Version

Rewrote all JSON parsing to use `sed`:

```bash
#!/bin/sh
set -e

BAO_ADDR="https://192.168.100.182"
BAO_ROLE_ID="${BAO_ROLE_ID}"
BAO_SECRET_ID="${BAO_SECRET_ID}"

# Authenticate to OpenBAO via AppRole
LOGIN_RESPONSE=$(curl -sk --request POST \
  --data "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
  ${BAO_ADDR}/v1/auth/approle/login)

TOKEN=$(echo "$LOGIN_RESPONSE" | sed 's/.*"client_token":"//' | sed 's/".*//')

# Fetch secrets from OpenBAO
SECRETS_RESPONSE=$(curl -sk --header "X-Vault-Token: ${TOKEN}" \
  ${BAO_ADDR}/v1/secret/data/grafana/credentials)

ADMIN_PASS=$(echo "$SECRETS_RESPONSE" | sed 's/.*"admin_password":"//' | sed 's/".*//')
OAUTH_SECRET=$(echo "$SECRETS_RESPONSE" | sed 's/.*"oauth_client_secret":"//' | sed 's/".*//')
PROM_PASS=$(echo "$SECRETS_RESPONSE" | sed 's/.*"prometheus_password":"//' | sed 's/".*//')

# Start Grafana with secrets injected
exec env \
  GF_SECURITY_ADMIN_PASSWORD="${ADMIN_PASS}" \
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="${OAUTH_SECRET}" \
  PROMETHEUS_PASSWORD="${PROM_PASS}" \
  /run.sh "$@"
```

### How the `sed` JSON Parsing Works

Each `sed` command pair does two operations:

1. `sed 's/.*"client_token":"//'`  --  strips everything from the start of the string up to and including `"client_token":"`, leaving the token value and everything after it
2. `sed 's/".*//'`  --  strips the closing quote and everything after it, leaving just the token value

Not a proper JSON parser. But it works reliably when the JSON structure is known and consistent, which OpenBAO's API responses are.

### The `exec env` Pattern  --  This Is the Critical Part

```bash
exec env \
  GF_SECURITY_ADMIN_PASSWORD="${ADMIN_PASS}" \
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="${OAUTH_SECRET}" \
  PROMETHEUS_PASSWORD="${PROM_PASS}" \
  /run.sh "$@"
```

`exec` replaces the current shell process with the specified command. `env` sets environment variables for the new process. Together, they set three new variables and launch Grafana's `/run.sh` in one atomic step.

Why not just use `export`? Because `exec` destroys the current shell when it launches the new process. Variables set with `export` are lost at that boundary. `exec env` sets the variables and launches the process simultaneously, ensuring they survive.

**This pattern is mandatory for Docker entrypoint scripts that inject secrets.** Simple `export` does not persist through `exec`. This is a non-obvious Docker behavior that causes silent failures  --  the container starts, but the variables are empty, leading to authentication failures that look like configuration problems rather than what they actually are.

### Deploy

```bash
chmod +x ~/monitoring/entrypoint.sh
cd ~/monitoring && sudo docker compose up -d --force-recreate grafana
```

After 60 seconds:

```bash
docker ps | grep grafana
# Up 3 minutes  --  no restart loop
```

---

## Chapter 12: Where Do Secrets Actually Live?

During development, a question came up: "Will the output show up in logs or memory? Somewhere someone can see those creds?"

Honest answer: secrets exist in several places during the container lifecycle.

1. **Shell variables during startup**  --  brief, in process memory, gone once `exec` replaces the shell
2. **Docker logs**  --  output is captured by shell variable assignment (`SECRETS=$(...)`), won't appear in logs unless the script errors out
3. **Process memory**  --  during the narrow startup window, theoretically visible in `/proc` to root
4. **Docker environment**  --  after startup, `docker inspect` and `docker exec grafana env` will show them (same exposure as the `.env` file)
5. **Grafana logs**  --  Grafana masks the admin password: `GF_SECURITY_ADMIN_PASSWORD=*********`

**What improved:** The `.env` file no longer contains passwords. It contains only AppRole credentials (`role_id` and `secret_id`) that are scoped to read-only access to Grafana's secrets. The actual secrets are encrypted at rest in OpenBAO. They're fetched fresh every container start. If the `.env` file is compromised, the attacker gets AppRole credentials, not root access to the vault.

**What didn't change:** Docker environment variable exposure (inherent to Docker's architecture). Anyone with `docker exec` access can still read secrets from the running container.

Secrets management is about *reducing* the attack surface, not eliminating it. Moving from plaintext files to an encrypted vault eliminates the most common attack vector (file disclosure) but doesn't prevent a root-level attacker from extracting them from process memory. The improvement is meaningful. Understanding the remaining exposure is equally important.

---

## Chapter 13: The Final `.env` and Docker Compose

### `.env`  --  Before and After

**Before (3 plaintext secrets):**

```bash
GF_SECURITY_ADMIN_PASSWORD=<redacted>
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=<redacted>
PROMETHEUS_PASSWORD=<redacted>
```

**After (0 plaintext secrets):**

```bash
GF_SERVER_ROOT_URL=https://192.168.75.109
GF_AUTH_GENERIC_OAUTH_ENABLED=true
GF_AUTH_GENERIC_OAUTH_NAME=Authentik
GF_AUTH_GENERIC_OAUTH_CLIENT_ID=grafana-client
GF_AUTH_GENERIC_OAUTH_SCOPES=openid profile email groups
GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://192.168.80.54:9000/application/o/authorize/
GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://192.168.80.54:9000/application/o/token/
GF_AUTH_GENERIC_OAUTH_API_URL=http://192.168.80.54:9000/application/o/userinfo
GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true
GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN=false
GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=contains(groups[*], 'Grafana Admins') && 'Admin' || 'Viewer'
GF_USERS_ALLOW_SIGN_UP=false
GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h
GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h
GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10
BAO_ROLE_ID=<redacted>
BAO_SECRET_ID=<redacted>
```

Three secrets removed. Two AppRole credentials added. File permissions remain 600.

### Docker Compose  --  Two Lines Added to Grafana

```yaml
volumes:
  - ./entrypoint.sh:/entrypoint.sh:ro   # mount script read-only
entrypoint: ["/entrypoint.sh"]           # override default startup
```

The `:ro` flag prevents any in-container modification. The `entrypoint` directive replaces Grafana's default entrypoint with our script, which eventually calls the original `/run.sh`.

---

## Chapter 14: Final Validation  --  End to End

**Container stability:**

```bash
docker ps | grep grafana
# Up 3 minutes, no restart loop, entrypoint: /entrypoint.sh
```

**Clean startup logs:**

```bash
sudo docker logs grafana 2>&1 | head -20
```

```
logger=settings ... msg="Starting Grafana" version=12.3.2
logger=settings ... var="GF_SECURITY_ADMIN_PASSWORD=*********"
logger=settings ... var="GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h"
logger=settings ... var="GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h"
logger=settings ... var="GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10"
```

Admin password received and masked. Session settings loaded. No errors.

**Local admin auth:**

```bash
curl -s -o /dev/null -w "%{http_code}" -u admin:<redacted> http://127.0.0.1:3000/api/org
# 200
```

**HTTPS from the jump box:**

```bash
curl -sk -o /dev/null -w "%{http_code}" https://192.168.75.109/login
# 200
```

**Prometheus datasource through Grafana:**

```bash
curl -s -u admin:<redacted> \
  http://127.0.0.1:3000/api/datasources/proxy/1/api/v1/query?query=up | python3 -m json.tool | head -10
```

Returned active targets. Prometheus password from OpenBAO working correctly through the full chain.

**No secrets in `.env`:**

```bash
grep -iE "(PASSWORD|SECRET)" ~/monitoring/.env
# BAO_SECRET_ID=<redacted>
```

Only the AppRole secret_id. No plaintext passwords.

**Browser + rate limiting:**

```bash
sudo journalctl -u haproxy --no-pager -n 50
```

All 50 requests returned 200. Zero 429 rejections. ~50 requests served in ~2 seconds. Page loaded fully.

---
## The Complete Scorecard

[![Hardening progression mapped to 18 chapters from 6.0 to 9.8](/images/ep3-chapter-progression.jpg)](/images/ep3-chapter-progression.jpg)

| # | Vulnerability | Fix | Status |
|---|---|---|---|
| VULN-01 | Default/Weak Credentials | Strong 32-char password, stored in OpenBAO | FIXED |
| VULN-02 | Prometheus No Authentication | Basic auth with bcrypt, password in OpenBAO | FIXED |
| VULN-03/04 | Exporters Exposed | All exporters on internal Docker network only | FIXED |
| VULN-06/07 | No Session Limits | 1h inactive, 24h max, 10min rotation, rate limiting | FIXED |
| VULN-09/11 | Container Hardening | `cap_drop ALL`, minimal `cap_add`, no-new-privileges, resource limits | FIXED |
| VULN-10 | No TLS | HAProxy TLS 1.2+, security headers, HTTP-to-HTTPS redirect | FIXED |
| Phase 4 | Plaintext Secrets | All passwords in OpenBAO KV v2, AppRole auth, entrypoint injection | FIXED |
| Phase 6.3 | Snapshot Exfiltration | External snapshots disabled, snapshot URL cleared | FIXED |
| Phase 6.3b | Duplicate Datasource | Old manual datasource deleted, single provisioned datasource | FIXED |
| Phase 6.2 | No Audit Logging | Structured JSON logging, 30-day retention, auth event capture | FIXED |
| Phase 6.2b | Orphaned Dashboard UIDs | Bulk API replacement of 16 panel datasource references | FIXED |

---

## Chapter 15: Snapshot Exfiltration - The Data Leak You Forgot About (Phase 6.3)

Here's a fun default nobody talks about: any authenticated Grafana user can create a public snapshot with no expiration. That snapshot gets published to `snapshots.raintank.io` - an external service. The snapshot URL requires no authentication to view. And here's the part that should make your stomach drop: **the snapshot persists even after you delete the user's account.**

Fire a contractor. Revoke their OAuth access. Delete their Grafana account entirely. The snapshot they created last Tuesday? Still live. Still public. Still containing your infrastructure metrics.

Before hardening, any authenticated user could have done this:

```bash
curl -X POST http://192.168.75.84:3000/api/snapshots \
  --cookie "grafana_session=$GRAFANA_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "dashboard": {"title": "Infrastructure Metrics"},
    "name": "Exfiltrated Data",
    "expires": 0,
    "external": true
  }'
```

That returns a public URL. No authentication required. Never expires. Data exfiltration in 30 seconds.

### The Fix

**Review the current docker-compose.yml structure:**

```bash
cd ~/monitoring
cat docker-compose.yml | grep -A 50 "grafana:" | head -60
```

Environment variables were organized in labeled sections (Session Hardening, OAuth2, Server). New snapshot settings follow the same pattern.

**Add snapshot security environment variables** (using `nano`, never `sed` for YAML):

```bash
nano +57 ~/monitoring/docker-compose.yml
```

Added after the Server section:

```yaml
      # === SNAPSHOT SECURITY (Phase 6.3) ===
      - GF_SNAPSHOTS_EXTERNAL_ENABLED=false
      - GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL=
```

| Variable | Value | Effect |
|---|---|---|
| `GF_SNAPSHOTS_EXTERNAL_ENABLED` | `false` | Disables publishing snapshots to external services |
| `GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL` | (empty) | Clears the external snapshot URL as defense-in-depth |

**Verify the addition:**

```bash
grep -A 2 "SNAPSHOT" ~/monitoring/docker-compose.yml
```

```
      # === SNAPSHOT SECURITY (Phase 6.3) ===
      - GF_SNAPSHOTS_EXTERNAL_ENABLED=false
      - GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL=
```

**Verify it's a single entry** (the terminal had displayed a false duplicate because example "expected output" text was accidentally pasted into the shell - yes, really):

```bash
grep -n "SNAPSHOT" ~/monitoring/docker-compose.yml
```

```
79:      # === SNAPSHOT SECURITY (Phase 6.3) ===
80:      - GF_SNAPSHOTS_EXTERNAL_ENABLED=false
81:      - GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL=
```

Single entry confirmed. Lesson learned: when following step-by-step instructions, be careful to copy only the command, not surrounding documentation text. If you see bash errors with markdown-style formatting (`**`, backticks, etc.), you pasted docs.

### The Restart That Didn't Work

```bash
cd ~/monitoring
sudo docker compose restart grafana
```

```bash
sudo docker exec grafana env | grep -i snapshot
# (no output)
```

Nothing. The environment variables didn't load.

`docker compose restart` only stops and starts the existing container. It does NOT re-read `docker-compose.yml`. It does NOT recreate the container. It does NOT apply changes to environment variables, volume mounts, ports, or anything else in the compose file.

This is the same lesson from earlier phases, and it keeps biting. Here's the reference table that finally made it stick:

| Command | Re-reads compose file | Recreates container | Applies env changes |
|---|---|---|---|
| `restart` | No | No | No |
| `up -d` | Yes | Only if changed | Yes |
| `up -d --force-recreate` | Yes | Always | Yes |
| `down` + `up -d` | Yes | Always (fresh) | Yes |

### The Correct Approach

```bash
sudo docker compose up -d --force-recreate grafana
```

```
[+] up 1/1
 Container grafana Recreated    0.3s
```

```bash
sudo docker exec grafana env | grep -i snapshot
```

```
GF_SNAPSHOTS_EXTERNAL_ENABLED=false
GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL=
```

Both present. External snapshots are dead.

*Compliance: NIST AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection), SOC 2 CC6.7, CIS 3.3, PCI-DSS 7.1*

---

## Chapter 16: The Browser Auth Popup Mystery

This is where things got weird.

During UI testing of the snapshot security changes, a native browser popup appeared: `Sign in to access this site` / `Authorization required by https://192.168.75.84`. This wasn't Grafana's login page. This was the browser's own credential dialog  --  the one you see when a server sends a `WWW-Authenticate: Basic` header.

It appeared on every dashboard page, even after successfully logging in through OAuth via Authentik. The Grafana sidebar loaded fine. The dashboard structure rendered. Then the popup appeared over the content. Clicking "Cancel" dismissed it, but dashboard panels showed no data.

Tested in a fresh incognito window. Logged in as `akadmin` (Authentik admin account) via OAuth. Same behavior. Not a cache issue. Not a permissions issue.

So what's sending a `WWW-Authenticate` header?

[![Duplicate datasource diagnostic chain showing browser popup mystery and cascading panel failures](/images/ep3-datasource-diagnostic.jpg)](/images/ep3-datasource-diagnostic.jpg)

### The Diagnostic Chain

**Step 1  --  Rule out HAProxy basic auth:**

```bash
sudo grep -A 5 "userlist" /etc/haproxy/haproxy.cfg
# (no output)
```

```bash
sudo cat /etc/haproxy/haproxy.cfg
```

No `userlist`, no `http-request auth`, no basic auth directives anywhere. HAProxy only performs TLS termination, security headers, rate limiting, and proxying. Eliminated as the source.

**Step 2  --  Rule out cached browser credentials:**

Tested in fresh incognito window. Logged in as `akadmin` via OAuth. Same behavior. Not a cache issue and not a role/permission issue.

**Step 3  --  Verify Prometheus credentials in the Grafana container:**

```bash
sudo docker exec grafana env | grep PROMETHEUS
# PROMETHEUS_PASSWORD=<redacted>
```

Password present and correct.

**Step 4  --  Test Prometheus connectivity from inside the Grafana container:**

```bash
sudo docker exec grafana curl -s -u prometheus:<redacted> \
  http://prometheus:9090/api/v1/status/config | head -20
```

```
{"status":"success","data":{"yaml":"global:\n  scrape_interval: 15s...
```

Authentication works correctly from inside the container. (Side note: BusyBox `wget` on Alpine doesn't support `--user` or `--password` flags. Use `curl -u` instead.)

**Step 4b  --  Verify datasource provisioning configuration:**

```bash
cat ~/monitoring/grafana/provisioning/datasources/prometheus.yml
```

Confirmed: `access: proxy`, `basicAuth: true`, `basicAuthUser: prometheus`, `secureJsonData.basicAuthPassword: ${PROMETHEUS_PASSWORD}`. The provisioning file is correct.

**Step 5  --  List all datasources:**

```bash
source ~/monitoring/.env
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/datasources | jq .
```

And there it was:

```json
[
  {
    "id": 2,
    "uid": "PBFA97CFB590B2093",
    "name": "Prometheus",
    "basicAuth": true,
    "isDefault": true,
    "readOnly": true
  },
  {
    "id": 1,
    "uid": "cfb1rlaq8gutcf",
    "name": "prometheus",
    "basicAuth": false,
    "isDefault": false,
    "readOnly": false
  }
]
```

**Two Prometheus datasources.** One provisioned correctly with `basicAuth: true`. One created manually through the Grafana UI back before Phase 3 added auth to Prometheus, with `basicAuth: false`.

| Property | Provisioned (correct) | Manual (problematic) |
|---|---|---|
| UID | `PBFA97CFB590B2093` | `cfb1rlaq8gutcf` |
| Name | `Prometheus` (capital P) | `prometheus` (lowercase p) |
| basicAuth | `true` | **`false`** |
| readOnly | `true` | `false` |
| Origin | Provisioning YAML (Phase 3) | Created via UI (pre-Phase 3) |

### Why This Causes a Browser Popup

The chain of events:

1. Grafana proxies Prometheus queries server-side (due to `access: proxy`)
2. The provisioned datasource (id: 2) includes basic auth credentials  --  works fine
3. The old manual datasource (id: 1) has `basicAuth: false`  --  no credentials sent
4. When any dashboard panel references the old datasource, Prometheus returns `401 Unauthorized` with a `WWW-Authenticate: Basic` header
5. Grafana passes this `WWW-Authenticate` header through to the browser response
6. The browser interprets this as a prompt for user credentials and shows the native auth dialog
7. Even if no dashboard *explicitly* references the old datasource, Grafana's internal query routing or variable resolution can trigger queries against it

This is insidious. The popup looks like HAProxy or Grafana auth  --  not obviously a datasource issue. The provisioned datasource works fine. Only the hidden duplicate causes problems. And it was never cleaned up because provisioning creates a *new* datasource alongside existing ones  --  it doesn't replace or remove them.

### The Fix  --  Delete the Duplicate

```bash
source ~/monitoring/.env
sudo docker exec grafana curl -s -X DELETE \
  -u admin:<redacted> \
  localhost:3000/api/datasources/uid/cfb1rlaq8gutcf | jq .
```

```json
{
  "id": 1,
  "message": "Data source deleted"
}
```

Hard-refreshed the browser (`Ctrl+Shift+R`). Dashboard loaded successfully. No auth popup. All panels populated with Prometheus data correctly.

**Verify only one datasource remains:**

```bash
source ~/monitoring/.env
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/datasources | jq '.[].name'
```

```
"Prometheus"
```

Single entry. Clean.

---

## Chapter 17: "No Data"  --  The Orphaned Dashboard (Phase 6.2)

The duplicate datasource was dead. The browser popup was gone. Everything seemed fine.

Then I looked at the OpenBAO dashboard.

Every single panel showed "No data."

### Was the Pipeline Broken?

**Check if Prometheus is scraping OpenBAO:**

```bash
source ~/monitoring/.env
curl -s -u prometheus:<redacted> \
  'http://localhost:9090/api/v1/targets' | python3 -m json.tool | grep -A 10 "openbao"
```

```json
{
    "instance": "openbao-primary",
    "job": "openbao",
    "vlan": "100"
},
"scrapePool": "openbao",
"scrapeUrl": "http://192.168.100.140:8200/v1/sys/metrics?format=prometheus",
"lastError": "",
"health": "up",
"scrapeInterval": "30s"
```

Prometheus is scraping OpenBAO. Health: `up`. No errors.

**Check if the metrics actually exist:**

```bash
curl -s -u prometheus:<redacted> \
  'http://localhost:9090/api/v1/query?query=vault_core_unsealed' | python3 -m json.tool
```

```json
{
    "status": "success",
    "data": {
        "resultType": "vector",
        "result": [
            {
                "metric": {
                    "__name__": "vault_core_unsealed",
                    "cluster": "vault-cluster-5d956fd0",
                    "instance": "openbao-primary",
                    "job": "openbao",
                    "vlan": "100"
                },
                "value": [1770242604.465, "1"]
            }
        ]
    }
}
```

`vault_core_unsealed = 1`  --  OpenBAO is unsealed and healthy. The data pipeline (OpenBAO to Prometheus to Grafana) is working perfectly.

The issue is at the Grafana dashboard/panel level.

### The Wrong Username Detour

Before getting to the real root cause, there was a brief detour where Prometheus auth itself seemed broken.

**First attempt  --  unauthenticated request (failed):**

```bash
sudo docker exec prometheus wget -qO- 'http://localhost:9090/api/v1/targets' 2>/dev/null | python3 -m json.tool | grep -A 5 "openbao"
```

```
Expecting value: line 1 column 1 (char 0)
```

Prometheus has basic auth now. Unauthenticated requests return garbage.

**Second attempt  --  wrong username (failed):**

```bash
curl -s -u admin:<redacted> \
  'http://localhost:9090/api/v1/targets' | python3 -m json.tool | grep -A 10 "openbao"
```

```
Expecting value: line 1 column 1 (char 0)
```

**Verbose curl to see the actual HTTP response:**

```bash
curl -v -u admin:<redacted> \
  'http://localhost:9090/api/v1/targets' 2>&1 | head -30
```

```
< HTTP/1.1 401 Unauthorized
< Www-Authenticate: Basic
...
Unauthorized
```

401\. The password was right, but the username was wrong. Let's check what Prometheus actually expects:

```bash
sudo docker exec prometheus cat /etc/prometheus/web-config.yml
```

```yaml
basic_auth_users:
  prometheus: $2y$10$...
```

Username is `prometheus`, not `admin`. Configured back in Phase 3. Two things to verify when auth fails  --  the username AND the variable name. Don't assume either. Check the actual config files.

Also worth noting: the first attempt used `$PROMETHEUS_ADMIN_PASSWORD` which doesn't exist in `.env`. The actual variable is `PROMETHEUS_PASSWORD`:

```bash
grep -i prom ~/monitoring/.env
# PROMETHEUS_PASSWORD=<redacted>
```

### The Actual Root Cause  --  Orphaned UIDs

**Get the dashboard UID:**

```bash
source ~/monitoring/.env
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/search?query=OpenBAO | python3 -m json.tool
```

```json
[
    {
        "id": 4,
        "uid": "grf6jtj",
        "title": "OpenBAO",
        "uri": "db/openbao",
        "url": "/d/grf6jtj/openbao",
        "tags": ["monitoring", "openbao", "secrets", "security", "vlan100"]
    }
]
```

**Inspect what datasource UID each panel references:**

```bash
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/dashboards/uid/grf6jtj | python3 -c "
import sys, json
data = json.load(sys.stdin)
for panel in data.get('dashboard', {}).get('panels', []):
    ds = panel.get('datasource', {})
    title = panel.get('title', 'unknown')
    print(f'{title}: uid={ds.get(\"uid\", \"NONE\")}, type={ds.get(\"type\", \"NONE\")}')
"
```

```
Transit Seal Unreachable Time: uid=cfb1rlaq8gutcf, type=prometheus
Audit Log Performance: uid=cfb1rlaq8gutcf, type=prometheus
Identity Entities: uid=cfb1rlaq8gutcf, type=prometheus
Token lookup and validation operations: uid=cfb1rlaq8gutcf, type=prometheus
Token Validation Rate: uid=cfb1rlaq8gutcf, type=prometheus
New panel: uid=cfb1rlaq8gutcf, type=prometheus
Transit Auto-Unseal Operations: uid=cfb1rlaq8gutcf, type=prometheus
Active Tokens by Auth Method: uid=cfb1rlaq8gutcf, type=prometheus
OIDC Authentication Rate: uid=cfb1rlaq8gutcf, type=prometheus
PKI Certificate Operations: uid=cfb1rlaq8gutcf, type=prometheus
Total HTTP Requests: uid=cfb1rlaq8gutcf, type=prometheus
Token Creations: uid=cfb1rlaq8gutcf, type=prometheus
Active Goroutines: uid=cfb1rlaq8gutcf, type=prometheus
Memory Usage: uid=cfb1rlaq8gutcf, type=prometheus
Active Requests: uid=cfb1rlaq8gutcf, type=prometheus
OpenBao Status: uid=cfb1rlaq8gutcf, type=prometheus
```

All 16 panels reference `cfb1rlaq8gutcf`.

**Check what datasource actually exists now:**

```bash
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/datasources | python3 -m json.tool | grep -E '"uid"|"name"'
```

```
        "uid": "PBFA97CFB590B2093",
        "name": "Prometheus",
```

| Item | Value |
|---|---|
| Datasource UID panels reference | `cfb1rlaq8gutcf` |
| Actual datasource UID | `PBFA97CFB590B2093` |
| Status of `cfb1rlaq8gutcf` | **DELETED** (in Phase 6.3) |

There it is. Dashboard panels store datasource references by UID, not by name. When we deleted the duplicate datasource to fix the browser popup, every panel on the OpenBAO dashboard became an orphan. Grafana doesn't show an error for this  --  it just says "No data." Which is ambiguous as hell, because it could mean no metrics exist, wrong time range, or broken datasource reference. There's no "hey, the datasource this panel is pointing at doesn't exist anymore" warning.

### The Fix  --  Bulk UID Replacement via API

16 panels needed their datasource UID updated. Clicking through each one in the UI? No. We're using the API.

The approach: export the dashboard JSON, string-replace the old UID with the correct one, re-import with `overwrite: true`.

**Export, transform, and create the fixed JSON:**

```bash
source ~/monitoring/.env
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/dashboards/uid/grf6jtj | python3 -c "
import sys, json

data = json.load(sys.stdin)
dashboard = data['dashboard']

# Remove read-only fields that would cause import errors
dashboard.pop('id', None)
dashboard.pop('version', None)

# String replacement for all UID references
raw = json.dumps(dashboard)
fixed = raw.replace('cfb1rlaq8gutcf', 'PBFA97CFB590B2093')
dashboard = json.loads(fixed)

payload = {'dashboard': dashboard, 'overwrite': True}
print(json.dumps(payload))
" > /tmp/fixed-dashboard.json
```

### The stdin Piping Failure

**First attempt  --  pipe the file into docker exec (failed):**

```bash
sudo docker exec grafana curl -s -X POST \
  -u admin:<redacted> \
  -H "Content-Type: application/json" \
  -d @- localhost:3000/api/dashboards/db < /tmp/fixed-dashboard.json | python3 -m json.tool
```

```json
{
    "message": "bad request data"
}
```

Piping file content from the host via stdin (`< /tmp/file`) into `docker exec` doesn't reliably pass the data through to the `curl -d @-` process inside the container. The stdin redirection applies to `docker exec`, but the data doesn't reach the subprocess correctly. This is a known Docker limitation with complex stdin piping.

### The Working Approach  --  docker cp First

**Copy the file into the container:**

```bash
sudo docker cp /tmp/fixed-dashboard.json grafana:/tmp/fixed-dashboard.json
```

```
Successfully copied 23kB to grafana:/tmp/fixed-dashboard.json
```

**Import the fixed dashboard using the file inside the container:**

```bash
sudo docker exec grafana curl -s -X POST \
  -u admin:<redacted> \
  -H "Content-Type: application/json" \
  -d @/tmp/fixed-dashboard.json \
  localhost:3000/api/dashboards/db | python3 -m json.tool
```

```json
{
    "folderUid": "",
    "id": 4,
    "slug": "openbao",
    "status": "success",
    "uid": "grf6jtj",
    "url": "/d/grf6jtj/openbao",
    "version": 26
}
```

Dashboard updated. All 16 panels now reference the correct datasource UID.

### Verify the Fix

**Confirm all panel UIDs are correct:**

```bash
sudo docker exec grafana curl -s -u admin:<redacted> \
  localhost:3000/api/dashboards/uid/grf6jtj | python3 -c "
import sys, json
data = json.load(sys.stdin)
for panel in data.get('dashboard', {}).get('panels', []):
    ds = panel.get('datasource', {})
    title = panel.get('title', 'unknown')
    print(f'{title}: uid={ds.get(\"uid\", \"NONE\")}')
"
```

All 16 panels now show `uid=PBFA97CFB590B2093`. Opened the dashboard in the browser  --  every panel populated with live data.

### Why This Matters

This entire chain  --  duplicate datasource causing browser popups, deleting it to fix the popup, orphaning 16 dashboard panels, then bulk-fixing them via the API  --  is what real-world incremental hardening looks like. In a production environment, you rarely get a clean-room deployment. You inherit drift, manual changes, and layered configurations.

The duplicate datasource existed because Prometheus auth was added incrementally (Phase 3) without cleaning up the manually-created datasource from before auth existed. Provisioning creates *new* resources. It does not replace or remove existing ones.

The "No data" symptom is dangerously ambiguous  --  it could mean no metrics exist, wrong time range, wrong query, or broken datasource reference. Before deleting any datasource, query all dashboards to check for references.

And when you need to fix 16 panels? API-based bulk replacement is faster, safer, and reproducible compared to clicking through each panel in the UI.

*Compliance: NIST AC-4 (Information Flow Enforcement), SOC 2 CC6.1 (Logical Access Security)*

---

## Chapter 18: Audit Logging (Phase 6.2)

With the datasource cleanup behind us, Phase 6.2 added structured JSON audit logging to Grafana for compliance visibility.

**Add audit logging environment variables to docker-compose.yml:**

```bash
nano +80 ~/monitoring/docker-compose.yml
```

Added after the Snapshot Security section:

```yaml
      # === AUDIT LOGGING (Phase 6.2) ===
      - GF_LOG_MODE=console file
      - GF_LOG_LEVEL=info
      - GF_LOG_FILE_FORMAT=json
      - GF_LOG_FILE_LOG_ROTATE=true
      - GF_LOG_FILE_MAX_DAYS=30
```

| Variable | Value | Effect |
|---|---|---|
| `GF_LOG_MODE` | `console file` | Logs to both stdout (for `docker logs`) and persistent file |
| `GF_LOG_LEVEL` | `info` | Captures auth events, API calls, errors without debug noise |
| `GF_LOG_FILE_FORMAT` | `json` | Machine-parseable structured logs for SIEM/Loki ingestion |
| `GF_LOG_FILE_LOG_ROTATE` | `true` | Prevents log files from growing unbounded |
| `GF_LOG_FILE_MAX_DAYS` | `30` | 30-day retention |

**Validate and deploy:**

```bash
grep -A 6 "AUDIT LOGGING" ~/monitoring/docker-compose.yml
```

```
      # === AUDIT LOGGING (Phase 6.2) ===
      - GF_LOG_MODE=console file
      - GF_LOG_LEVEL=info
      - GF_LOG_FILE_FORMAT=json
      - GF_LOG_FILE_LOG_ROTATE=true
      - GF_LOG_FILE_MAX_DAYS=30
```

```bash
sudo docker compose -f ~/monitoring/docker-compose.yml config --quiet && echo "YAML OK" || echo "YAML ERROR"
# YAML OK

sudo docker compose up -d --force-recreate grafana
```

**Verify environment variables loaded:**

```bash
sudo docker exec grafana env | grep GF_LOG
```

All five variables present.

**Find where Grafana actually writes logs** (don't assume default paths):

```bash
sudo docker exec grafana find / -name "*.log" -type f 2>/dev/null
```

```
/var/log/grafana/grafana.log
```

Not the often-documented `/var/lib/grafana/log/`. Containerized deployments don't always follow the defaults.

**Verify JSON format:**

```bash
sudo docker exec grafana tail -1 /var/log/grafana/grafana.log
```

Valid JSON line. Structured, machine-parseable.

**Verify auth events are being captured:**

```bash
sudo docker exec grafana grep -i "auth\|login\|session\|user" /var/log/grafana/grafana.log | tail -10
```

```json
{"level":"info","logger":"context","method":"GET","msg":"Request Completed","orgId":1,"path":"/api/live/ws","remote_addr":"192.168.38.215","uname":"grafana-admin@lab.local","userId":3,...}
```

Key fields captured: `remote_addr` (source IP for forensics), `uname` (authenticated username), `userId` (internal user ID), `path` (API endpoint accessed), `method` (HTTP method), `status` (response code). Everything you need for a compliance audit trail.

*Compliance: NIST AU-2 (Audit Events), AU-3 (Content of Audit Records), SOC 2 CC7.2 (System Monitoring), CIS 8.2/8.11 (Audit Logging/Retention)*

---

## The 14 Gotchas That Cost Me Real Time

Write these down. Tattoo them somewhere. They'll save you hours.

1. **`exec env` is mandatory**  --  `entrypoint.sh` must use `exec env VAR=value /run.sh` to pass dynamically-retrieved secrets to Grafana. Simple `export` doesn't persist through `exec`.

2. **Alpine has no python3**  --  The Grafana container is Alpine-based. Don't use `python3`, `jq`, or anything not in the base image. Use `sed`, `grep`, and shell builtins.

3. **KV v2 paths require `/data/`**  --  Policies must reference `secret/data/grafana/*`, not `secret/grafana/*`. The CLI hides this. Policies and API calls don't.

4. **20 req/10s will break your browser**  --  A single Grafana page load generates 40+ requests in 2 seconds. 100 req/10s is the tested minimum for normal browser use.

5. **Test with real clients**  --  `curl` validates the mechanism. It doesn't simulate how a browser actually behaves. Always test with both.

6. **OpenBAO CLI runs inside the container**  --  `sudo docker exec -it openbao sh`, then set `BAO_ADDR` and `BAO_TOKEN`. Use `http://127.0.0.1:8200` inside; `https://192.168.100.182` from external hosts.

7. **`docker compose restart` doesn't reload env vars**  --  Use `--force-recreate` for structural or environment changes. This bit us in Phase 6.3 *and* Phase 6.2. It will bite you too.

8. **`sed -i` is fine for HAProxy but lethal for YAML**  --  HAProxy config is plain ASCII. YAML files get UTF-8 corruption from `sed`. Use `nano` or `cat >` for YAML edits.

9. **`systemctl reload` over `restart`**  --  Reload applies config without dropping connections. Production-safe.

10. **Back up before every config change**  --  `cp file file.backup.$(date +%Y%m%d-%H%M%S)`. This saved me at least twice.

11. **Duplicate datasources cause browser auth popups**  --  If you provisioned a datasource after manually creating one, you have two. The old one without `basicAuth` will trigger `WWW-Authenticate` popups that look like HAProxy or Grafana auth issues. Delete duplicates via the API before they haunt you.

12. **Dashboard panels reference datasources by UID, not name**  --  Delete a datasource and every panel pointing at its UID shows "No data" with zero explanation. Before deleting any datasource, query all dashboards for UID references first.

13. **stdin piping through `docker exec` is unreliable**  --  `docker exec curl -d @- < /tmp/file.json` doesn't work reliably. Use `docker cp` to move the file into the container first, then reference it locally with `-d @/tmp/file.json`.

14. **Don't assume log file paths in containers**  --  Grafana logs to `/var/log/grafana/grafana.log`, not the often-documented `/var/lib/grafana/log/`. Use `find / -name "*.log"` inside the container to locate them.

[![Docker Compose command behavior matrix showing which commands apply config changes](/images/ep3-docker-matrix.jpg)](/images/ep3-docker-matrix.jpg)

---

## File Inventory (Final State)

| File | Location | Permissions | Purpose |
|---|---|---|---|
| `.env` | `~/monitoring/` | 600 | OAuth config + AppRole credentials (no passwords) |
| `entrypoint.sh` | `~/monitoring/` | 755 | OpenBAO secret fetcher, sed-based |
| `docker-compose.yml` | `~/monitoring/` | 644 | Container orchestration with entrypoint override |
| `haproxy.cfg` | `/etc/haproxy/` | 644 | TLS termination, rate limiting (100/10s), security headers |
| `grafana.pem` | `/etc/haproxy/certs/` | 600 | Self-signed TLS certificate |
| `web-config.yml` | `~/monitoring/prometheus/` | 644 | Prometheus basic auth (bcrypt hash) |
| `prometheus.yml` | `~/monitoring/prometheus/` | 644 | Scrape configs with self-scrape auth |
| `prometheus.yml` | `~/monitoring/grafana/provisioning/datasources/` | 644 | Datasource with `${PROMETHEUS_PASSWORD}` |

---

## What's Next

This stack is hardened. It's not finished.

- **Phase 7.1**  --  Remaining hardening items
- **Authentik hardening**  --  TLS, security headers, default misconfiguration audit (separate episode)

The third video in the "Build It, Break It, Fix It" series covers this final hardened architecture. B-roll is planned. If you've ever wanted to watch someone's rate limiter break on camera because a single browser tab fired 50 requests in two seconds, or watch a duplicate datasource cause a mystery popup that takes five diagnostic steps to trace, that footage exists now.

Stay paranoid.

---

## Sources & Frameworks

- **NIST SP 800-53 Rev 5**  --  Security and Privacy Controls for Information Systems and Organizations: [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **CIS Controls v8**  --  Center for Internet Security Critical Security Controls: [https://www.cisecurity.org/controls/v8](https://www.cisecurity.org/controls/v8)
- **CIS Docker Benchmark**  --  Container hardening guidelines: [https://www.cisecurity.org/benchmark/docker](https://www.cisecurity.org/benchmark/docker)
- **PCI-DSS v4.0**  --  Payment Card Industry Data Security Standard: [https://www.pcisecuritystandards.org/document_library/](https://www.pcisecuritystandards.org/document_library/)
- **AICPA SOC 2**  --  Trust Services Criteria (CC series): [https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services](https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services)
- **Grafana Documentation**  --  Configuration and administration: [https://grafana.com/docs/grafana/latest/](https://grafana.com/docs/grafana/latest/)
- **HAProxy Documentation**  --  Configuration manual: [https://docs.haproxy.org/](https://docs.haproxy.org/)
- **OpenBAO Documentation**  --  Secrets management and PKI: [https://openbao.org/docs/](https://openbao.org/docs/)
- **Prometheus Documentation**  --  Basic auth and web configuration: [https://prometheus.io/docs/](https://prometheus.io/docs/)

---

*© 2026 Oob Skulden™  --  Stay Paranoid.*
