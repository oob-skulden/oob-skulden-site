---
title: "Hardening a Grafana Monitoring Stack: 6 Phases, 15 Fixes, and the Gotchas Nobody Warns You About"
date: 2026-02-15T12:00:00-06:00
draft: false
author: "Oob Skulden™"
description: "The remediation companion to our vulnerability assessment. Six phases of hardening a Grafana/Prometheus monitoring stack -- from session timeouts to OpenBAO secret injection, HAProxy TLS termination, Docker network segmentation, and container capability dropping. Every config shown, every gotcha documented."
tags:
  - Security
  - Grafana
  - Prometheus
  - Hardening
  - Docker
  - HAProxy
  - TLS
  - OpenBAO
  - Monitoring
  - Container Security
  - Security Headers
  - Compliance
  - DevSecOps
categories:
  - Security
  - Hardening Guides
  - Homelab
keywords:
  - grafana security hardening
  - prometheus basic auth configuration
  - haproxy tls termination grafana
  - openbao secret injection docker
  - docker container capability dropping
  - monitoring stack hardening guide
  - grafana session timeout configuration
  - haproxy rate limiting configuration
  - prometheus network segmentation docker
  - container security best practices
  - nist 800-53 monitoring compliance
  - soc 2 grafana hardening
  - cis docker benchmark compliance
  - pci-dss monitoring stack
  - grafana audit logging json
  - security headers haproxy
  - grafana snapshot security
  - openssl certificate renewal automation
  - appRole openbao grafana
  - defense in depth monitoring
showToc: false
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
---

*The views and opinions expressed on this site are my own and do not reflect the views of my employer. This content is based entirely on publicly available documentation for open-source tools and does not contain proprietary information from any current or former employer.*

---

**⚠️ Controlled Lab Environment — Educational Use Only**

All configurations and commands in this post were developed and tested in an isolated personal homelab environment. Adapt all settings to your own environment’s requirements before implementation. Always test in non-production environments first.

---

# Fix It — Hardening & Verification Playbook

**Published by Oob Skulden™**

**Methodology:** Fix the vulnerability. Verify the fix.

**Target Environment:** Grafana-lab (192.168.75.109) | Authentik-lab (192.168.80.54) | OpenBAO (192.168.100.140)

**Baseline Score:** 6.0/10 (vulnerable) | **Target Score:** 9.8/10 (hardened)

**URL Verification Date:** February 21, 2026

---

## Document Structure

This document contains the last two steps of the four-step pattern:

1. **FIX IT** — Step-by-step hardening commands
2. **VERIFY** — Confirm the vulnerability is now closed

> For PROVE IT and BREAK IT steps, see **Part 1: Build It, Break It — Vulnerability Discovery & Exploitation Playbook**

FIX IT and VERIFY sections run on the actual servers (they must — you can't harden a server remotely).

---

## The Big Picture

Alright, so here's where we are. In Part 1, we proved that this monitoring stack is basically an open book. Prometheus is handing out infrastructure maps to anyone who asks, Grafana sessions last forever, secrets are sitting in plaintext config files, and there's not a single byte of encryption in transit. We scored it a 6 out of 10, and honestly, that might be generous.

Now we fix it. Six phases, each one building on the last. We're not doing a "rip and replace" — we're hardening incrementally so you can validate every change as you go. If something breaks, you know exactly which phase caused it. That's the whole point of doing this step by step instead of dumping a "hardened" docker-compose.yml and hoping for the best.

One more thing before we dive in — every phase ends with a verification script. Don't skip those. The whole methodology is prove it's broken, then prove it's fixed. If the VERIFY script doesn't pass, don't move on. Debug it. That's how you actually learn this stuff, and it's how you'd demonstrate compliance in a real audit.

---

## Prerequisites — What Must Exist Before Phase 1

### Infrastructure (must be running and reachable):

- **Grafana-lab (192.168.75.109):** Docker + docker compose installed, `~/monitoring/` directory with vanilla monitoring stack
- **Authentik-lab (192.168.80.54):** Authentik deployed, admin access to `http://192.168.80.54:9000`
- **OpenBAO (192.168.100.140):** OpenBAO deployed in Docker, unsealed, root token available

### Authentik Configuration (must be done in Authentik UI first):

1. Create an OAuth2/OIDC Provider named `grafana-oidc-provider`
2. Set redirect URI: `http://192.168.75.109:3000/login/generic_oauth`
3. Note the Client ID (typically `grafana-client`) and Client Secret (you'll need this in Step 1.1)
4. Create an Application linked to this provider

### Grafana-lab host packages:

```bash
sudo apt install -y apache2-utils jq
```

(needed for Phases 3 and 6)

---

## Password & Credential Convention

This playbook uses consistent variable names across all phases. Decide your passwords NOW and use them everywhere.

```bash
# DECIDE THESE VALUES BEFORE STARTING — write them down securely
# These are used throughout the entire playbook

ADMIN_PASSWORD="<your-grafana-admin-password>"      # Grafana admin (replaces default admin/admin)
PROM_PASSWORD="<your-prometheus-password>"           # Prometheus basic auth
OAUTH_CLIENT_SECRET="<from-authentik-step-above>"    # Copy from Authentik provider

# These are GENERATED during Phase 1 Step 1.2 — you'll fill them in after that step
GRAFANA_ROLE_ID="<generated-in-step-1.2>"
GRAFANA_SECRET_ID="<generated-in-step-1.2>"

# These are GENERATED during Phase 6.1 — you'll fill them in after that step
PKI_ROLE_ID="<generated-in-phase-6.1>"
PKI_SECRET_ID="<generated-in-phase-6.1>"
```

Every command in this playbook references these variables. When you see `$ADMIN_PASSWORD` in a curl command, use the value you chose above.

---

## Phase 1: FIX IT — Session Hardening + OpenBAO Secrets Management

**Time:** ~2 hours | **Score:** 6.0 to 7.5 (+1.5)

**Vulnerabilities Addressed:** VULN-05, VULN-06

This is the biggest single jump in our security score, and for good reason. We're tackling two problems that, combined, are genuinely dangerous.

**VULN-05 (OAuth Secret in Plaintext)** — Right now, the OAuth client secret that connects Grafana to Authentik is sitting in a `.env` file and gets injected straight into the container's environment variables. That means anyone with `docker inspect` access can read it, anyone who compromises the host can read it, and it's probably checked into version control somewhere. We're going to move that secret into OpenBAO (our secrets vault) so it's retrieved at runtime and never stored on disk.

**VULN-06 (Session Persistence After Account Disable)** — This one's the scarier of the two. Right now, Grafana has no session timeouts. Zero. If someone logs in and you disable their account in Authentik an hour later, their session cookie still works. They can still hit the API, still create service accounts, still exfiltrate data — because Grafana never checks back with Authentik once the session is established. We're adding a 1-hour inactive timeout, a 24-hour hard maximum, and 10-minute token rotation so that sessions actually expire.

Let's start with the vault.

---

### Step 1.1: OpenBAO — Store OAuth Secret

First thing we need to do is get the secret off the Grafana host and into the vault. Think of OpenBAO like a safe deposit box — Grafana doesn't get a copy of the key to keep, it has to go to the vault and ask for it every time the container starts. That way, if someone compromises the Grafana host, the secret isn't just sitting there waiting to be found.

```bash
# SSH to OpenBAO host (192.168.100.140)
ssh oob@192.168.100.140

# Enter the container
sudo docker exec -it openbao sh

# Set environment
export BAO_ADDR='http://127.0.0.1:8200'

# Authenticate (enter root token when prompted)
bao login

# Enable KV v2 (skip if already enabled)
bao secrets enable -version=2 -path=secret kv 2>/dev/null || echo "KV already enabled"

# Store the OAuth secret
# IMPORTANT: Use the $OAUTH_CLIENT_SECRET from your Password Convention section
bao kv put secret/grafana/oauth \
  client_id="grafana-client" \
  client_secret="$OAUTH_CLIENT_SECRET"

# Verify
bao kv get secret/grafana/oauth
```

---

### Step 1.2: OpenBAO — Create AppRole for Grafana

Now here's where it gets important. We're not going to give Grafana a root token — that would defeat the entire purpose. Instead, we create an AppRole, which is like a service account specifically for Grafana. It gets a role_id (think username) and a secret_id (think password), and the policy we attach only lets it read from `secret/data/grafana/*`. It can't write, it can't list other paths, it can't do anything else in the vault. Least privilege.

```bash
# Still inside OpenBAO container shell

# Enable AppRole (skip if already enabled)
bao auth enable approle 2>/dev/null || echo "AppRole already enabled"

# Create policy — read-only access to Grafana secrets
bao policy write grafana-policy - << 'EOF'
path "secret/data/grafana/*" {
  capabilities = ["read"]
}
path "secret/metadata/grafana/*" {
  capabilities = ["read", "list"]
}
EOF

# Create AppRole
bao write auth/approle/role/grafana \
  token_policies="grafana-policy" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0 \
  secret_id_num_uses=0

# Get Role ID (SAVE THIS -- you need it in Step 1.3 .env as GRAFANA_ROLE_ID)
bao read auth/approle/role/grafana/role-id
# Example output: role_id    5154bce7-b3a9-3e94-aeba-c9ac9a86ef8b

# Generate Secret ID (SAVE THIS -- you need it in Step 1.3 .env as GRAFANA_SECRET_ID)
bao write -f auth/approle/role/grafana/secret-id
# Example output: secret_id    4007fcee-89d2-5a5f-fd80-4dea4a27abd4

# >>> WRITE THESE DOWN NOW and update the Password Convention section <<<

# Test the full chain (use the role_id and secret_id you just saved)
BAO_TEST_TOKEN=$(bao write -format=json auth/approle/login \
  role_id="$GRAFANA_ROLE_ID" \
  secret_id="$GRAFANA_SECRET_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
echo "Token: $BAO_TEST_TOKEN"

# Exit OpenBAO container
exit

# Exit SSH
exit
```

---

### Step 1.3: Grafana-lab — Create .env File

Now we set up the .env file on the Grafana host. Notice what's in here and what's NOT. The admin password and the OpenBAO AppRole credentials are here — but the OAuth client secret is gone. That's the whole point. The .env tells Grafana how to reach the vault, and the vault provides the actual secret at startup.

We also `chmod 600` this file because even though we've removed the OAuth secret, the AppRole credentials are sensitive too. If an attacker gets the role_id and secret_id, they can authenticate to OpenBAO and read the secrets themselves.

Use the passwords you chose in the Password & Credential Convention section and the Role ID / Secret ID from Step 1.2 output.

```bash
# On Grafana-lab (192.168.75.109)
cd ~/monitoring

# Backup current .env
cp .env .env.vanilla

# Create hardened .env (fill in YOUR values from the Convention section)
cat > .env << EOF
# Grafana Credentials
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=$ADMIN_PASSWORD

# OpenBAO AppRole (from Step 1.2 output)
BAO_ADDR=http://192.168.100.140:8200
BAO_ROLE_ID=$GRAFANA_ROLE_ID
BAO_SECRET_ID=$GRAFANA_SECRET_ID

# Prometheus Password (used in Phase 3)
PROMETHEUS_PASSWORD=$PROM_PASSWORD
EOF

# Lock down permissions
chmod 600 .env

# VERIFY: Confirm no placeholder text remains
grep "YOUR_\|<" .env && echo "ERROR: Unfilled placeholders!" || echo "OK: All values filled"
```

---

### Step 1.4: Create Entrypoint Script

This is the most important file in the entire playbook. The entrypoint script runs before Grafana starts, authenticates to OpenBAO using the AppRole credentials, pulls the OAuth secret, and passes it into the Grafana process. The secret never touches disk, never appears in docker-compose.yml, and never shows up in `docker inspect`.

**CRITICAL GOTCHA:** Must use `exec env VAR=value /run.sh` pattern. Simple `export` does NOT persist through `exec`.

This one cost me a lot of debugging time. If you use `export GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=$CLIENT_SECRET` followed by `exec /run.sh`, the variable disappears. The `exec` call replaces the shell process, and exports don't carry through. You have to use the `exec env VAR=value /run.sh` pattern to inject the variables directly into the new process. This is one of those Linux fundamentals that bites you when you least expect it.

```bash
cat > ~/monitoring/entrypoint.sh << 'ENTRYPOINT'
#!/bin/sh
# Grafana Entrypoint with OpenBAO Secret Retrieval
# Published by Oob Skulden™

set -e

echo "[entrypoint] Authenticating to OpenBAO..."
LOGIN_RESPONSE=$(curl -s --fail \
  --request POST \
  --data "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
  ${BAO_ADDR}/v1/auth/approle/login)

TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

if [ -z "$TOKEN" ]; then
  echo "[entrypoint] ERROR: Failed to authenticate to OpenBAO"
  echo "[entrypoint] Response: $LOGIN_RESPONSE"
  exit 1
fi

echo "[entrypoint] Retrieving OAuth secrets..."
SECRETS=$(curl -s --fail \
  -H "X-Vault-Token: ${TOKEN}" \
  ${BAO_ADDR}/v1/secret/data/grafana/oauth)

if [ -z "$SECRETS" ]; then
  echo "[entrypoint] ERROR: Failed to retrieve secrets"
  exit 1
fi

CLIENT_ID=$(echo "$SECRETS" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['client_id'])")
CLIENT_SECRET=$(echo "$SECRETS" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['client_secret'])")

if [ -z "$CLIENT_SECRET" ]; then
  echo "[entrypoint] ERROR: Failed to parse OAuth secret"
  echo "[entrypoint] Check that secret/grafana/oauth contains client_id and client_secret"
  exit 1
fi

echo "[entrypoint] Secrets loaded successfully"
echo "[entrypoint] Starting Grafana..."

exec env \
  GF_AUTH_GENERIC_OAUTH_CLIENT_ID="$CLIENT_ID" \
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="$CLIENT_SECRET" \
  /run.sh "$@"
ENTRYPOINT

chmod +x ~/monitoring/entrypoint.sh
```

---

### Step 1.5: Update docker-compose.yml

Here's the full compose file for Phase 1. A few things to pay attention to: Grafana is now bound to `127.0.0.1:3000` instead of `0.0.0.0:3000` — this means it only accepts connections from localhost, not from the network. We're going to put HAProxy in front of it in Phase 2, but even now, this is a good habit. The entrypoint is set to our custom script, and the session hardening environment variables are in the `environment` section.

Notice that the OAuth `client_id` and `client_secret` are NOT in this file. The entrypoint script injects them at runtime. That's the entire point of Steps 1.1 through 1.4.

```bash
cp docker-compose.yml docker-compose.yml.vanilla

cat > docker-compose.yml << 'EOF'
services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    user: "0"
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./entrypoint.sh:/entrypoint.sh:ro
    entrypoint: ["/entrypoint.sh"]
    env_file:
      - .env
    environment:
      # Session Hardening (Phase 1)
      - GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h
      - GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h
      - GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10
      # OAuth2 / Authentik (secrets injected by entrypoint)
      - GF_AUTH_GENERIC_OAUTH_ENABLED=true
      - GF_AUTH_GENERIC_OAUTH_NAME=Authentik
      - GF_AUTH_GENERIC_OAUTH_SCOPES=openid profile email groups
      - GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://192.168.80.54:9000/application/o/authorize/
      - GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://192.168.80.54:9000/application/o/token/
      - GF_AUTH_GENERIC_OAUTH_API_URL=http://192.168.80.54:9000/application/o/userinfo/
      - GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=contains(groups[*], 'Grafana Admins') && 'Admin' || 'Viewer'
      - GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true
      - GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN=false
      # Server
      - GF_SERVER_ROOT_URL=http://192.168.75.109:3000

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
EOF
```

---

### Step 1.6: Deploy and Validate

This is the moment of truth for Phase 1. We're tearing down the old stack and bringing up the new one. The first thing we check is whether the entrypoint script successfully authenticated to OpenBAO and retrieved the secret. If you see "Secrets loaded successfully" in the logs, the vault integration is working. If you see an error, double-check your AppRole credentials in the .env file and make sure OpenBAO is unsealed and reachable from the Grafana host.

```bash
docker compose down -v
docker compose up -d

# Wait for startup
sleep 10

# Validate entrypoint ran
docker logs grafana 2>&1 | grep "\[entrypoint\]"
# Expected:
#   [entrypoint] Authenticating to OpenBAO...
#   [entrypoint] Retrieving OAuth secrets...
#   [entrypoint] Secrets loaded successfully
#   [entrypoint] Starting Grafana...

# Validate session settings loaded
docker logs grafana 2>&1 | grep -E "(INACTIVE_LIFETIME|MAXIMUM_LIFETIME|TOKEN_ROTATION)"

# Validate secret NOT in container metadata
docker inspect grafana --format '{{json .Config.Env}}' | grep -i "CLIENT_SECRET"
# Expected: No output (secret only in process environment)

# Validate Grafana healthy
curl -s http://localhost:3000/api/health | grep '"database":"ok"'

# Test OAuth login in browser: http://192.168.75.109:3000
```

---

### VERIFY — Phase 1 Vulnerabilities Closed

```bash
echo "=== Phase 1: VERIFY VULNS CLOSED ==="
echo ""

echo "--- VULN-05: OAuth Secret No Longer Exposed ---"
echo -n "  Secret NOT in .env: "
grep -q "CLIENT_SECRET" ~/monitoring/.env && echo "FAIL (still in .env)" || echo "PASS"

echo -n "  Secret NOT in docker-compose.yml: "
grep -qi "client_secret" ~/monitoring/docker-compose.yml && echo "FAIL" || echo "PASS"

echo -n "  Secret NOT in container env: "
docker exec grafana env 2>/dev/null | grep -q "CLIENT_SECRET" && echo "FAIL" || echo "PASS"

echo -n "  Secret NOT in docker inspect: "
docker inspect grafana --format '{{json .Config.Env}}' | grep -q "CLIENT_SECRET" && echo "FAIL" || echo "PASS"

echo -n "  Entrypoint retrieves from OpenBAO: "
docker logs grafana 2>&1 | grep -q "Secrets loaded successfully" && echo "PASS" || echo "FAIL"

echo ""
echo "--- VULN-06: Session Timeouts Now Configured ---"
echo -n "  Inactive timeout (1h): "
docker logs grafana 2>&1 | grep -q "INACTIVE_LIFETIME_DURATION=1h" && echo "PASS" || echo "FAIL"

echo -n "  Max lifetime (24h): "
docker logs grafana 2>&1 | grep -q "MAXIMUM_LIFETIME_DURATION=24h" && echo "PASS" || echo "FAIL"

echo -n "  Token rotation (10min): "
docker logs grafana 2>&1 | grep -q "TOKEN_ROTATION_INTERVAL_MINUTES=10" && echo "PASS" || echo "FAIL"

echo -n "  OAuth login still works: "
curl -s http://localhost:3000/login | grep -q "Authentik" && echo "PASS" || echo "FAIL"

echo ""
echo "Score: 6.0 -> 7.5 (+1.5)"
```

**Phase 1 Checkpoint:** Before proceeding to Phase 2, confirm: (1) OAuth login works in browser, (2) session timeouts appear in `docker logs grafana`, (3) no CLIENT_SECRET in `docker inspect`. If any fail, troubleshoot before continuing.

---

## Phase 2: FIX IT — HAProxy TLS Termination

**Time:** ~1 hour | **Score:** 7.5 to 8.0 (+0.5)

**Vulnerabilities Addressed:** VULN-07, VULN-10

Phase 1 secured our secrets and sessions. But here's the thing — all of that work is undermined if traffic between the browser and Grafana is unencrypted. Every login, every session cookie, every API call is traveling in plaintext across the network right now. Anyone on the same VLAN with tcpdump can see everything.

**VULN-10 (No TLS Encryption)** — This is the big one. We're putting HAProxy in front of Grafana as a reverse proxy that handles TLS termination. All external traffic hits HAProxy on port 443 (HTTPS), and HAProxy talks to Grafana on localhost port 3000. The certificate comes from our OpenBAO PKI engine — same vault, different use case.

**VULN-07 (No Rate Limiting)** — While we're adding HAProxy, we're also adding rate limiting. Right now, an attacker can throw thousands of login attempts per minute at Grafana with zero pushback. No lockout, no delay, no rate limit headers. HAProxy's stick-table feature gives us a simple but effective 100-requests-per-10-seconds limit per IP.

We're also adding a full suite of security headers (HSTS, X-Frame-Options, CSP basics) and stripping the Server header so we're not advertising what's running behind the proxy.

---

### Step 2.1: Issue TLS Certificate from OpenBAO

We're issuing a TLS certificate from OpenBAO's PKI secrets engine. This is the same vault we used for OAuth secrets in Phase 1, but now we're using its certificate authority capabilities. The certificate is valid for 30 days (720 hours), and we'll automate renewal in Phase 6.1.

One important detail — we're bundling the certificate, private key, and CA certificate into a single PEM file for HAProxy. The order matters: cert first, then key, then CA. Get this wrong and HAProxy will refuse to start with a cryptic error.

```bash
# SSH to OpenBAO (192.168.100.140)
ssh oob@192.168.100.140
sudo docker exec -it openbao sh
export BAO_ADDR='http://127.0.0.1:8200'
bao login

# Create PKI role for Grafana (if not exists)
bao write pki/roles/grafana-server \
  allowed_domains="192.168.75.109" \
  allow_bare_domains=true \
  allow_ip_sans=true \
  max_ttl="720h" \
  require_cn=false

# Issue certificate
bao write -format=json pki/issue/grafana-server \
  common_name="192.168.75.109" \
  ip_sans="192.168.75.109" \
  ttl="720h" > /tmp/grafana-cert.json

# Extract components (using python3 for reliable JSON parsing)
python3 -c "
import json
with open('/tmp/grafana-cert.json') as f:
    data = json.load(f)['data']
with open('/tmp/grafana.crt', 'w') as f:
    f.write(data['certificate'])
with open('/tmp/grafana.key', 'w') as f:
    f.write(data['private_key'])
with open('/tmp/grafana-ca.crt', 'w') as f:
    f.write(data['issuing_ca'])
print('Certificates extracted successfully')
"

# Bundle for HAProxy (CRITICAL: order matters — cert + key + CA)
cat /tmp/grafana.crt /tmp/grafana.key /tmp/grafana-ca.crt > /tmp/grafana.pem
chmod 600 /tmp/grafana.pem

exit    # exit container

# Copy to Grafana host
scp /tmp/grafana.pem oob@192.168.75.109:/tmp/

# Cleanup
rm /tmp/grafana-cert.json /tmp/grafana.crt /tmp/grafana.key /tmp/grafana-ca.crt /tmp/grafana.pem

exit    # exit SSH
```

---

### Step 2.2: Install HAProxy on Grafana-lab

```bash
# On Grafana-lab (192.168.75.109)
sudo apt update && sudo apt install -y haproxy

# Install certificate
sudo mkdir -p /etc/haproxy/certs
sudo cp /tmp/grafana.pem /etc/haproxy/certs/grafana.pem
sudo chown haproxy:haproxy /etc/haproxy/certs/grafana.pem
sudo chmod 600 /etc/haproxy/certs/grafana.pem
rm /tmp/grafana.pem

# Verify
sudo openssl x509 -in /etc/haproxy/certs/grafana.pem -noout -subject -dates
```

---

### Step 2.3: Configure HAProxy

This is the HAProxy configuration that does the heavy lifting for Phase 2. Let me walk through what each section is doing, because there's a lot packed in here.

The `frontend http_grafana` section catches any HTTP traffic on port 80 and redirects it to HTTPS with a 301. This means even if someone types `http://192.168.75.109` in their browser, they get bumped to HTTPS automatically.

The `frontend https_grafana` section is where the real work happens. It terminates TLS on port 443, injects all our security headers, implements rate limiting via a stick-table (100 requests per 10 seconds per IP), and forwards the request to the Grafana backend on localhost:3000.

The security headers are worth calling out individually. HSTS tells browsers to always use HTTPS for this site. X-Frame-Options prevents clickjacking. X-Content-Type-Options prevents MIME sniffing. And we're deleting the Server and X-Powered-By headers so we're not advertising our stack to anyone scanning.

The `frontend stats` binds to localhost:8404 — it's the HAProxy stats page, and it's intentionally only accessible from the server itself. You don't want your load balancer stats exposed to the network.

```bash
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.original

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
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend http_grafana
    bind *:80
    mode http
    redirect scheme https code 301

frontend https_grafana
    bind *:443 ssl crt /etc/haproxy/certs/grafana.pem
    mode http

    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    http-response set-header Permissions-Policy "camera=(), microphone=(), geolocation=()"
    http-response del-header Server
    http-response del-header X-Powered-By

    # Rate limiting (100 req/10s per IP)
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

    # Forward proto header
    http-request set-header X-Forwarded-Proto https

    default_backend grafana_backend

backend grafana_backend
    mode http
    balance roundrobin
    option forwardfor
    server grafana 127.0.0.1:3000 check

frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 30s
EOF

# Validate config
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
```

---

### Step 2.4: Update Grafana ROOT_URL and Restart

```bash
cd ~/monitoring

# Update ROOT_URL in docker-compose.yml
# Change: GF_SERVER_ROOT_URL=http://192.168.75.109:3000
# To:     GF_SERVER_ROOT_URL=https://192.168.75.109
sed -i 's|GF_SERVER_ROOT_URL=http://192.168.75.109:3000|GF_SERVER_ROOT_URL=https://192.168.75.109|' docker-compose.yml

# Restart Grafana to pick up new ROOT_URL
docker compose up -d --force-recreate grafana

# Start HAProxy
sudo systemctl enable haproxy
sudo systemctl restart haproxy
```

---

### Step 2.5: Update Authentik Redirect URI

In Authentik admin (`http://192.168.80.54:9000`):

1. Go to **Applications -> Providers -> grafana-oidc-provider**
2. Change Redirect URI from `http://192.168.75.109:3000/login/generic_oauth` to `https://192.168.75.109/login/generic_oauth`
3. Click **Update**

---

### VERIFY — Phase 2 Vulnerabilities Closed

```bash
echo "=== Phase 2: VERIFY VULNS CLOSED ==="
echo ""

echo "--- VULN-10: TLS Now Active ---"
echo -n "  HTTPS responds: "
curl -skI https://192.168.75.109 | grep -q "200\|302" && echo "PASS" || echo "FAIL"

echo -n "  HTTP redirects to HTTPS: "
curl -sI http://192.168.75.109 | grep -q "301" && echo "PASS" || echo "FAIL"

echo -n "  HSTS header present: "
curl -skI https://192.168.75.109 | grep -qi "strict-transport-security" && echo "PASS" || echo "FAIL"

echo -n "  X-Frame-Options present: "
curl -skI https://192.168.75.109 | grep -qi "x-frame-options" && echo "PASS" || echo "FAIL"

echo -n "  Server header stripped: "
curl -skI https://192.168.75.109 | grep -qi "^server:" && echo "FAIL (exposed)" || echo "PASS (stripped)"

echo -n "  Direct port 3000 blocked: "
curl -s --connect-timeout 3 http://192.168.75.109:3000 >/dev/null 2>&1 && echo "FAIL (accessible)" || echo "PASS (blocked)"

echo -n "  TLS cert valid: "
echo | openssl s_client -connect 192.168.75.109:443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null && echo "PASS" || echo "FAIL"

echo ""
echo "--- VULN-07: Rate Limiting Active ---"
echo -n "  HAProxy running: "
sudo systemctl is-active haproxy | grep -q "active" && echo "PASS" || echo "FAIL"

echo -n "  Rate limiting (verify 429 on flood): "
# Rapid fire 150 requests — last ones should get 429
for i in $(seq 1 150); do
  curl -sk -o /dev/null -w "" https://192.168.75.109/api/health
done
LAST_CODE=$(curl -sk -o /dev/null -w "%{http_code}" https://192.168.75.109/api/health)
[ "$LAST_CODE" = "429" ] && echo "PASS (429 returned)" || echo "MANUAL CHECK ($LAST_CODE)"

echo ""
echo "Score: 7.5 -> 8.0 (+0.5)"
```

**Phase 2 Checkpoint:** Before proceeding to Phase 3, confirm: (1) `https://192.168.75.109` loads in browser (accept self-signed cert), (2) `http://192.168.75.109` redirects to HTTPS, (3) OAuth login still works through HTTPS. Also update Authentik redirect URI to use `https://` if not done in Step 2.5.

---

## Phase 3: FIX IT — Prometheus Authentication

**Time:** ~30 minutes | **Score:** 8.0 to 8.5 (+0.5)

**Vulnerabilities Addressed:** VULN-01 (Grafana default creds — addressed by strong password in Phase 1), VULN-02 (Prometheus unauthenticated), VULN-03 (cAdvisor exposure — partial, full fix in Phase 6), VULN-04 (Blackbox SSRF — partial, full fix in Phase 6)

This phase is about the most dangerous thing we found in Part 1 — Prometheus is completely open. No authentication, no authorization, nothing. Anybody on the network can query it and get a complete map of your infrastructure: hostnames, kernel versions, Docker container names, internal IPs, scrape targets. It's a free reconnaissance tool for attackers.

**VULN-02 (Prometheus Unauthenticated)** — We're adding basic auth to Prometheus using its built-in `web-config.yml` feature. This means every request to the Prometheus API now requires a username and password. We're also binding Prometheus to localhost so it's not reachable from the network at all — Grafana talks to it over the Docker network, which is internal.

**VULN-03/04 (cAdvisor and Blackbox Exposure)** — We're partially addressing these here by binding Prometheus to localhost (so the Prometheus *query* path is closed), but the exporters themselves are still exposed on their own ports. We'll finish that in Phase 6.3 when we bind them to localhost too.

The tricky part of this phase is the datasource provisioning. We need Grafana to automatically know the Prometheus password so it can query through the new auth. That's what the provisioned datasource file does — it injects the credentials at Grafana startup instead of requiring manual configuration in the UI.

**GOTCHA:** Delete any manually-created Prometheus datasource in Grafana UI BEFORE this phase. Duplicate datasources (one with auth, one without) cause browser WWW-Authenticate popups.

---

### Step 3.1: Install htpasswd and Generate Hash

We're using `htpasswd` from the apache2-utils package to generate a bcrypt hash of the Prometheus password. Prometheus expects bcrypt specifically — MD5 or SHA won't work. The `-C 10` flag sets the bcrypt cost factor. Higher is slower (more resistant to brute force), but 10 is a good balance for a service that only authenticates on startup.

```bash
# On Grafana-lab
sudo apt install -y apache2-utils

# Generate bcrypt hash (use the password from .env PROMETHEUS_PASSWORD)
source ~/monitoring/.env
PROM_HASH=$(htpasswd -nbB -C 10 prometheus "$PROMETHEUS_PASSWORD" | cut -d: -f2)
echo "Hash: $PROM_HASH"
```

---

### Step 3.2: Create Prometheus web-config.yml

```bash
cat > ~/monitoring/prometheus/web-config.yml << EOF
basic_auth_users:
  prometheus: $PROM_HASH
EOF

chmod 644 ~/monitoring/prometheus/web-config.yml
```

---

### Step 3.3: Create Grafana Datasource Provisioning

This is the part that makes everything work together seamlessly. Instead of manually adding the Prometheus datasource in the Grafana UI (which you'd have to redo every time you rebuild), we're using Grafana's provisioning feature to declare the datasource as code. The `${PROMETHEUS_PASSWORD}` variable gets resolved from the container's environment at startup — it pulls from the `.env` file we created in Phase 1.

The `editable: false` flag is intentional. We don't want someone accidentally modifying the provisioned datasource in the UI and breaking the auth configuration. If you need to change the password, change it in the `.env` file and redeploy.

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

chmod 644 ~/monitoring/grafana/provisioning/datasources/prometheus.yml
```

---

### Step 3.4: Update docker-compose.yml

Update the Prometheus service to add auth and localhost binding, and add provisioning volume to Grafana.

```bash
cd ~/monitoring
cp docker-compose.yml docker-compose.yml.backup.$(date +%Y%m%d-%H%M%S)
```

Edit with `nano` — update the **prometheus** service:

```yaml
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
```

Add provisioning volume to **Grafana**:

```yaml
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./entrypoint.sh:/entrypoint.sh:ro
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
```

---

### Step 3.5: Deploy and Validate

```bash
docker compose up -d --force-recreate prometheus grafana
sleep 5

# Prometheus requires auth now
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/metrics
# Expected: 401

# With credentials it works
source ~/monitoring/.env
curl -s -o /dev/null -w "%{http_code}" -u prometheus:$PROMETHEUS_PASSWORD http://localhost:9090/metrics
# Expected: 200

# Prometheus not accessible externally
curl -s --connect-timeout 3 http://192.168.75.109:9090/metrics
# Expected: Connection refused
```

---

### VERIFY — Phase 3 Vulnerabilities Closed

```bash
echo "=== Phase 3: VERIFY VULNS CLOSED ==="
source ~/monitoring/.env

echo ""
echo "--- VULN-02: Prometheus Now Requires Auth ---"

echo -n "  Auth required (401): "
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/metrics)
[ "$HTTP" = "401" ] && echo "PASS" || echo "FAIL ($HTTP)"

echo -n "  Auth works with creds: "
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -u prometheus:$PROMETHEUS_PASSWORD http://localhost:9090/metrics)
[ "$HTTP" = "200" ] && echo "PASS" || echo "FAIL ($HTTP)"

echo -n "  Localhost only: "
sudo ss -tlnp | grep 9090 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"

echo -n "  External access blocked: "
curl -s --connect-timeout 3 http://192.168.75.109:9090/metrics >/dev/null 2>&1 && echo "FAIL" || echo "PASS"

echo -n "  Datasource provisioned: "
docker logs grafana 2>&1 | grep -q "inserting datasource\|Datasource" && echo "PASS" || echo "CHECK MANUALLY"

echo ""
echo "Score: 8.0 -> 8.5 (+0.5)"
```

**Phase 3 Checkpoint:** Before proceeding to Phase 4, confirm: (1) `curl http://localhost:9090/metrics` returns 401, (2) `curl -u prometheus:$PROM_PASSWORD http://localhost:9090/metrics` returns 200, (3) Grafana dashboards still show data (provisioned datasource works). **GOTCHA:** If you see WWW-Authenticate popups in the browser, delete any manually-created Prometheus datasource from Grafana UI — the provisioned one handles auth automatically.

---

## Phase 5: FIX IT — Container Hardening

**Time:** ~45 minutes | **Score:** 9.0 to 9.5 (+0.5)

**Vulnerabilities Addressed:** VULN-09, VULN-11

Alright, we've secured the application layer — secrets are in the vault, traffic is encrypted, Prometheus requires auth, and the OpenBAO integration is validated. Now we go deeper into the container itself.

**VULN-09 (Missing Container Hardening)** — By default, Docker containers inherit a huge set of Linux capabilities. Your Grafana container can do things like change file ownership, bind to privileged ports, send raw packets, and override file permissions — capabilities it absolutely does not need to serve dashboards. We're going to `cap_drop: ALL` to remove every capability, then selectively add back only the four that Grafana actually needs (CHOWN, SETGID, SETUID, and DAC_OVERRIDE). We're also setting `no-new-privileges` so that even if an attacker finds a way to execute code inside the container, they can't escalate their privileges.

**VULN-11 (No Resource Limits)** — Without resource limits, a single container can consume all the CPU and memory on the host. That's a denial-of-service risk — whether it's a memory leak, a runaway query, or an attacker intentionally flooding the service. We're capping Grafana at 2 CPU cores and 2GB of memory. That's generous for a monitoring dashboard, but it means a compromised container can't starve the host.

**CRITICAL GOTCHAS:**

1. `read_only: true` is **INCOMPATIBLE** with Grafana (SQLite needs write access)
2. `DAC_OVERRIDE` capability is **REQUIRED** — without it, SQLite writes fail: "attempt to write a readonly database"
3. Use `nano +linenum` for YAML edits, **NEVER** `sed` (UTF-8 corruption risk)

The DAC_OVERRIDE gotcha is the one that will get you. You'll see a lot of container hardening guides that say "drop all capabilities" and leave it at that. Grafana uses SQLite for its internal database, and SQLite needs DAC_OVERRIDE to write to files owned by different users. Without it, Grafana starts, tries to write to its database, and immediately crashes with "attempt to write a readonly database." This is one of those things you only learn by actually doing it and watching it fail.

---

### Step 5.1: Add Hardening to Grafana Service

```bash
cd ~/monitoring
cp docker-compose.yml docker-compose.yml.backup.$(date +%Y%m%d-%H%M%S)
```

Add these lines to the **grafana** service in docker-compose.yml (use `nano`):

```yaml
    # Container Hardening (Phase 5)
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
      - DAC_OVERRIDE
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

---

### Step 5.2: Deploy and Validate

```bash
# Validate YAML
docker compose config --quiet && echo "YAML OK" || echo "YAML ERROR"

# Deploy
docker compose up -d --force-recreate grafana

# IMPORTANT: Wait and check for crash loop
sleep 10
docker ps | grep grafana
# Look for "Up X seconds" NOT "Restarting (1)"

# If crash loop, check logs
docker logs grafana 2>&1 | tail -5
# If "attempt to write a readonly database" — you missed DAC_OVERRIDE
```

---

### VERIFY — Phase 5 Vulnerabilities Closed

```bash
echo "=== Phase 5: VERIFY VULNS CLOSED ==="
echo ""

echo "--- VULN-09: Container Hardened ---"
echo -n "  cap_drop ALL: "
docker inspect grafana --format='{{json .HostConfig.CapDrop}}' | grep -q "ALL" && echo "PASS" || echo "FAIL"

echo -n "  cap_add minimal: "
CAPS=$(docker inspect grafana --format='{{json .HostConfig.CapAdd}}')
echo "$CAPS" | grep -q "DAC_OVERRIDE" && echo "PASS ($CAPS)" || echo "FAIL ($CAPS)"

echo -n "  no-new-privileges: "
docker inspect grafana --format='{{json .HostConfig.SecurityOpt}}' | grep -q "no-new-privileges" && echo "PASS" || echo "FAIL"

echo ""
echo "--- VULN-11: Resource Limits Set ---"
echo -n "  Memory limit: "
MEM=$(docker inspect grafana --format='{{.HostConfig.Memory}}')
[ "$MEM" = "2147483648" ] && echo "PASS (2GB)" || echo "FAIL ($MEM)"

echo -n "  CPU limit: "
CPU=$(docker inspect grafana --format='{{.HostConfig.NanoCpus}}')
[ "$CPU" = "2000000000" ] && echo "PASS (2 cores)" || echo "FAIL ($CPU)"

echo -n "  Grafana healthy: "
curl -s http://localhost:3000/api/health | grep -q '"database":"ok"' && echo "PASS" || echo "FAIL"

echo ""
echo "Score: 9.0 -> 9.5 (+0.5)"
```

**Phase 5 Checkpoint:** Before proceeding to Phase 6, confirm: (1) `docker ps | grep grafana` shows "Up" not "Restarting", (2) `cap_drop ALL` shows in `docker inspect`, (3) Grafana loads in browser and dashboards display data. If crash loop: check `docker logs grafana` for "attempt to write a readonly database" — means `DAC_OVERRIDE` is missing from `cap_add`.

---

## Phase 6: FIX IT — Enhanced Security (Cert Renewal, Audit Logging, Network Hardening, Host Firewall)

**Time:** ~1.5 hours | **Score:** 9.5 to 9.8 (+0.3)

**Vulnerabilities Addressed:** VULN-12 (network + firewall), VULN-14 (logging), plus operational improvements

This is the final phase, and it's all about operational maturity — the kind of stuff that separates a homelab from something you could actually defend in an audit.

We're doing four things here: automating certificate renewal so TLS doesn't silently expire, adding structured audit logging so you actually have forensic evidence when something goes wrong, binding the remaining exporters to localhost so they're not exposed to the network, and adding a host-level firewall as a second independent layer of defense.

None of these individually are dramatic security improvements — that's why the score only goes up 0.3 points. But collectively, they're the difference between "we hardened this once" and "this is operationally maintained." Certificates that auto-renew don't expire at 3 AM on a Saturday. JSON logs can be ingested by a SIEM. Firewall rules survive Docker misconfigurations. This is the stuff that matters when you're not actively watching the system.

---

### Phase 6.1: Automated Certificate Renewal

Remember that TLS certificate we issued in Phase 2? It's valid for 30 days. If we don't renew it, HAProxy will start serving an expired cert, browsers will throw scary warnings, and your monitoring dashboard becomes effectively inaccessible. In production, expired certs are one of the most common causes of outages — just ask any SRE who's been paged at 2 AM because someone forgot to renew.

We're building a cron job that authenticates to OpenBAO with a dedicated PKI AppRole (separate from the Grafana secrets AppRole — different credentials, different permissions), issues a fresh certificate, installs it, and reloads HAProxy without downtime. The `systemctl reload haproxy` command is a graceful reload — existing connections finish normally while new connections get the new cert.

**Prerequisite:** Create a dedicated PKI AppRole on OpenBAO (don't reuse the Grafana secrets AppRole).

```bash
# On OpenBAO host
ssh oob@192.168.100.140
sudo docker exec -it openbao sh
export BAO_ADDR='http://127.0.0.1:8200'
bao login

# Create PKI-specific policy
bao policy write pki-renew-grafana - << 'EOF'
path "pki/issue/grafana-server" {
  capabilities = ["create", "update"]
}
EOF

# Create dedicated AppRole
bao write auth/approle/role/pki-grafana-renew \
  token_policies="pki-renew-grafana" \
  token_ttl=5m \
  token_max_ttl=10m

# Get credentials -- you need these for the renewal script below
bao read auth/approle/role/pki-grafana-renew/role-id
# Example: role_id    6cd54333-7046-2323-d667-9bede5715cd2

bao write -f auth/approle/role/pki-grafana-renew/secret-id
# Example: secret_id    a1b2c3d4-...

# >>> SAVE these as PKI_ROLE_ID and PKI_SECRET_ID in Password Convention <<<

exit    # container
exit    # SSH
```

Create the renewal script on Grafana-lab (fill in `PKI_ROLE_ID` and `PKI_SECRET_ID` from the step above):

```bash
sudo tee /usr/local/bin/renew-grafana-cert.sh > /dev/null << RENEWAL
#!/bin/bash
# Grafana HAProxy Certificate Renewal via AppRole
# Published by Oob Skulden™

set -e

OPENBAO_ADDR="http://192.168.100.140:8200"
PKI_ROLE_ID="$PKI_ROLE_ID"
PKI_SECRET_ID="$PKI_SECRET_ID"
GRAFANA_IP="192.168.75.109"
CERT_PATH="/etc/haproxy/certs/grafana.pem"

echo "=== Certificate Renewal Starting: \$(date) ==="

# Authenticate with PKI AppRole
TOKEN=\$(curl -s --fail -X POST \\
  -d "{\"role_id\":\"\${PKI_ROLE_ID}\",\"secret_id\":\"\${PKI_SECRET_ID}\"}" \\
  \${OPENBAO_ADDR}/v1/auth/approle/login | jq -r '.auth.client_token')

if [ -z "\$TOKEN" ] || [ "\$TOKEN" = "null" ]; then
  echo "ERROR: AppRole authentication failed"
  exit 1
fi

# Issue new certificate
CERT_JSON=\$(curl -s --fail -X POST \\
  -H "X-Vault-Token: \${TOKEN}" \\
  -d "{\"common_name\":\"\${GRAFANA_IP}\",\"ip_sans\":\"\${GRAFANA_IP}\",\"ttl\":\"720h\"}" \\
  \${OPENBAO_ADDR}/v1/pki/issue/grafana-server)

CERT=\$(echo "\$CERT_JSON" | jq -r '.data.certificate')
KEY=\$(echo "\$CERT_JSON" | jq -r '.data.private_key')
CA=\$(echo "\$CERT_JSON" | jq -r '.data.issuing_ca')

if [ -z "\$CERT" ] || [ "\$CERT" = "null" ]; then
  echo "ERROR: Failed to issue certificate"
  exit 1
fi

# Backup old cert
cp \${CERT_PATH} \${CERT_PATH}.backup.\$(date +%Y%m%d-%H%M%S) 2>/dev/null || true

# Install new certificate (cert + key + CA)
printf '%s\n%s\n%s\n' "\$CERT" "\$KEY" "\$CA" > \${CERT_PATH}
chown haproxy:haproxy \${CERT_PATH}
chmod 600 \${CERT_PATH}

# Reload HAProxy (zero downtime)
systemctl reload haproxy

echo "Certificate renewed successfully: \$(date)"
RENEWAL

sudo chmod 700 /usr/local/bin/renew-grafana-cert.sh

# Schedule: every 20 days at 2 AM
sudo touch /var/log/grafana-cert-renewal.log
(sudo crontab -l 2>/dev/null; echo "0 2 */20 * * /usr/local/bin/renew-grafana-cert.sh >> /var/log/grafana-cert-renewal.log 2>&1") | sudo crontab -

# Verify cron
sudo crontab -l | grep renew-grafana
```

---

### Phase 6.2: Audit Logging

Right now, Grafana's logs go to the console (stdout) and disappear when the container restarts. That means if someone compromises Grafana, creates a backdoor service account, and the container gets restarted for any reason — the evidence is gone. No forensic trail, no audit history, nothing to investigate.

We're fixing this by enabling file-based logging in JSON format with 30-day rotation. JSON format matters because it's machine-parseable — if you ever connect a SIEM or log aggregator (Loki, ELK, Splunk), JSON logs can be ingested without custom parsing rules. Console logs are human-readable but useless for automated analysis.

We're also disabling external snapshot sharing while we're here. Grafana snapshots can contain sensitive dashboard data, and the default configuration allows sharing them to external services. That's a data exfiltration risk that most people don't think about.

Add these environment variables to the **Grafana** service in docker-compose.yml:

```yaml
      # Audit Logging (Phase 6.2)
      - GF_LOG_MODE=console file
      - GF_LOG_LEVEL=info
      - GF_LOG_FILE_FORMAT=json
      - GF_LOG_FILE_LOG_ROTATE=true
      - GF_LOG_FILE_MAX_DAYS=30
      # Snapshot Security (Phase 6.3)
      - GF_SNAPSHOTS_EXTERNAL_ENABLED=false
```

Also add a log volume:

```yaml
    volumes:
      - grafana-storage:/var/lib/grafana
      - grafana-logs:/var/log/grafana
      - ./entrypoint.sh:/entrypoint.sh:ro
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
```

And in the **volumes** section:

```yaml
volumes:
  grafana-storage:
  prometheus-storage:
  grafana-logs:
```

Deploy:

```bash
docker compose up -d --force-recreate grafana
sleep 5

# Verify JSON logging
docker exec grafana ls -la /var/log/grafana/
docker exec grafana tail -3 /var/log/grafana/grafana.log
# Should show JSON-formatted log entries
```

---

### Phase 6.3: Network Hardening (Exporter Localhost Binding)

Remember in Part 1 when we showed that cAdvisor, Node Exporter, and Blackbox Exporter are all accessible from the network with zero authentication? Prometheus is locked down now (Phase 3), but the exporters themselves are still wide open on their own ports. Anyone on the network can hit port 9100 and get full host metrics, port 8080 for container details, or port 9115 to use Blackbox as an SSRF proxy to probe other VLANs.

The fix is simple — bind them to localhost. Prometheus scrapes them over the Docker network (which is internal), so they don't need to listen on a routable interface at all.

Update remaining services in docker-compose.yml:

```yaml
  node-exporter:
    ports:
      - "127.0.0.1:9100:9100"

  cadvisor:
    ports:
      - "127.0.0.1:8080:8080"

  blackbox-exporter:
    ports:
      - "127.0.0.1:9115:9115"
```

Deploy:

```bash
docker compose up -d --force-recreate node-exporter cadvisor blackbox-exporter
```

---

### Phase 6.4: Host Firewall Hardening (Defense-in-Depth)

**Why this matters even with localhost binding:**

Phase 6.3 binds exporters to `127.0.0.1`, which prevents external access on this single-host lab. But localhost binding is a Docker-level control — it's one layer. Defense-in-depth means adding a host-level firewall as a second independent layer, so that if Docker networking misconfigures (a compose file edit drops the `127.0.0.1` prefix, a container restart reverts to defaults, or you migrate to a multi-host deployment), the firewall still blocks unauthorized access.

In a distributed deployment where Prometheus and exporters run on separate VMs, localhost binding breaks scraping entirely — the exporter must listen on a routable interface. At that point, host firewall rules become the **primary** access control, not a backup layer. Building the firewall now means the rules are already in place when you scale out.

**What we're implementing:** `ufw` rules on Grafana-lab that restrict monitoring ports to localhost-only traffic at the kernel level, independent of Docker's port binding. This creates two independent controls for the same risk.

---

#### Step 6.4.1: Install and Enable ufw

```bash
# On Grafana-lab (192.168.75.109)

# Install ufw (may already be present on Debian 13)
sudo apt install -y ufw

# CRITICAL: Before enabling ufw, allow SSH first — or you'll lock yourself out
sudo ufw allow ssh
# This adds: 22/tcp ALLOW Anywhere

# Check current status
sudo ufw status
# Expected: Status: inactive (first time) or active with SSH rule
```

**Why ufw over iptables/nftables:** Debian 13 ships with nftables as the backend, but `ufw` provides a human-readable rule management layer on top. Rules persist across reboots automatically. For a homelab-to-production playbook, `ufw` is the right starting point — it's what most Debian/Ubuntu admins will use. The nftables and iptables equivalents are provided below for reference.

---

#### Step 6.4.2: Allow Required Inbound Traffic

```bash
# HTTPS (HAProxy) — must be accessible from the network for users to reach Grafana
sudo ufw allow 443/tcp comment 'HAProxy HTTPS - Grafana frontend'

# HTTP (HAProxy redirect) — needed for the 301 redirect to HTTPS
sudo ufw allow 80/tcp comment 'HAProxy HTTP - redirect to HTTPS'

# SSH — already allowed in Step 6.4.1, but add a comment for documentation
# (skip if already added above)
# sudo ufw allow ssh comment 'SSH management access'
```

**What we're NOT allowing from the network:** Ports 3000 (Grafana direct), 9090 (Prometheus), 9100 (Node Exporter), 8080 (cAdvisor), 9115 (Blackbox). These are already localhost-bound by Docker, but the firewall adds a second deny layer.

---

#### Step 6.4.3: Explicitly Deny Monitoring Ports from External Access

```bash
# Deny monitoring ports from any external source
# These are already localhost-bound by Docker (Phase 6.3), but the firewall
# provides a second independent control at the kernel level

# Grafana direct access — must go through HAProxy on 443
sudo ufw deny 3000/tcp comment 'Grafana direct - must use HAProxy'

# Prometheus — localhost only, Grafana queries via Docker network
sudo ufw deny 9090/tcp comment 'Prometheus - localhost only'

# Node Exporter — localhost only, Prometheus scrapes via Docker network
sudo ufw deny 9100/tcp comment 'Node Exporter - localhost only'

# cAdvisor — localhost only, Prometheus scrapes via Docker network
sudo ufw deny 8080/tcp comment 'cAdvisor - localhost only'

# Blackbox Exporter — localhost only, eliminates SSRF from network
sudo ufw deny 9115/tcp comment 'Blackbox Exporter - localhost only, SSRF prevention'
```

**Why explicit deny rules when ufw default-deny would cover this:** Two reasons. First, explicit rules self-document the intent — anyone running `ufw status` sees exactly which monitoring ports are blocked and why. Second, if someone later changes the default policy to allow (a common mistake), the explicit deny rules still protect the monitoring ports.

---

#### Step 6.4.4: Set Default Policies and Enable

```bash
# Default deny incoming — anything not explicitly allowed is dropped
sudo ufw default deny incoming

# Default allow outgoing — Grafana needs to reach Authentik (VLAN 80) and OpenBAO (VLAN 100)
sudo ufw default allow outgoing

# Enable the firewall
# WARNING: This prompt will ask "Command may disrupt existing ssh connections. Proceed (y|n)?"
# Answer y — we already allowed SSH in Step 6.4.1
sudo ufw enable
```

---

#### Step 6.4.5: Verify Firewall Rules

```bash
# View all rules with numbers and comments
sudo ufw status verbose

# Expected output (order may vary):
# Status: active
# Logging: on (low)
# Default: deny (incoming), allow (outgoing), disabled (routed)
#
# To             Action      From
# --             ------      ----
# 22/tcp         ALLOW IN    Anywhere          # SSH management access
# 443/tcp        ALLOW IN    Anywhere          # HAProxy HTTPS - Grafana frontend
# 80/tcp         ALLOW IN    Anywhere          # HAProxy HTTP - redirect to HTTPS
# 3000/tcp       DENY IN     Anywhere          # Grafana direct - must use HAProxy
# 9090/tcp       DENY IN     Anywhere          # Prometheus - localhost only
# 9100/tcp       DENY IN     Anywhere          # Node Exporter - localhost only
# 8080/tcp       DENY IN     Anywhere          # cAdvisor - localhost only
# 9115/tcp       DENY IN     Anywhere          # Blackbox Exporter - localhost only

# Verify rules persist after reboot
sudo ufw status numbered
```

---

#### Step 6.4.6: Test from Jump Box

```bash
# From jump box — verify firewall blocks what it should and allows what it must
GRAFANA="192.168.75.109"

echo "=== Firewall Validation from Jump Box ==="

echo "--- Should WORK (allowed through firewall) ---"
echo -n "  HTTPS (443): "
curl -sk -o /dev/null -w "%{http_code}" https://$GRAFANA && echo " (should be 200/302)"

echo -n "  HTTP redirect (80): "
curl -s -o /dev/null -w "%{http_code}" http://$GRAFANA && echo " (should be 301)"

echo ""
echo "--- Should FAIL (blocked by firewall + localhost binding) ---"
echo -n "  Grafana direct (3000): "
curl -s --connect-timeout 3 http://$GRAFANA:3000 >/dev/null 2>&1 && echo "FAIL (accessible!)" || echo "BLOCKED"

echo -n "  Prometheus (9090): "
curl -s --connect-timeout 3 http://$GRAFANA:9090 >/dev/null 2>&1 && echo "FAIL (accessible!)" || echo "BLOCKED"

echo -n "  Node Exporter (9100): "
curl -s --connect-timeout 3 http://$GRAFANA:9100 >/dev/null 2>&1 && echo "FAIL (accessible!)" || echo "BLOCKED"

echo -n "  cAdvisor (8080): "
curl -s --connect-timeout 3 http://$GRAFANA:8080 >/dev/null 2>&1 && echo "FAIL (accessible!)" || echo "BLOCKED"

echo -n "  Blackbox (9115): "
curl -s --connect-timeout 3 http://$GRAFANA:9115 >/dev/null 2>&1 && echo "FAIL (accessible!)" || echo "BLOCKED"
```

---

#### Alternative Firewall Implementations (Reference)

The steps above use `ufw` because it's the most common tool on Debian/Ubuntu. If your environment uses a different firewall, here are the equivalent rules.

**iptables (legacy, still common):**

```bash
# Allow SSH, HTTPS, HTTP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Deny monitoring ports from external access
iptables -A INPUT -p tcp --dport 3000 -j DROP
iptables -A INPUT -p tcp --dport 9090 -j DROP
iptables -A INPUT -p tcp --dport 9100 -j DROP
iptables -A INPUT -p tcp --dport 8080 -j DROP
iptables -A INPUT -p tcp --dport 9115 -j DROP

# Persist across reboots (Debian)
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

**nftables (modern replacement, Debian 13 default backend):**

```bash
nft add table inet monitoring_filter
nft add chain inet monitoring_filter input { type filter hook input priority 0 \; policy accept \; }

# Allow management and web
nft add rule inet monitoring_filter input tcp dport 22 accept
nft add rule inet monitoring_filter input tcp dport 443 accept
nft add rule inet monitoring_filter input tcp dport 80 accept

# Deny monitoring ports
nft add rule inet monitoring_filter input tcp dport 3000 drop
nft add rule inet monitoring_filter input tcp dport 9090 drop
nft add rule inet monitoring_filter input tcp dport 9100 drop
nft add rule inet monitoring_filter input tcp dport 8080 drop
nft add rule inet monitoring_filter input tcp dport 9115 drop

# Persist
nft list ruleset > /etc/nftables.conf
sudo systemctl enable nftables
```

**For multi-host deployments** where exporters run on separate VMs and must listen on routable interfaces, replace the deny-all rules with source-restricted allow rules:

```bash
# ufw — on a remote node-exporter VM, allow only Prometheus to scrape
ufw allow from 192.168.75.109 to any port 9100 proto tcp comment 'Prometheus scrape only'
ufw deny 9100/tcp comment 'Block all other access to node-exporter'

# iptables — same logic
iptables -A INPUT -p tcp --dport 9100 -s 192.168.75.109 -j ACCEPT
iptables -A INPUT -p tcp --dport 9100 -j DROP

# nftables — same logic
nft add rule inet monitoring_filter input tcp dport 9100 ip saddr 192.168.75.109 accept
nft add rule inet monitoring_filter input tcp dport 9100 drop
```

---

#### Defense-in-Depth Summary: Two Independent Controls Per Port

| Port | Service | Layer 1: Docker Binding | Layer 2: Host Firewall (ufw) |
|------|---------|------------------------|------------------------------|
| 443 | HAProxy HTTPS | `*:443` (public) | `ALLOW` (user access) |
| 80 | HAProxy HTTP | `*:80` (redirect) | `ALLOW` (redirect to HTTPS) |
| 3000 | Grafana | `127.0.0.1:3000` (localhost) | `DENY` (must use HAProxy) |
| 9090 | Prometheus | `127.0.0.1:9090` (localhost) | `DENY` (Docker network only) |
| 9100 | Node Exporter | `127.0.0.1:9100` (localhost) | `DENY` (Docker network only) |
| 8080 | cAdvisor | `127.0.0.1:8080` (localhost) | `DENY` (Docker network only) |
| 9115 | Blackbox | `127.0.0.1:9115` (localhost) | `DENY` (SSRF prevention) |
| 22 | SSH | OS-level | `ALLOW` (management) |

**Either layer failing independently does not expose the service.** Both Docker binding AND the firewall must be misconfigured simultaneously for an attacker to reach a monitoring port from the network. This is what defense-in-depth means in practice.

**Compliance mapping:** NIST AC-3 (Access Enforcement), NIST SC-7 (Boundary Protection), CIS 6.2 (Establish Access Based on Need), CIS 4.4 (Implement and Manage a Firewall on Servers). The host firewall satisfies CIS 4.4 directly — a control that localhost binding alone does not address.

---

### VERIFY — Phase 6 Vulnerabilities Closed

```bash
echo "=== Phase 6: VERIFY VULNS CLOSED ==="
echo ""

echo "--- VULN-14: Structured Audit Logging ---"
echo -n "  JSON log format: "
docker exec grafana cat /var/log/grafana/grafana.log 2>/dev/null | head -1 | grep -q '"level"' && echo "PASS" || echo "FAIL"

echo -n "  Log rotation: "
docker exec grafana env | grep -q "GF_LOG_FILE_LOG_ROTATE=true" && echo "PASS" || echo "FAIL"

echo -n "  30-day retention: "
docker exec grafana env | grep -q "GF_LOG_FILE_MAX_DAYS=30" && echo "PASS" || echo "FAIL"

echo ""
echo "--- Exporter Network Hardening (Layer 1: Docker Binding) ---"
echo -n "  Node Exporter localhost: "
sudo ss -tlnp | grep 9100 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"

echo -n "  cAdvisor localhost: "
sudo ss -tlnp | grep 8080 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"

echo -n "  Blackbox localhost: "
sudo ss -tlnp | grep 9115 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"

echo -n "  Prometheus localhost: "
sudo ss -tlnp | grep 9090 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"

echo ""
echo "--- Host Firewall (Layer 2: ufw) ---"
echo -n "  ufw active: "
sudo ufw status | grep -q "Status: active" && echo "PASS" || echo "FAIL"

echo -n "  Default deny incoming: "
sudo ufw status verbose | grep -q "Default: deny (incoming)" && echo "PASS" || echo "FAIL"

echo -n "  SSH allowed: "
sudo ufw status | grep "22/tcp" | grep -q "ALLOW" && echo "PASS" || echo "FAIL"

echo -n "  HTTPS allowed: "
sudo ufw status | grep "443/tcp" | grep -q "ALLOW" && echo "PASS" || echo "FAIL"

echo -n "  Port 3000 denied: "
sudo ufw status | grep "3000/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"

echo -n "  Port 9090 denied: "
sudo ufw status | grep "9090/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"

echo -n "  Port 9100 denied: "
sudo ufw status | grep "9100/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"

echo -n "  Port 8080 denied: "
sudo ufw status | grep "8080/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"

echo -n "  Port 9115 denied: "
sudo ufw status | grep "9115/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"

echo ""
echo "--- External Access Validation ---"
echo -n "  External Node Exporter blocked: "
curl -s --connect-timeout 3 http://192.168.75.109:9100/metrics >/dev/null 2>&1 && echo "FAIL" || echo "PASS"

echo -n "  External cAdvisor blocked: "
curl -s --connect-timeout 3 http://192.168.75.109:8080/metrics >/dev/null 2>&1 && echo "FAIL" || echo "PASS"

echo -n "  External Blackbox blocked: "
curl -s --connect-timeout 3 http://192.168.75.109:9115/metrics >/dev/null 2>&1 && echo "FAIL" || echo "PASS"

echo ""
echo "--- Operational ---"
echo -n "  Cert renewal cron: "
sudo crontab -l | grep -q "renew-grafana-cert" && echo "PASS" || echo "FAIL"

echo -n "  Snapshots disabled: "
docker exec grafana env | grep -q "GF_SNAPSHOTS_EXTERNAL_ENABLED=false" && echo "PASS" || echo "FAIL"

echo ""
echo "Score: 9.5 -> 9.8 (+0.3)"
```

---

## Final Comprehensive Validation — All 15 VULNs

This is the victory lap — and the most important script in the entire playbook. Run this after all six phases are complete. Every vulnerability we found in Part 1 gets checked here in a single pass. If everything shows PASS, you've taken this stack from a 6.0 to a 9.8.

But here's why this script really matters: it's not just for you. This is your audit evidence. If someone asks "how do you know your monitoring stack is secure?" you point them at this output. Every check maps to a specific vulnerability, which maps to specific compliance controls. That's the bridge between "I hardened my homelab" and "I can demonstrate compliance."

Run this after all phases are complete:

```bash
echo "=========================================="
echo "  BUILD IT, BREAK IT, FIX IT"
echo "  COMPLETE HARDENING VALIDATION"
echo "  Published by Oob Skulden™"
echo "=========================================="
echo ""

source ~/monitoring/.env

# VULN-01: Grafana Default Credentials
echo "--- VULN-01: Grafana Admin Credentials ---"
echo -n "  Default creds rejected: "
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -u admin:admin https://192.168.75.109/api/admin/settings -k)
[ "$HTTP" = "401" ] && echo "PASS" || echo "FAIL ($HTTP)"

# VULN-02: Prometheus
echo "--- VULN-02: Prometheus Access ---"
echo -n "  Auth required: "
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/metrics)
[ "$HTTP" = "401" ] && echo "PASS" || echo "FAIL ($HTTP)"
echo -n "  Localhost only: "
sudo ss -tlnp | grep 9090 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"

# VULN-03: Node Exporter
echo "--- VULN-03: Node Exporter ---"
echo -n "  Localhost only: "
sudo ss -tlnp | grep 9100 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"
echo -n "  External blocked: "
curl -s --connect-timeout 3 http://192.168.75.109:9100/metrics >/dev/null 2>&1 && echo "FAIL" || echo "PASS"

# VULN-04: Blackbox
echo "--- VULN-04: Blackbox Exporter ---"
echo -n "  Localhost only: "
sudo ss -tlnp | grep 9115 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"
echo -n "  SSRF blocked: "
curl -s --connect-timeout 3 "http://192.168.75.109:9115/probe?target=http://google.com&module=http_2xx" >/dev/null 2>&1 && echo "FAIL" || echo "PASS"

# VULN-05: Secrets Management
echo "--- VULN-05: OAuth Secret ---"
echo -n "  Not in container env: "
docker exec grafana env 2>/dev/null | grep -q "CLIENT_SECRET" && echo "FAIL" || echo "PASS"
echo -n "  Not in docker inspect: "
docker inspect grafana --format '{{json .Config.Env}}' | grep -q "CLIENT_SECRET" && echo "FAIL" || echo "PASS"
echo -n "  OpenBAO injection: "
docker logs grafana 2>&1 | grep -q "Secrets loaded successfully" && echo "PASS" || echo "FAIL"

# VULN-06: Session Timeouts
echo "--- VULN-06: Session Management ---"
echo -n "  Inactive timeout (1h): "
docker logs grafana 2>&1 | grep -q "INACTIVE_LIFETIME_DURATION=1h" && echo "PASS" || echo "FAIL"
echo -n "  Max lifetime (24h): "
docker logs grafana 2>&1 | grep -q "MAXIMUM_LIFETIME_DURATION=24h" && echo "PASS" || echo "FAIL"

# VULN-07: Rate Limiting
echo "--- VULN-07: Brute Force Protection ---"
echo -n "  HAProxy active: "
sudo systemctl is-active haproxy | grep -q "active" && echo "PASS" || echo "FAIL"

# VULN-08: OAuth over HTTP (inherent — mitigated by TLS on Grafana side)
echo "--- VULN-08: OAuth Transport ---"
echo -n "  TLS on Grafana: "
curl -sk -o /dev/null -w "%{http_code}" https://192.168.75.109 | grep -q "200\|302" && echo "PASS" || echo "FAIL"

# VULN-09: Container Hardening
echo "--- VULN-09: Container Security ---"
echo -n "  cap_drop ALL: "
docker inspect grafana --format='{{json .HostConfig.CapDrop}}' | grep -q "ALL" && echo "PASS" || echo "FAIL"
echo -n "  no-new-privileges: "
docker inspect grafana --format='{{json .HostConfig.SecurityOpt}}' | grep -q "no-new-privileges" && echo "PASS" || echo "FAIL"

# VULN-10: TLS
echo "--- VULN-10: Encryption ---"
echo -n "  HTTPS active: "
curl -skI https://192.168.75.109 | grep -q "200\|302" && echo "PASS" || echo "FAIL"
echo -n "  HTTP redirects: "
curl -sI http://192.168.75.109 | grep -q "301" && echo "PASS" || echo "FAIL"
echo -n "  HSTS: "
curl -skI https://192.168.75.109 | grep -qi "strict-transport-security" && echo "PASS" || echo "FAIL"

# VULN-11: Resource Limits
echo "--- VULN-11: Resource Limits ---"
echo -n "  Memory (2GB): "
MEM=$(docker inspect grafana --format='{{.HostConfig.Memory}}')
[ "$MEM" = "2147483648" ] && echo "PASS" || echo "FAIL ($MEM)"
echo -n "  CPU (2 cores): "
CPU=$(docker inspect grafana --format='{{.HostConfig.NanoCpus}}')
[ "$CPU" = "2000000000" ] && echo "PASS" || echo "FAIL ($CPU)"

# VULN-12: Network Segmentation
echo "--- VULN-12: Network Hardening ---"
echo -n "  cAdvisor localhost: "
sudo ss -tlnp | grep 8080 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"
echo -n "  Node Exporter localhost: "
sudo ss -tlnp | grep 9100 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"
echo -n "  Blackbox localhost: "
sudo ss -tlnp | grep 9115 | grep -q "127.0.0.1" && echo "PASS" || echo "FAIL"
echo -n "  Host firewall active: "
sudo ufw status | grep -q "Status: active" && echo "PASS" || echo "FAIL"
echo -n "  Firewall default deny: "
sudo ufw status verbose | grep -q "Default: deny (incoming)" && echo "PASS" || echo "FAIL"
echo -n "  Port 9090 firewall deny: "
sudo ufw status | grep "9090/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"
echo -n "  Port 9100 firewall deny: "
sudo ufw status | grep "9100/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"
echo -n "  Port 8080 firewall deny: "
sudo ufw status | grep "8080/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"
echo -n "  Port 9115 firewall deny: "
sudo ufw status | grep "9115/tcp" | grep -q "DENY" && echo "PASS" || echo "FAIL"

# VULN-13: Auto Sign-Up
echo "--- VULN-13: OAuth Auto Sign-Up ---"
echo "  (Controlled via Authentik group membership — acceptable risk with RBAC)"

# VULN-14: Audit Logging
echo "--- VULN-14: Audit Logging ---"
echo -n "  JSON format: "
docker exec grafana cat /var/log/grafana/grafana.log 2>/dev/null | head -1 | grep -q '"level"' && echo "PASS" || echo "FAIL"
echo -n "  30-day retention: "
docker exec grafana env | grep -q "GF_LOG_FILE_MAX_DAYS=30" && echo "PASS" || echo "FAIL"

# VULN-15: Backup/DR
echo "--- VULN-15: Backup/DR ---"
echo "  (Requires manual backup procedures — not automated in this playbook)"

echo ""
echo "=========================================="
echo "  Grafana Health: $(curl -s http://localhost:3000/api/health | grep -o '"database":"[^"]*"')"
echo "  Final Score: 9.8/10"
echo "=========================================="
```

---

## Security Score Progression

| Phase | Score | Improvement | VULNs Addressed |
|-------|-------|-------------|-----------------|
| Baseline | 6.0/10 | – | – |
| Phase 1 | 7.5/10 | +1.5 | VULN-05, VULN-06 |
| Phase 2 | 8.0/10 | +0.5 | VULN-07, VULN-10 |
| Phase 3 | 8.5/10 | +0.5 | VULN-02, VULN-03 (partial), VULN-04 (partial) |
| Phase 4 | 9.0/10 | +0.5 | VULN-05 (deep validation) |
| Phase 5 | 9.5/10 | +0.5 | VULN-09, VULN-11 |
| Phase 6 | 9.8/10 | +0.3 | VULN-12, VULN-14 |

---

## Compliance Mapping Summary

This is where the rubber meets the road for anyone who needs to justify this work to leadership or map it to a compliance framework. Every fix we implemented traces back to at least one control in NIST 800-53, SOC 2, CIS Controls, CIS Docker Benchmark, PCI-DSS, or OWASP. This isn't compliance theater — these are real controls that address real risks we actually demonstrated in Part 1.

| Framework | Control | Vulnerability | Phase |
|-----------|---------|---------------|-------|
| NIST AC-2(3) | Disable System Access | VULN-06 Session Persistence | Phase 1 |
| NIST AC-3 | Access Enforcement | VULN-02 Prometheus, VULN-03 cAdvisor, VULN-04 Blackbox | Phase 3, 6.3 |
| NIST AC-12 | Session Termination | VULN-06 No Timeouts | Phase 1 |
| NIST AU-2 | Audit Event Logging | VULN-14 Ephemeral Logs | Phase 6.2 |
| NIST AU-4 | Audit Storage Capacity | VULN-14 No Retention | Phase 6.2 |
| NIST CM-7 | Least Functionality | VULN-09 Full Capabilities | Phase 5 |
| NIST IA-5 | Authenticator Management | VULN-05 Plaintext Secrets | Phase 1, 4 |
| NIST SC-5 | Denial of Service | VULN-07 No Rate Limits | Phase 2 |
| NIST SC-8 | Transmission Confidentiality | VULN-10 No TLS | Phase 2 |
| NIST SC-28 | Protection at Rest | VULN-05 Secrets in Compose | Phase 1, 4 |
| SOC 2 CC6.1 | Logical Access | VULN-02 Prometheus, VULN-05 Secrets, VULN-06 Session | Phase 1, 3, 4 |
| SOC 2 CC6.2 | Prior to Issuing Creds | VULN-02 No Prom Auth | Phase 3 |
| SOC 2 CC6.7 | Transmission Protection | VULN-10 HTTP Cleartext | Phase 2 |
| SOC 2 CC7.2 | Security Event Detection | VULN-14 No Audit Logs | Phase 6.2 |
| CIS 5.3 | Disable Dormant Accounts | VULN-06 Session Persist | Phase 1 |
| CIS 6.2 | Establish Access Based on Need | VULN-02 Prometheus, VULN-03 cAdvisor, VULN-05 AppRole | Phase 1, 3, 4, 6.3 |
| CIS 8.2 | Collect Audit Logs | VULN-14 Console Only | Phase 6.2 |
| CIS Docker 5.3 | Restrict Capabilities | VULN-09 Full Caps | Phase 5 |
| CIS Docker 5.4 | Use Trusted Base Images | VULN-09 Container Defaults | Phase 5 |
| CIS Docker 5.10 | Memory Limits | VULN-11 Unlimited | Phase 5 |
| CIS Docker 5.11 | CPU Limits | VULN-11 Unlimited | Phase 5 |
| CIS Docker 5.25 | Restrict Container Privileges | VULN-09 no-new-privileges | Phase 5 |
| PCI-DSS 4.1 | Encrypt Transmissions | VULN-10 HTTP | Phase 2 |
| PCI-DSS 8.2.8 | Session Timeout | VULN-06 No Timeout | Phase 1 |
| OWASP ASVS 2.2.1 | Anti-Automation Controls | VULN-07 No Rate Limiting | Phase 2 |
| OWASP SSRF | Server-Side Request Forgery | VULN-04 Blackbox Proxy | Phase 6.3 |
| NIST SC-7 | Boundary Protection | Host Firewall Rules | Phase 6.4 |
| CIS 4.4 | Implement and Manage a Firewall on Servers | Host Firewall (ufw) | Phase 6.4 |

---

## Known Gotchas Quick Reference

Every single one of these cost real debugging time. If you're following this playbook and something breaks, check this table first before you start Googling. The `exec env` pattern alone probably cost me an hour of "why is OAuth failing silently?" The DAC_OVERRIDE issue is the one that trips up every container hardening tutorial that says "just drop all capabilities." And the Prometheus datasource duplicate — that one will make you think HAProxy is broken when it's actually a Grafana UI problem.

| Issue | Symptom | Fix |
|-------|---------|-----|
| `export` doesn't persist through `exec` | OAuth login fails silently | Use `exec env VAR=value /run.sh` |
| `read_only: true` + Grafana | "attempt to write a readonly database" | Don't use `read_only` with Grafana |
| Missing `DAC_OVERRIDE` | SQLite crash loop | Add to `cap_add` |
| `docker compose restart` | Config changes not applied | Use `--force-recreate` or `down` / `up` |
| `sed` for YAML edits | UTF-8 corruption, duplicate entries | Use `nano +linenum` |
| Duplicate Prometheus datasources | Browser WWW-Authenticate popup | Delete manual datasource before provisioning |
| HSTS browser cache | Browser forces HTTPS after reverting | Clear HSTS or use incognito |
| KV v2 API paths | 403 on secret retrieval | Use `/v1/secret/data/grafana/oauth` not `/v1/secret/grafana/oauth` |
| PEM bundle order | HAProxy TLS failure | cert + key + CA (in that order) |
| Cert file permissions | HAProxy won't start | `chown haproxy:haproxy`, `chmod 600` |
| `curl` returns 000 | Looks like service down | Add `-k` flag for self-signed certs |
| ufw enabled without SSH rule | Locked out of server | Always `ufw allow ssh` BEFORE `ufw enable` |
| ufw + Docker port binding conflict | Docker bypasses ufw on published ports | Localhost binding (Phase 6.3) + ufw deny = two layers needed |
| Firewall rules not persisting | Rules lost after reboot | ufw persists automatically; iptables needs `netfilter-persistent save` |

---

## Placeholders — Fill Before Recording

All credentials should be decided in the Password & Credential Convention section at the top of this document before starting.

| Variable | Set When | Used In | Description |
|----------|----------|---------|-------------|
| `$ADMIN_PASSWORD` | Before starting | All PROVE IT, .env, VERIFY | Grafana admin password |
| `$PROM_PASSWORD` | Before starting | Phase 3, .env | Prometheus basic auth password |
| `$OAUTH_CLIENT_SECRET` | Before starting (from Authentik) | Step 1.1 | OAuth client_secret |
| `$GRAFANA_ROLE_ID` | Generated in Step 1.2 | Step 1.3 .env, Phase 4 | Grafana AppRole role_id |
| `$GRAFANA_SECRET_ID` | Generated in Step 1.2 | Step 1.3 .env, Phase 4 | Grafana AppRole secret_id |
| `$PKI_ROLE_ID` | Generated in Phase 6.1 | Renewal script | PKI AppRole role_id |
| `$PKI_SECRET_ID` | Generated in Phase 6.1 | Renewal script | PKI AppRole secret_id |

---

*Published by Oob Skulden™ — Every command traces to official vendor documentation. No obscure exploits — just reading the docs and using the APIs as designed, without authorization. Stay paranoid.*
