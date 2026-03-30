---
title: "Hardening Authentik: Every Misconfiguration I Found in My Own IdP"
date: 2026-03-02T08:00:00-06:00
lastmod: 2026-03-02T08:00:00-06:00
draft: false
author:
  - "Oob Skulden"
description: "How to harden Authentik 2025.12.3 -- localhost bind, HAProxy path blocking and rate limiting, OpenBAO AppRole secrets injection, akadmin deactivation, and Docker worker capability hardening. Every command, every dead end, every lesson."
tags:
  - "Authentik"
  - "Docker"
  - "HAProxy"
  - "OpenBAO"
  - "Hardening"
  - "Secrets Management"
  - "Homelab"
categories:
  - Security Hardening
series:
  - "Authentik Identity Provider"
keywords:
  - "authentik hardening guide"
  - "authentik 2025.12.3 security"
  - "authentik openbao secrets injection"
  - "haproxy block expression policy rce"
  - "docker cap_drop all hardening"
  - "disable akadmin authentik"
  - "authentik file uri secrets"
  - "docker worker capabilities drop"
  - "authentik reverse proxy haproxy"
  - "authentik .env file permissions"
  - "authentik docker compose security"
  - "authentik localhost bind 127.0.0.1"
cover:
  image: ""
  alt: "HAProxy returning 403 on the Authentik expression policy RCE path -- F-03 closed at the network layer"
  caption: "The F-03 RCE path blocked at the proxy before it reaches Authentik."
canonicalURL: "https://oobskulden.com/2026/03/hardening-authentik-every-misconfiguration-i-found-in-my-own-idp/"
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: true
tools_used:
  - "Authentik"
  - "Docker"
  - "HAProxy"
attack_surface:
  - "Identity provider hardening"
  - "SSO misconfiguration"
cve_references: []
lab_environment: "Authentik 2024.x, Docker CE 29.3.0"
showToc: true
TocOpen: false
---

<!--
SEO Target Queries:
- authentik hardening guide
- authentik 2025.12.3 security hardening
- how to harden authentik docker compose
- authentik openbao secrets injection
- haproxy block authentik expression policy rce
- docker cap_drop all worker container
- disable akadmin authentik
- authentik file:// uri secrets injection
- authentik reverse proxy haproxy security headers
- authentik .env file permissions chmod 600

AEO -- Featured Snippet Targets:

Q: Does Authentik support secrets injection from a vault?
A: Yes. Authentik natively resolves file:// URIs in configuration values. Set AUTHENTIK_SECRET_KEY to file:///run/secrets/secret_key and write the secret to that path at container startup via an entrypoint script that authenticates to a vault (OpenBAO, HashiCorp Vault). No plaintext credentials required in the environment or on disk.

Q: What is the minimum HAProxy configuration to block Authentik RCE via the expression policy API?
A: Block three paths with HTTP 403: /api/v3/policies/expression/ (creation), /api/v3/policies/all/{uuid}/test/ (execution), and /api/v3/managed/blueprints/ (persistence). This closes the primary RCE chain at the proxy layer regardless of token permissions.

Q: Is it safe to disable akadmin in Authentik?
A: Yes. Deactivate (do not delete) akadmin via ak shell by setting is_active = False. Authentik uses akadmin's primary key in some internal relationships, so deletion can cause integrity issues. Deactivation eliminates it as an attack target while preserving referential integrity.

Q: What capabilities does the Authentik worker container actually need?
A: Starting from cap_drop: ALL, the minimum required capabilities for Authentik 2025.12.3 are FOWNER (for /data volume permission changes at startup) and KILL (for the health check signal). CHOWN, DAC_OVERRIDE, SETGID, and SETUID may be required depending on volume ownership configuration.

Q: Why does docker exec ak shell fail after entrypoint secrets injection via exec env?
A: docker exec spawns a new process with the container's base environment and does not inherit the process tree built by the entrypoint. Secrets injected via exec env are invisible to ak shell. The fix is file:// URI -- the secret is resolved at the application configuration level, not the environment level, so it works regardless of process spawn method.

Schema: TechArticle
-->

> **Disclaimer:** All testing was performed against infrastructure owned and operated by the author in a private lab environment. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent laws in other jurisdictions. This content is provided for educational and defensive security research purposes only. Do not test against systems you do not own or have explicit written authorization to test.
>
> This content represents personal educational work conducted in a home lab environment on personal equipment. It does not reflect the views, opinions, or positions of any employer or affiliated organization. All security methodologies are derived from publicly available frameworks, published CVE advisories, and open-source tool documentation. All tools referenced are free, open-source, and publicly available.
{{< ai-walkthrough >}}



## This Is Part 2

In Part 1 -- [I Broke My Own Identity Provider](https://oobskulden.com/2026/02/i-broke-my-own-identity-provider/) -- I ran a complete live audit of Authentik 2025.12.3 from a jump box on a separate VLAN using only pre-installed Linux tools. The result: 10 of 15 findings confirmed exploitable, including full RCE from a non-superuser account, complete database compromise, and a two-command path to god-mode administrative access. The entire attack chain took under 15 minutes.

Part 1 ended with a list of fixes. This article is those fixes -- every command, every gotcha, every dead end, and every verification step. The same four-phase methodology applies: Prove It, Break It, Harden It, Verify It. This article covers the Harden It and Verify It phases in full.

{{< youtube rxBVwtKpdfA >}}


If you have not read Part 1, the finding references below link back to specific sections. You do not need Part 1 to follow this article, but the context makes the hardening decisions clearer.

**What this article covers:**
Chapter 1: Localhost bind (F-02) | Chapter 2: HAProxy headers, path blocking, rate limiting (F-01, F-03, F-04, F-06) | Chapter 3: .env permissions (F-07) | Chapter 4: OpenBAO AppRole secret injection (F-07) | Chapter 5: akadmin deactivation (F-12) | Chapter 6: Docker group removal and worker container hardening (F-10, F-12)


## What Was Fixed -- Quick Reference

**Target:** Authentik 2025.12.3 on Debian 13, Docker Compose
**Findings closed:** F-01, F-02, F-03, F-04, F-06, F-07, F-10, F-12
**Findings left open (residual risk):** Docker socket (F-10 partial)
**Prerequisites:** HAProxy reverse proxy, OpenBAO instance, Docker Compose access

| What | How | Closes |
|---|---|---|
| Bind to localhost only | `127.0.0.1` in compose ports | F-02 |
| Block RCE API paths | HAProxy `deny` ACLs | F-01, F-03, F-04 |
| Add missing security headers | HAProxy `set-header` | F-06 |
| Rate limit login endpoint | HAProxy stick-table, 20 req/60s | F-09 |
| Lock .env file | `chmod 600` / `chown root:root` | F-07 |
| Remove plaintext secrets | OpenBAO AppRole + `file://` URI | F-07 |
| Disable akadmin | `is_active = False` via `ak shell` | F-12 |
| Remove docker group membership | `gpasswd -d` | F-12 host path |
| Drop worker capabilities | `cap_drop: ALL` + selective add-back | F-10 |

## Chapter 1 -- Localhost Bind

### The Problem (F-02)

The default `docker-compose.yml` binds Authentik's HTTP and HTTPS ports to `0.0.0.0`. In the audit, port 9000 was reachable from the jump box on VLAN 50 -- a completely separate network segment from the Authentik host on VLAN 80. An attacker with access to any routable segment bypasses HAProxy entirely and speaks directly to the application backend.

The fix is one line per port: restrict the bind address to `127.0.0.1` so all external traffic must pass through the reverse proxy.

### The Fix -- Authentik 2025.12.3

```yaml
# docker-compose.yml -- server service ports block

# Before
  - "0.0.0.0:${COMPOSE_PORT_HTTP:-9000}:9000"
  - "0.0.0.0:${COMPOSE_PORT_HTTPS:-9443}:9443"

# After
  - "127.0.0.1:${COMPOSE_PORT_HTTP:-9000}:9000"
  - "127.0.0.1:${COMPOSE_PORT_HTTPS:-9443}:9443"
```

```bash
sudo docker compose up -d --force-recreate server
```

### Verify It -- Authentik 2025.12.3

```bash
# From jump box -- 192.168.50.10
curl -sk --max-time 3 http://192.168.80.54:9000 && echo "OPEN" || echo "CLOSED"
# Expected: CLOSED
```

**CLOSED** -- Port 9000 is no longer reachable cross-VLAN. HAProxy is now the only entry point.

## Chapter 2 -- HAProxy: Headers, Path Blocking and Rate Limiting

### The Problem (F-01, F-03, F-04, F-06, F-09)

With the application bound to localhost, HAProxy becomes the sole entry point. Four gaps remained in the existing proxy config:

Missing security headers: CSP, HSTS, Permissions-Policy (F-06). No X-Forwarded-For overwrite, so clients could spoof their source IP (F-08). Dangerous API paths reachable with a valid token: expression policy RCE (F-03), blueprint injection (F-04), unauthenticated metrics (F-01). No rate limiting on authentication endpoints.

`X-Frame-Options` and `X-Content-Type-Options` were already present in 2025.12.3 -- a version improvement noted in Part 1. The gaps were the three missing headers and path-level controls.

### Security Headers

```text
# haproxy.cfg -- frontend block
http-response set-header Content-Security-Policy \
  "default-src 'self'; script-src 'self' 'unsafe-inline'; \
   style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
   font-src 'self'; connect-src 'self'; frame-ancestors 'none'"

http-response set-header Strict-Transport-Security \
  "max-age=63072000; includeSubDomains; preload"

http-response set-header Permissions-Policy \
  "geolocation=(), microphone=(), camera=()"
```

> **Note on `unsafe-inline`:** Authentik inlines styles and scripts in its frontend -- removing `unsafe-inline` breaks the UI. This is an Authentik application constraint, not an oversight. A nonce-based strict CSP would require upstream changes to Authentik's templating.

### X-Forwarded-For Overwrite

The audit confirmed all spoofed XFF headers were accepted (F-08). These two lines discard any client-supplied value and replace it with the actual source IP as seen by HAProxy.

```text
http-request del-header X-Forwarded-For
http-request set-header X-Forwarded-For %[src]
```

### Path Blocking -- Closing the F-03 RCE Chain

The three paths below are the core of the attack chains from Part 1. Blocking them at the proxy layer means the application backend never sees the request -- no authentication bypass, no token required.

```text
# Block expression policy RCE (F-03)
acl block_expr  path_beg /api/v3/policies/expression/
# Block blueprint injection (F-04)
acl block_bp    path_beg /api/v3/managed/blueprints/
# Block policy test execution (F-03 execution path)
acl block_test  path_reg ^/api/v3/policies/all/[^/]+/test/
# Block unauthenticated metrics (F-01)
acl block_metr  path_beg /-/metrics/

http-request deny deny_status 403 if block_expr or block_bp or block_test or block_metr
```

> **Enterprise Decision -- Selective Blocking vs Full API Lockdown**
> Blocking these paths at the proxy preserves Authentik's admin UI, which uses different API paths. Full API lockdown breaks the interface. Selective path blocking is the minimum effective control that closes the RCE chain without operational impact. Internal access via localhost bypasses HAProxy entirely, so admin operations from the host still work.

### Rate Limiting -- Login Endpoint

The F-09 audit confirmed all weak passwords were accepted with no throttling. HAProxy handles rate limiting at the connection level before the request reaches Authentik.

```text
# haproxy.cfg -- global and frontend sections

# Track source IPs in a stick table: 100k entries, expire after 60s
stick-table type ip size 100k expire 60s store http_req_rate(60s)

# frontend block -- add these lines
http-request track-sc0 src
http-request deny deny_status 429 if { sc_http_req_rate(0) gt 20 }
```

This allows 20 requests per source IP per 60-second window. Legitimate login attempts stay well under this threshold. Automated brute force does not.

> **Tuning note:** `20 req/60s` is conservative for a homelab with known users. Adjust the threshold to match your actual usage pattern -- too low and you lock out legitimate users, too high and brute force gets through. For production, combine with Authentik's native `Reputation` policy for per-user throttling at the application layer.

### Reload HAProxy

```bash
sudo systemctl reload haproxy
```

### Verify It

```bash
# All four paths must return 403
curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.80.54/api/v3/policies/expression/
curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.80.54/api/v3/managed/blueprints/
curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.80.54/api/v3/policies/all/test/test/
curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.80.54/-/metrics/

# Rate limiting -- 21 rapid requests should trigger 429 on the last ones
for i in $(seq 1 22); do
  curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.80.54/api/v3/core/users/me/
done | sort | uniq -c
# Expected: mix of 200/401 then 429 as threshold is crossed
```

**403 403 403 403** -- All four paths blocked at the proxy layer. Rate limiting active: requests beyond 20/60s return 429.

## Chapter 3 -- Securing the Authentik .env File

### The Problem (F-07)

The `.env` file was `664 oob:docker` -- world-readable. It contained `SECRET_KEY` and `PG_PASS` in plaintext. Any user on the system, any backup agent, any log shipper with filesystem access could read both credentials without privileges. This was the foundation of two full attack chains in Part 1.

### The Fix

```bash
sudo chown root:root ~/authentik/.env
sudo chmod 600 ~/authentik/.env
```

> **Gotcha: 600 root:root Breaks docker compose**
> After `chmod 600` / `chown root:root`, `docker compose` commands run as the `oob` user fail silently -- the process cannot read the `.env` file. All subsequent compose operations must use `sudo`. This is the correct tradeoff. The file contains credentials; no unprivileged process should read it.

### Verify It

```bash
cat ~/authentik/.env && echo "READABLE" || echo "DENIED"
# Expected: DENIED
```

**DENIED** -- `.env` is unreadable to the `oob` user. Credentials are no longer exposed to unprivileged processes.

## Chapter 4 -- OpenBAO AppRole Secret Injection

### The Problem (F-07 -- Full Remediation)

Chapter 3 restricted who could read the `.env` file. Chapter 4 removes the plaintext credentials from it entirely. Even root-restricted files can be read by privileged processes, backup agents, or misconfigured tools. The goal is zero secrets on disk.

### The Architecture

The design uses OpenBAO's AppRole authentication method. AppRole credentials (`role_id`, `secret_id`) are stored in `.env` -- these are authentication tokens, not the secrets themselves. The actual secrets (`SECRET_KEY`, `PG_PASS`) are stored in OpenBAO KV v2 at `secret/authentik/config`.

A custom `entrypoint.sh` fetches secrets at container startup, writes them to a `tmpfs` mount at `/run/secrets`, and Authentik reads them via `file://` URI -- confirmed native support in Authentik's source (`/authentik/lib/tests/test_config.py`). Secrets exist only in memory. They are never written to disk. Container restart fetches fresh secrets from OpenBAO.

### OpenBAO Setup

```bash
# Inside the OpenBAO container (BAO_ADDR=http://127.0.0.1:8200)

# Store secrets
bao kv put secret/authentik/config \
  secret_key="[REDACTED]" \
  pg_pass="[REDACTED]"

# Create scoped read-only policy
bao policy write authentik-read - << 'EOF'
path "secret/data/authentik/*" {
  capabilities = ["read"]
}
EOF

# Enable AppRole and create role
bao auth enable approle
bao write auth/approle/role/authentik-role \
  token_policies=authentik-read \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_num_uses=0
```

`secret_id_num_uses=0` means unlimited uses -- correct for a long-running service that restarts repeatedly. For higher-security environments, set this to a small positive integer and rotate the `secret_id` on a schedule.

```bash
# Retrieve credentials for .env
bao read auth/approle/role/authentik-role/role-id
bao write -f auth/approle/role/authentik-role/secret-id
```

### The Entrypoint Script

> **Dead End: Pasting Into nano Kills Your SSH Session**
> The first three attempts to create `entrypoint.sh` used nano. Each time, the script was pasted into an open nano buffer -- but the shell tried to execute the pasted text as terminal commands instead. The line `mkdir -p /run/secrets` failed with `Permission denied`, which triggered `set -e`, which closed the SSH connection. The fix: never use a text editor for heredocs. Use `cat > entrypoint.sh << 'EOF'` pasted directly at the `$` prompt. The single quotes around `'EOF'` prevent variable expansion during the paste.

This script runs as the container's entrypoint. It authenticates to OpenBAO, fetches the secrets, writes them to tmpfs, then hands off to the normal Authentik startup.

```sh
#!/bin/sh
set -e

BAO_ADDR="https://192.168.100.182"
BAO_ROLE_ID="${BAO_ROLE_ID}"
BAO_SECRET_ID="${BAO_SECRET_ID}"

# Authenticate to OpenBAO via AppRole
LOGIN_RESPONSE=$(curl -sk --request POST \
  --data "{\"role_id\":\"${BAO_ROLE_ID}\",\"secret_id\":\"${BAO_SECRET_ID}\"}" \
  ${BAO_ADDR}/v1/auth/approle/login)

TOKEN=$(echo "$LOGIN_RESPONSE" | sed 's/.*"client_token":"//; s/".*//')

# Fail loud if login failed
if [ -z "$TOKEN" ] || echo "$TOKEN" | grep -q "errors"; then
  echo "ENTRYPOINT ERROR: OpenBAO login failed: ${LOGIN_RESPONSE}" >&2
  exit 1
fi

# Fetch secrets
SECRETS_RESPONSE=$(curl -sk --header "X-Vault-Token: ${TOKEN}" \
  ${BAO_ADDR}/v1/secret/data/authentik/config)

SECRET_KEY=$(echo "$SECRETS_RESPONSE" | sed 's/.*"secret_key":"//; s/".*//')
PG_PASS=$(echo "$SECRETS_RESPONSE" | sed 's/.*"pg_pass":"//; s/".*//')

# Fail loud if secrets are empty
if [ -z "$SECRET_KEY" ] || [ -z "$PG_PASS" ]; then
  echo "ENTRYPOINT ERROR: Failed to retrieve secrets from OpenBAO" >&2
  exit 1
fi

# Write to tmpfs -- memory only, never disk
mkdir -p /run/secrets
echo -n "${SECRET_KEY}" > /run/secrets/secret_key
echo -n "${PG_PASS}" > /run/secrets/pg_pass
chmod 644 /run/secrets/secret_key /run/secrets/pg_pass

echo "ENTRYPOINT: secrets written to /run/secrets" >&2

exec dumb-init -- ak "$@"
```

### docker-compose.yml Changes -- Server and Worker

Apply to both the `server` and `worker` services.

```yaml
entrypoint: ["/entrypoint.sh"]
environment:
  AUTHENTIK_SECRET_KEY: file:///run/secrets/secret_key
  AUTHENTIK_POSTGRESQL__PASSWORD: file:///run/secrets/pg_pass
tmpfs:
  - /run/secrets:mode=0777
volumes:
  - ./entrypoint.sh:/entrypoint.sh:ro
```

### Lessons Learned -- This Chapter Had the Most Gotchas

> **Gotcha 1: Compose `:?` Validation Fires Before the Entrypoint**
> Docker Compose `:?` validation (e.g. `${AUTHENTIK_SECRET_KEY:?}`) fires during `compose up`, before any container starts. The entrypoint never runs. Remove `:?` validation entirely. If OpenBAO is unreachable, the entrypoint exits with code 1 -- that is the failure signal, not a compose validation error.

> **Dead End: `tmpfs` mode=0700 -- Container Restart Loop**
> The first attempt used `/run/secrets:mode=0700`. The container entered a restart loop immediately: `cannot create /run/secrets/secret_key: Permission denied`. Mode `0700` restricts directory traversal to the owner only. The entrypoint runs as root and can write files -- but the `authentik` user process that starts afterward cannot traverse the directory to read them. The fix is `mode=0777`. The tmpfs is ephemeral and container-scoped -- the directory permissions are not a security boundary. The file permissions (`644`) are.

> **Gotcha 2: `exec env` Does Not Survive `docker exec ak shell`**
> Using `exec env AUTHENTIK_SECRET_KEY=... dumb-init` injects secrets into the process tree from the entrypoint. But `docker exec ak shell` spawns a new process with the base environment (9 vars) -- it sees no `SECRET_KEY` and refuses to start. `file://` URI resolves this: all processes read from tmpfs files regardless of how they were spawned, including `ak shell`.

> **Dead End: `ENV_SECRET=31` Looks Wrong, Is Correct**
> During verification, checking whether secrets were in the environment returned `ENV_SECRET=31`. That looks like a populated secret -- but 31 is the length of the literal string `file:///run/secrets/secret_key`. Authentik holds the URI string in the env var and resolves it internally via `parse_uri`. The check was wrong, not the config. The real verification is `SK_LEN: 81` from `ak shell` (see Verify It below) -- that confirms Django resolved the URI to the actual secret.

> **Gotcha 3: `chmod 600` on tmpfs Files Breaks the `authentik` User**
> The entrypoint runs as root and writes files. `chmod 600` makes them unreadable by the `authentik` user that Authentik actually runs as. The correct mode is `644`. The tmpfs is ephemeral and container-scoped -- world-readable within the container is acceptable when the mount itself is memory-only.

> **Gotcha 4: Worker Needs Its Own Entrypoint Instance**
> The worker was not configured with the entrypoint script. It was still reading `SECRET_KEY` from the (now empty) environment variable and failing with `Secret key missing`. Apply the exact same entrypoint pattern to the worker service.

### OpenBAO Availability and Reboot Risk

The entrypoint creates a hard dependency on OpenBAO. If OpenBAO is unavailable at container startup -- including during system reboots while OpenBAO is still unsealing -- the entrypoint exits with code 1, Docker retries via `restart: unless-stopped`, and Authentik stays down until OpenBAO is healthy. This is the correct behavior.

> **Shamir Unseal on Reboot**
> This lab uses OpenBAO with Shamir unseal (3-of-5 threshold). After any reboot, OpenBAO starts sealed and requires manual intervention from 3 keyholders. Authentik will be unavailable until OpenBAO is manually unsealed. For production environments, auto-unseal via AWS KMS, Azure Key Vault, or an HSM eliminates this operational gap.

### Verify It -- Authentik 2025.12.3 + OpenBAO Secrets Injection

```bash
# Entrypoint ran
sudo docker logs authentik-server-1 2>&1 | grep ENTRYPOINT
# Expected: ENTRYPOINT: secrets written to /run/secrets

# Secrets exist in tmpfs with correct permissions
sudo docker exec authentik-server-1 ls -la /run/secrets/
# Expected: -rw-r--r-- authentik authentik  secret_key pg_pass

# Worker tmpfs -- files owned root:root (entrypoint runs as root in the worker)
sudo docker exec authentik-worker-1 ls -la /run/secrets/
# Expected: -rw-r--r-- root root  secret_key pg_pass
```

root:root is correct in the worker -- the worker entrypoint has no `user:` directive. The Authentik process reads the files via the `file://` URI regardless of owner because mode 644 makes them world-readable within the container-scoped tmpfs.

```bash
# Django resolved file:// URI to actual secret
sudo docker exec authentik-server-1 ak shell -c \
  "from django.conf import settings; print('SK_LEN:', len(settings.SECRET_KEY))"
# Expected: SK_LEN: 81
```

**SK_LEN: 81** -- Django resolved the `file://` URI to the actual secret value from tmpfs. `ak shell` works correctly. No plaintext credentials on disk.

## Chapter 5 -- Disabling akadmin in Authentik

### The Problem (F-12)

The default Authentik admin account (`akadmin`) was active and flagged as superuser. The F-12 finding demonstrated that a recovery key for this account could be generated with no password, no MFA, and no authentication -- just `docker exec` on the server container. The URL provided a full superuser session, usable cross-VLAN, in under 10 seconds.

Deactivating `akadmin` eliminates this account as an attack target without deleting it, which could break internal Authentik references.

### The Fix

```bash
sudo docker exec authentik-server-1 ak shell -c "
from authentik.core.models import User
u = User.objects.get(username='akadmin')
u.is_active = False
u.save()
print('active:', u.is_active)
"
# Expected: active: False
```

### Verify It

Re-run the F-12 attack from Part 1. The recovery endpoint should return no usable link.

```bash
curl -sk -X POST https://192.168.80.54/api/v3/core/users/6/recovery/ \
  -H "Content-Type: application/json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('link','no link'))"
# Expected: no link
```

**no link** -- The F-12 recovery key bypass is closed. `akadmin` cannot be used as an attack vector.

## Chapter 6 -- Docker Group Membership and Worker Container Hardening

### The Problem: Docker Group (F-12 Host Path)

The `oob` user was a member of the `docker` group. Docker group membership is functionally equivalent to unrestricted root on the host -- any member can mount the host filesystem into a container, read `/etc/shadow`, or spawn a privileged shell. This was the access path that made the F-12 two-command attack possible.

```bash
sudo gpasswd -d oob docker

# Verify
groups oob
# Expected: docker absent

# Note: takes effect on next login.
# Current session retains the token until logout.
# sudo docker compose still works via sudo.
```

### The Problem: Worker Container (F-10)

The worker container had three compounding issues from the F-10 finding: `user: root` running as root inside the container, `/var/run/docker.sock` mounted giving full Docker API access from inside the container, and no capability restrictions meaning the full Linux capability set inherited from the host.

> **Dead End: The Worker Was 2 Weeks Stale**
> When `docker compose ps` was run during the audit, the worker showed `Created: 2 weeks ago`. It had never been recreated during any of the earlier hardening steps. All the earlier `--force-recreate server` commands left the worker untouched. The worker was still running the original pre-hardening configuration -- no entrypoint, no cap_drop, credentials from the plaintext env var. The lesson: always check the `Created` timestamp in `docker compose ps`. If it predates your changes, the container is not running your new config.

> **Architecture Decision: Docker Socket Retained**
> `docker exec authentik-worker-1 ak shell` confirmed 2 active outposts. Removing the Docker socket breaks outpost lifecycle management -- Authentik can no longer start, stop, or update outpost containers automatically. The socket is retained. The compensating controls are `cap_drop ALL` and `no-new-privileges`. The socket remains a residual risk documented below.

### Worker Hardening Configuration

```yaml
# docker-compose.yml -- worker service
worker:
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  cap_add:
    - CHOWN
    - DAC_OVERRIDE
    - SETGID
    - SETUID
    - FOWNER
    - KILL
```

### Why Those Six Capabilities

`cap_drop ALL` was the starting point. Each capability added back required a confirmed failure.

> **Dead End: Duplicate `entrypoint:` Line from Multiline `sed`**
> Inserting the entrypoint and tmpfs into the worker block via a multiline `sed` command produced two `entrypoint:` lines and put the `tmpfs` in the wrong position. `docker compose up` silently used the last value -- which happened to be correct -- but YAML with duplicate keys is undefined behavior. Recovery required `sed -i '62d' docker-compose.yml` to delete the duplicate line. The lesson: `sed` is unreliable for multiline YAML insertions. Use `sed -i '{line_number}a\ content'` for single-line inserts only, and verify with `sed -n` after every edit before recreating containers.

> **FOWNER -- Required for /data Volume**
> `cap_drop ALL` caused the worker to crash on startup: `chmod: changing permissions of '/data': Operation not permitted`. The worker `chown`s the `/data` volume at startup. `FOWNER` allows the process to bypass file ownership checks on `chmod`/`chown` operations even when the process UID does not match the file owner.

> **KILL -- Required for the Health Check**
> After adding `FOWNER`, the worker started successfully but showed `unhealthy` in `docker compose ps`. Inspection revealed: `operation not permitted -- failed to signal worker process`. The Authentik health check sends a signal to the worker process to verify responsiveness. `cap_drop ALL` removes `KILL`. The container was healthy; the health check was broken. Adding `KILL` resolves it.

### Residual Risk: Docker Socket

No capability restriction fully mitigates the Docker socket. A process with socket access can instruct the Docker daemon to run a privileged container regardless of its own capability set. Practical mitigations include using a Docker socket proxy (e.g. [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)) that restricts which API calls are permitted, removing the socket entirely and managing outposts manually, or monitoring socket usage via `auditd` rules on `/var/run/docker.sock`.

For this lab, the socket is retained with compensating controls and documented as a known residual risk.

### Verify It

```bash
sudo docker inspect authentik-worker-1 \
  --format 'CapDrop={{.HostConfig.CapDrop}} SecOpt={{.HostConfig.SecurityOpt}}'
# Expected: CapDrop=[ALL] SecOpt=[no-new-privileges:true]

sudo docker compose ps
# Expected: server (healthy), worker (healthy)
```

**CapDrop=[ALL] SecOpt=[no-new-privileges:true]** -- Worker capability restrictions confirmed. Both containers healthy.

## Final End-to-End Verification

All hardening controls verified from the attacker perspective. Every check re-runs the original attack command and expects failure.

| Check | Expected | Result |
|---|---|---|
| Port 9000 direct access cross-VLAN | CLOSED | CLOSED |
| `/api/v3/policies/expression/` (F-03 RCE) | 403 | 403 |
| `/api/v3/managed/blueprints/` (F-04) | 403 | 403 |
| `/-/metrics/` (F-01) | 403 | 403 |
| `.env` readable as `oob` (F-07) | DENIED | DENIED |
| Secrets in server tmpfs | 644 in-memory | 644 authentik:authentik |
| Secrets in worker tmpfs | 644 in-memory | 644 root:root |
| Django `SECRET_KEY` resolved (file:// URI) | SK_LEN: 81 | SK_LEN: 81 |
| `akadmin` active (F-12) | False | False |
| Recovery link generated for `akadmin` (F-12) | no link | no link |
| `oob` in docker group (F-12 host path) | Absent | Absent |
| Worker `CapDrop` (F-10) | [ALL] | [ALL] |
| Worker `no-new-privileges` (F-10) | true | true |
| Server container status | healthy | healthy |
| Worker container status | healthy | healthy |

## Compliance Mapping -- Remediated Findings

The compliance table from Part 1 covers all 15 findings. This table maps only the findings addressed in this article to the controls their remediation satisfies.

| Finding | NIST 800-53 | SOC 2 | PCI-DSS 4.0 | CIS v8 | OWASP ASVS |
|---|---|---|---|---|---|
| Localhost bind (F-02) | CM-7, SC-7 | CC6.6 | 1.2, 1.3 | CIS 2.7 | -- |
| HAProxy headers (F-06) | SC-18, SI-11 | CC6.6 | 6.4.1 | CIS 16.13 | 14.4 |
| Path blocking (F-03/04/01) | AC-3, SI-10 | CC6.1 | 6.4.2 | CIS 16.5 | -- |
| .env permissions (F-07) | AC-3, IA-5 | CC6.1 | 8.3.2 | CIS 5.4 | -- |
| OpenBAO secrets (F-07) | SC-28, IA-5 | CC6.1 | 8.3.1 | CIS 3.11 | -- |
| akadmin disabled (F-12) | IA-2, AC-2 | CC6.3 | 8.2.2 | CIS 5.3 | -- |
| Docker group (F-12 host) | AC-6 | CC6.1 | 7.2.1 | CIS 5.4 | -- |
| Worker cap_drop (F-10) | CM-7, AC-6 | CC6.1 | 2.2.1 | CIS 4.8 | -- |

## Dead Ends and Discoveries

The full details are in the chapter callouts above. Quick reference:

| # | Chapter | What Went Wrong | Fix |
|---|---------|-----------------|-----|
| 1 | Ch. 4 | Pasted `entrypoint.sh` into nano -- shell executed it as commands, SSH disconnected | `cat > file << 'EOF'` at `$` prompt only |
| 2 | Ch. 4 | `tmpfs mode=0700` -- entrypoint (root) writes files, but `authentik` user can't traverse the directory to read them | `mode=0777`; file permissions (`644`) are the boundary |
| 3 | Ch. 4 | `exec env` injection -- appeared healthy, broke on `ak shell` (9-var clean env) | `file://` URI; resolved at application level regardless of spawn method |
| 4 | Ch. 4 | `ENV_SECRET=31` looked wrong -- it's the length of the URI string, not the secret | Correct check: `SK_LEN: 81` from `ak shell` |
| 5 | Ch. 6 | Worker container 2 weeks stale -- never recreated, running pre-hardening config | Check `Created` timestamp in `docker compose ps` before assuming config is live |
| 6 | Ch. 6 | Multiline `sed` inserted duplicate `entrypoint:` key in YAML | Verify with `sed -n '{range}p'` after every insert; `sed -i '{line}d'` to recover |

> **Common searches this section answers:**
> "Authentik entrypoint.sh nano SSH disconnect" -- "docker compose tmpfs permission denied secrets" -- "ak shell missing SECRET_KEY after entrypoint" -- "Authentik worker container unhealthy cap_drop"

## Key Lessons

### 1. Defaults Are Optimized for Getting Started, Not Staying Secure

Every gap closed in this article existed in the default deployment. `0.0.0.0` binds, world-readable credential files, active superuser accounts, no capability restrictions -- none of these are bugs. They are defaults. The security baseline starts after you go beyond the getting-started guide.

### 2. Fail Loud, Fail Fast

The original entrypoint had no error handling. If OpenBAO returned an error, `TOKEN` would contain the error JSON, `SECRET_KEY` would be empty, and Authentik would fail with `Secret key missing` -- no indication of why. Adding explicit validation with `exit 1` and a clear error message means failures are immediately visible in `docker logs`. The Docker restart loop handles recovery once the dependency is available.

### 3. file:// URI Is the Right Pattern for Secrets Injection

`exec env` injects secrets into the process tree from the entrypoint. It does not survive `docker exec ak shell`, which spawns a new process with the base environment. `file://` URI is resolved at the application level -- every process that reads config picks it up regardless of how it was spawned. This is native Authentik functionality, confirmed in the source code.

### 4. Capability Tuning Is Iterative -- Start from ALL Dropped

`cap_drop ALL` is the starting point. Then add back only what breaks. `FOWNER` for the data volume chmod. `KILL` for the health check signal. Each capability added back was driven by a confirmed failure with a specific error message. Starting from ALL dropped and building up is significantly more secure than starting from the default capability set and trying to guess what to remove.

### 5. The Docker Socket Is the Elephant in the Room

The worker still has `/var/run/docker.sock` mounted. No capability restriction on the container fully mitigates this -- a process with socket access can ask the Docker daemon to run a privileged container regardless of its own caps. The real fix is either removing the socket (accepting manual outpost management) or a socket proxy that restricts which API operations are permitted. Documented as a residual risk.

### 6. Version Deltas Are Real -- Verify Live Behavior

Several findings shifted between versions. The metrics endpoint moved from Basic Auth with `SECRET_KEY` to a separate Bearer token. `X-Frame-Options` and `X-Content-Type-Options` appeared natively. The Postgres password env var name changed. Never rely on documentation from a different version. Always verify against running source code and live behavior.

## Frequently Asked Questions

**Does Authentik support secrets injection from a vault?**
Yes. Authentik natively resolves `file://` URIs in configuration values, confirmed in `/authentik/lib/tests/test_config.py`. Set `AUTHENTIK_SECRET_KEY: file:///run/secrets/secret_key` and write the secret to that path at container startup. The secret is read at application initialization -- no plaintext required in the environment.

**What is the minimum HAProxy configuration to block Authentik RCE via the expression policy API?**
Block three paths: `/api/v3/policies/expression/` (creation), `/api/v3/policies/all/{uuid}/test/` (execution), and `/api/v3/managed/blueprints/` (persistence). Return HTTP 403. This closes the primary attack chain at the proxy layer, regardless of token permissions.

**Is it safe to disable akadmin in Authentik?**
Yes. Deactivating (not deleting) akadmin via `ak shell` sets `is_active = False` without removing the account or breaking internal references. Authentik uses akadmin's pk (user ID 6 by default) in some internal relationships -- deletion can cause integrity issues. Deactivation eliminates it as an attack target while preserving referential integrity.

**What capabilities does the Authentik worker container actually need?**
Starting from `cap_drop: ALL`, two capabilities are required for normal operation on 2025.12.3: `FOWNER` (for `/data` volume permission changes at startup) and `KILL` (for the health check signal to the worker process). `CHOWN`, `DAC_OVERRIDE`, `SETGID`, `SETUID` may be required depending on your volume ownership configuration.

**Why does docker exec ak shell fail after entrypoint secrets injection via exec env?**
`docker exec` spawns a new process with the container's base environment -- it does not inherit the process tree built by the entrypoint. If secrets are injected via `exec env`, `ak shell` sees a clean environment with no `SECRET_KEY`. The fix is `file://` URI: the secret is resolved at the application configuration level, not the environment level, so it works regardless of how the process was spawned.

**What is the residual risk after these hardening steps?**
The Docker socket remains mounted in the worker container for outpost lifecycle management. A process with socket access can instruct the Docker daemon to run a privileged container regardless of its own capability set. Compensating controls are `cap_drop: ALL` and `no-new-privileges: true`. Full mitigation requires either a Docker socket proxy (e.g. Tecnativa/docker-socket-proxy) or manual outpost management without the socket.

## Sources

- Part 1 -- [I Broke My Own Identity Provider](https://oobskulden.com/posts/i-broke-my-own-identity-provider/)
- [Authentik documentation](https://docs.goauthentik.io)
- Authentik source -- config URI parsing: `/authentik/lib/tests/test_config.py` (`parse_uri`)
- [OpenBAO documentation](https://openbao.org/docs/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-63B Section 5.1.1 -- Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

> **Compliance Disclaimer**
> This article documents a personal homelab security audit conducted by an individual researcher in a personal capacity. It does not reflect the views, opinions, or positions of any employer, past or present. This is not professional security consulting advice. All techniques were performed exclusively on personal homelab infrastructure. Do not test these techniques on systems you do not own or do not have explicit written authorization to test.

*Published by Oob Skulden™ | oobskulden.com*
