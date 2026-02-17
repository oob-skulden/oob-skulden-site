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

> **Homelab Environment -- Adapt Before Applying**
>
> The configurations in this post are demonstrated in a personal homelab running on isolated VLANs. While the hardening principles apply broadly, you should evaluate and adapt these configurations to your own environment's requirements, network topology, and compliance obligations before implementation. Always test changes in a non-production environment first.

---

## Closing 15 Vulnerabilities Without Breaking the Stack

The assessment post left us with 15 vulnerabilities, a security score of 6.0, and a monitoring stack that was hemorrhaging data to anyone with `curl` and a network connection. This post is about fixing all of it -- and the implementation details that documentation never warns you about.

Six phases. Ordered by impact, not by difficulty. The easy wins go first because morale matters when you're staring down 15 findings, and because each phase builds on the one before it. Phase 1 stops sessions from outliving employees. Phase 2 is the big one -- HAProxy drops in and closes four vulnerabilities in a single deployment. Phase 3 puts a lock on Prometheus. Phase 4 gets secrets out of plaintext and into OpenBAO. Phase 5 strips containers down to minimum capabilities. Phase 6 sweeps up everything else.

Every phase includes the exact config, what broke during implementation, and what we learned from it breaking.

Quick orientation if you're reading this standalone: the monitoring stack (Grafana, Prometheus, and three exporters) runs on Grafana-lab (VLAN 75). Authentik handles SSO from VLAN 80. OpenBAO provides secret management on a separate VLAN. The assessment was run from a jump box on VLAN 50 with no prior credentials.

---

## Phase 1: Session Hardening + OAuth Sign-Up Control

**Closes:** VULN-06 (Session Persistence), VULN-13 (OAuth Auto Sign-Up)
**Score impact:** 6.0 to 7.5
**Duration:** ~2 hours

### Session Timeouts

The assessment found 7-day idle and 30-day absolute session maximums -- Grafana's defaults. A terminated employee retains dashboard access for up to a month. Three environment variables fix this:

```yaml
# docker-compose.yml -- Grafana environment
# === SESSION HARDENING (Phase 1) ===
- GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h
- GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h
- GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10
```

One-hour idle timeout, 24-hour absolute maximum. Token rotation stays at 10 minutes -- it keeps active sessions alive, which is fine now that the absolute cap prevents indefinite persistence. A terminated user loses access within one hour of inactivity, worst case.

The ideal solution is a webhook from Authentik that revokes Grafana sessions on user disable/delete events. That's a more complex integration and wasn't implemented in this phase, but the 1-hour idle timeout provides a reasonable backstop.

### OAuth Sign-Up

The assessment flagged a contradiction: `GF_USERS_ALLOW_SIGN_UP=false` but `GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true`. The OAuth flag overrides the general one.

We left OAuth sign-up enabled because Authentik application assignment controls which users can authenticate in the first place. If a user isn't assigned to the Grafana application in Authentik, they can't complete the OAuth flow regardless of the sign-up flag.

The mitigation is tight Authentik application assignment rather than disabling OAuth sign-up entirely. That's a deliberate trade-off -- it puts the access control boundary at the identity provider where it belongs, rather than duplicating it in every downstream application.

### OAuth Secret Migration to OpenBAO

This phase also included the first OpenBAO integration: migrating the OAuth client secret out of plaintext files and into encrypted storage. The full OpenBAO deployment gets its own series, but the secret injection pattern is relevant to this hardening narrative.

The setup:

| Item | Value |
|---|---|
| Secret path | `secret/grafana/oauth` |
| Policy | `grafana-policy` (read-only to `secret/data/grafana/*`) |
| AppRole | `grafana` |
| Role ID | `<redacted-role-id>` |
| Token TTL | 1h / Max TTL: 4h |

The entrypoint script fetches secrets at container startup:

```bash
#!/bin/bash
# ~/monitoring/entrypoint.sh (755 permissions)
# Fetch OAuth secret from OpenBAO at container startup

TOKEN=$(curl -s --request POST \
  --data "{\"role_id\":\"$BAO_ROLE_ID\",\"secret_id\":\"$BAO_SECRET_ID\"}" \
  $BAO_ADDR/v1/auth/approle/login | jq -r '.auth.client_token')

SECRET=$(curl -s --header "X-Vault-Token: $TOKEN" \
  $BAO_ADDR/v1/secret/data/grafana/oauth | jq -r '.data.data.client_secret')

CLIENT_ID=$(curl -s --header "X-Vault-Token: $TOKEN" \
  $BAO_ADDR/v1/secret/data/grafana/oauth | jq -r '.data.data.client_id')

exec env \
  GF_AUTH_GENERIC_OAUTH_CLIENT_ID="$CLIENT_ID" \
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="$SECRET" \
  /run.sh "$@"
```

The `.env` file (permissions 600) holds the AppRole credentials and admin password -- not the OAuth secret itself. The secret only exists in OpenBAO (encrypted at rest) and in container memory at runtime.

**The gotcha that cost an hour:** The original version used `export` followed by `exec /run.sh`. It didn't work. `exec` replaces the current shell process, so exported variables from the shell don't carry through. The fix is the `exec env VAR=value /run.sh` pattern -- `env` sets the variables in the environment that `exec` passes to the new process. Simple once you know it, frustrating until you figure it out.

---

## Phase 2: TLS Encryption + Rate Limiting + Security Headers

**Closes:** VULN-07 (Brute-Force), VULN-08 (Plaintext OAuth), VULN-09 (Missing Headers), VULN-10 (All HTTP)
**Score impact:** 7.5 to 8.0
**Duration:** ~3 hours

Four vulnerabilities. One service. Three hours of work. HAProxy is the single highest-value deployment in this entire hardening effort -- it gives us TLS termination, rate limiting, security headers, and real client IPs in the logs, all from one config file.

### HAProxy Configuration

HAProxy sits on Grafana-lab at 192.168.75.84 (the host's primary IP changed from .109 during a network reconfiguration between the assessment and hardening phases). It terminates TLS, adds security headers, rate-limits login attempts, and proxies to Grafana on localhost:

```
# Frontend -- HTTP to HTTPS redirect
frontend http_grafana
  bind *:80
  redirect scheme https code 301

# Frontend -- HTTPS (TLS termination)
frontend https_grafana
  bind *:443 ssl crt /etc/haproxy/certs/grafana.pem

  # Security headers (VULN-09)
  http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
  http-response set-header X-Frame-Options "SAMEORIGIN"
  http-response set-header X-Content-Type-Options "nosniff"
  http-response set-header X-XSS-Protection "1; mode=block"
  http-response set-header Referrer-Policy "strict-origin-when-cross-origin"

  # Rate limiting (VULN-07): 100 req/10s per IP
  stick-table type ip size 100k expire 30s store http_req_rate(10s)
  http-request track-sc0 src
  http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

  default_backend grafana_backend

# Backend -- Grafana on localhost only
backend grafana_backend
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Proto https
  server grafana 127.0.0.1:3000 check

# Stats page (localhost only)
frontend stats
  bind 127.0.0.1:8404
  stats enable
  stats uri /stats
```

Three details in this config that aren't obvious. The `option forwardfor` directive is what fixes the IP masking problem from VULN-14 -- HAProxy inserts the real client IP into the X-Forwarded-For header, so Grafana logs the actual attacker address instead of the Docker gateway. That's a logging fix hiding inside a proxy config. The rate limiting uses a stick-table keyed by source IP with a 10-second sliding window. 100 requests in 10 seconds is generous for legitimate use and kills the 54-requests-per-second brute-force pattern the assessment demonstrated. The 429 response tells clients they're being throttled -- some brute-force tools will back off, though a determined attacker just distributes across IPs.

### TLS Certificate

The certificate comes from OpenBAO's PKI engine (internal CA):

| Item | Value |
|---|---|
| PEM bundle | cert + key + CA in `/etc/haproxy/certs/grafana.pem` |
| Ownership | `haproxy:haproxy` |
| Permissions | 600 |

### Grafana Binding Changes

With HAProxy handling external traffic, Grafana no longer needs to be network-accessible:

```yaml
# docker-compose.yml
ports:
  - "127.0.0.1:3000:3000"  # Localhost only -- not accessible from network
```

`ROOT_URL` updated to `https://192.168.75.84`. OAuth redirect URIs updated in Authentik to use HTTPS. Firewall updated: port 3000 closed externally, ports 80 and 443 open.

The assessment's 50-attempts-in-0.931-seconds test now gets a 429 after the first 100 requests in any 10-second window. Not perfect -- a slow-and-low attack at 9 requests per second would still work -- but it eliminates the spray-and-pray approach.

---

## Phase 3: Prometheus Authentication + Network Segmentation

**Closes:** VULN-01 (Prometheus Unauth), VULN-12 (Network Segmentation)
**Score impact:** 8.0 to 8.5

VULN-01 was the first finding in the assessment -- Prometheus serving the complete infrastructure topology to anyone with network access. It's also one of the most satisfying to close, because Prometheus's reputation as "impossible to add auth to" is outdated.

### Prometheus Basic Auth

Prometheus doesn't support authentication natively in its config file. It added a `web.yml` configuration in recent versions that supports bcrypt basic auth:

```bash
# Generate bcrypt hash
htpasswd -nBC 12 prometheus
```

```yaml
# ~/monitoring/web-config.yml
basic_auth_users:
  prometheus: $2y$12$<bcrypt_hash>
```

```yaml
# docker-compose.yml -- Prometheus service
prometheus:
  ports:
    - "127.0.0.1:9090:9090"  # Localhost only
  volumes:
    - ./web-config.yml:/etc/prometheus/web-config.yml:ro
  command:
    - "--config.file=/etc/prometheus/prometheus.yml"
    - "--web.config.file=/etc/prometheus/web-config.yml"
```

Prometheus is now bound to localhost and requires authentication. The assessment's unauthenticated topology extraction (`curl http://192.168.75.109:9090/api/v1/targets`) returns nothing -- the port isn't reachable externally, and even local requests need credentials.

### Grafana Datasource Provisioning

Grafana needs authenticated access to Prometheus. This is handled through provisioning:

```yaml
# ~/monitoring/grafana/provisioning/datasources/prometheus.yml
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
```

The password is stored in `.env` as `PROMETHEUS_PASSWORD=<value>` and injected via environment variable substitution.

**The gotcha that caused 30 minutes of confusion:** After deploying Prometheus auth, the Grafana dashboards started showing browser basic auth popups -- the kind where the browser itself asks for a username and password. This happened because there were two Prometheus datasources: the original one created manually through the Grafana UI (no auth), and the new provisioned one (with auth). Grafana was querying both, and the unauthenticated one was returning 401 with a `WWW-Authenticate` header that the browser intercepted. The fix is deleting the old manually-created datasource from the Grafana UI. Provisioned datasources with `editable: false` can't be modified through the UI, which is the correct state.

### Docker Network Segmentation

The assessment showed all five containers on a single `monitoring_default` bridge network. The fix is two purpose-specific networks:

```yaml
# docker-compose.yml
networks:
  grafana_network:    # Grafana <-> Prometheus
    external: true
  prometheus_network: # Prometheus <-> Exporters
    external: true
```

Only Prometheus connects to both networks. Grafana can reach Prometheus but not the exporters. The exporters can't reach Grafana directly. A compromise of cAdvisor or blackbox-exporter no longer gives lateral movement to the Grafana container -- the attacker would need to pivot through Prometheus first, which now requires authentication.

---

## Phase 4: OpenBAO Dynamic Secret Injection

**Closes:** VULN-05 (OAuth Secret Plaintext)
**Score impact:** 8.5 to 9.0

Phases 1 through 3 are all standard hardening -- config changes, service deployments, network rules. Phase 4 is where the stack's security model actually changes. Secrets stop being static strings copied between files and start being dynamic values fetched at runtime from encrypted storage.

This phase validates the full AppRole chain end-to-end. The entrypoint script from Phase 1 was already in place -- this phase verified the complete workflow and removed the last plaintext secret references.

The verification chain: AppRole login returns a valid token, the token retrieves the secret from `secret/data/grafana/oauth`, the entrypoint script injects secrets via the `exec env` pattern, and Grafana starts with dynamically-retrieved OAuth credentials.

The OAuth secret was removed from the `docker-compose.yml` environment block entirely. It now exists in exactly two places: OpenBAO (`secret/grafana/oauth`), encrypted at rest, and in container memory at runtime after injection.

One useful verification: `docker inspect` no longer shows the secret because it wasn't set at container creation time -- it was injected at process start by the entrypoint:

```bash
sudo docker inspect grafana --format '{{json .Config.Env}}' | grep -i client_secret
# (empty -- secret is NOT in container metadata)
```

The secret is still visible via `docker exec grafana env` because it's in the running process environment. That's inherent to how environment variables work -- any process can read its own environment. The improvement is that the secret no longer persists in container metadata, the `.env` file, or the compose configuration. An attacker needs either a shell inside the container or root on the host to extract it.

---

## Phase 5: Container Hardening

**Closes:** VULN-11 (No Container Hardening)
**Score impact:** 9.0 to 9.5

This is the phase where things start breaking. Everything up to now was additive -- deploying HAProxy, enabling auth, adding networks. Phase 5 is subtractive. We're taking capabilities away from running containers, and containers don't always appreciate that.

Applied to Grafana first (other containers follow in Phase 6):

```yaml
# docker-compose.yml -- Grafana service
grafana:
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
```

`cap_drop: ALL` removes every Linux capability, then `cap_add` puts back only the four that Grafana actually needs. `no-new-privileges` prevents any process inside the container from gaining additional privileges through setuid binaries or capability inheritance. Resource limits cap CPU at 2 cores and memory at 2GB -- matching the host capacity, which prevents a single container from starving the others.

**The gotcha that caused a crash loop:** The first attempt used `cap_drop: ALL` with only `CHOWN`, `SETGID`, and `SETUID` added back. Grafana went into a restart loop with "attempt to write a readonly database" errors. Grafana uses SQLite for its internal database, and SQLite write operations require the `DAC_OVERRIDE` capability to bypass filesystem permission checks. Adding `DAC_OVERRIDE` to the `cap_add` list resolved it.

**The second gotcha that was tested and reverted:** `read_only: true` on the container filesystem seems like an obvious hardening step. It's not compatible with Grafana. SQLite requires write access to its data directory for journaling and WAL files. Setting the container filesystem to read-only crashed Grafana immediately. The correct approach would be a read-only filesystem with explicit tmpfs mounts for the SQLite data directory, but that adds complexity without proportional security benefit when the container already runs as a non-root user (472) with dropped capabilities.

---

## Phase 6: Everything Else

The first five phases are the structural changes -- the ones that fundamentally alter the stack's security posture. Phase 6 is the long tail: the individual fixes, the operational hardening, and the "we should probably have a backup" realization that should have happened on day one.

### Phase 6.1: Automated Certificate Renewal

**Supports:** VULN-08, VULN-10 (maintains TLS continuity)

TLS is useless if certificates expire and nobody notices. The renewal automation:

| Item | Value |
|---|---|
| Script | `/usr/local/bin/renew-grafana-cert.sh` |
| Cron | `0 2 */20 * *` (every 20 days at 2 AM) |
| Log | `/var/log/grafana-cert-renewal.log` |
| AppRole | `pki-grafana-renew` (dedicated -- not the same AppRole as secret access) |
| Permission | `pki/issue/grafana-server` only |

The workflow: AppRole login gets a short-lived token, the token requests a new certificate from OpenBAO's PKI engine, the script bundles cert + key + CA into the HAProxy PEM file, backs up the old certificate, installs the new one, and reloads HAProxy with `systemctl reload` (zero downtime -- HAProxy reloads gracefully without dropping connections).

The dedicated AppRole is worth calling out. The certificate renewal role can only issue certificates -- it can't read secrets from `secret/grafana/oauth` or any other path. Principle of least privilege applied to the automation itself.

### Phase 6.2: Audit Logging

**Closes:** VULN-14 (No Audit Logging)

```yaml
# docker-compose.yml -- Grafana environment
# === AUDIT LOGGING (Phase 6.2) ===
- GF_LOG_MODE=console file
- GF_LOG_LEVEL=info
- GF_LOG_FILE_FORMAT=json
- GF_LOG_FILE_LOG_ROTATE=true
- GF_LOG_FILE_MAX_DAYS=30
```

Before: Console-only, text format, ephemeral, attacker IPs masked as Docker gateway (172.18.0.1). After: Dual output (console + persistent file), JSON structured format for SIEM or Loki ingestion, 30-day retention with rotation.

The IP masking issue -- where all remote addresses showed as the Docker gateway -- is resolved by HAProxy's `X-Forwarded-For` header from Phase 2. With HAProxy in front, Grafana receives the real client IP in the forwarded header and logs it correctly. Two separate phases that depend on each other.

### Phase 6.3: Snapshot Security

**Supports:** Defense-in-depth (prevents data exfiltration)

```yaml
# === SNAPSHOT SECURITY (Phase 6.3) ===
- GF_SNAPSHOTS_EXTERNAL_ENABLED=false
- GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL=
```

Grafana ships with a feature that lets any authenticated user publish dashboard snapshots to an external service -- `snapshots.raintank.io` by default. Those snapshots are public. They don't expire. They persist after the user's account is deleted. It's a one-click data exfiltration path disguised as a sharing feature, and it's enabled out of the box.

An insider or a compromised account takes a snapshot of the infrastructure dashboard, publishes it externally, and walks away. The snapshot survives account termination. Nobody gets notified. Disabling external snapshots and clearing the URL kills the vector. Internal snapshots still work fine.

### Phase 6 Remaining: Exporter Localhost Binding + Backups

**Closes:** VULN-02 (cAdvisor), VULN-03 (Node Exporter), VULN-04 (Blackbox SSRF), VULN-15 (No Backup)

The exporter binding follows the same pattern applied to Prometheus and Grafana:

```yaml
# docker-compose.yml
cadvisor:
  ports:
    - "127.0.0.1:8080:8080"

node-exporter:
  ports:
    - "127.0.0.1:9100:9100"

blackbox-exporter:
  ports:
    - "127.0.0.1:9115:9115"
```

Prometheus scrapes all three over the internal Docker network -- it doesn't need the host-mapped ports at all. The localhost binding is defense-in-depth: even if someone adds a route to the host, the exporter ports aren't listening on the external interface.

This eliminates the Blackbox SSRF vector entirely. The assessment showed cross-VLAN reconnaissance through `http://192.168.75.109:9115/probe?target=...` -- that URL no longer resolves to anything. Blackbox still functions for its intended purpose (probing targets that Prometheus defines in its scrape config) because Prometheus reaches it over the Docker network, not through the host port mapping.

Backup scripts for both Docker volumes (`grafana-storage` and `prometheus-storage`) with offsite storage and documented recovery procedures complete the phase.

---

## Compliance Closure Summary

### Controls Fully Closed

| Control | Phase | How Verified |
|---|---|---|
| NIST AC-2(3) | 1 | Session timeout confirmed via admin API: 1h idle |
| NIST AC-7 | 2 | HAProxy stick-table: 429 on excess requests |
| NIST AC-12 | 1 | 24h absolute max confirmed via admin API |
| NIST AU-2 | 6.2 | JSON log file created, auth events captured |
| NIST AU-3 | 6.2 | Structured JSON with timestamp, user, IP, action |
| NIST CM-7 | 3, 5 | Prometheus localhost + cap_drop ALL |
| NIST IA-5 | 2, 4 | TLS protects transit + OpenBAO manages secrets |
| NIST SC-6 | 5 | CPU/memory limits: 2 CPU / 2GB |
| NIST SC-8 | 2 | TLS 1.2+ enforced, HTTP redirects to HTTPS |
| NIST SC-23 | 2 | HSTS prevents protocol downgrade |
| NIST SC-28 | 4 | OAuth secret in OpenBAO, not on disk |
| SOC 2 CC6.1 | 1-4 | Auth on all endpoints + session controls |
| SOC 2 CC6.3 | 1 | 1h idle timeout enforces access removal |
| SOC 2 CC6.7 | 2 | All traffic TLS-encrypted |
| SOC 2 CC7.2 | 6.2 | 30-day persistent structured audit logs |
| CIS v8 4.1 | 3 | Prometheus auth + localhost binding |
| CIS v8 6.2 | 1 | Session expiry automates revocation |
| CIS v8 16.8 | 2 | HSTS, X-Frame-Options, Referrer-Policy |
| CIS Docker 4.10 | 4 | Secret in OpenBAO, not in Dockerfiles/env |
| CIS Docker 5.26 | 5 | no-new-privileges prevents escalation |
| CIS Docker 5.30 | 3 | User-defined networks replace default bridge |

### Controls Pending Phase 6 Completion

| Control | What Remains |
|---|---|
| NIST AC-3 | Exporter localhost binding |
| NIST AC-4 | Blackbox target allowlist |
| NIST SC-7 | Exporter access restriction |
| NIST CP-9 | Backup scripts |
| NIST CP-10 | Recovery procedures |
| SOC 2 CC6.6 | SSRF elimination |
| SOC 2 A1.2 | Backup documentation |
| CIS v8 13.4 | Network access controls on exporters |
| CIS Docker 5.4 | cAdvisor privilege restriction |

### PCI-DSS v4.0 Closure

Most PCI controls closed through Phases 1-6. The notable gaps:

| PCI Requirement | Status | Gap |
|---|---|---|
| 8.4.2 -- MFA for CDE access | Partial | Authentik SSO is primary auth, but local admin still lacks MFA. Disabling the local login form or enforcing TOTP via Authentik closes this. |
| 10.5.1 -- 12-month retention | Partial | 30 days on-disk. Central log forwarding to a SIEM with 12-month retention is needed. |
| 12.10.1 -- Incident response plan | Open | No IR documentation. Requires a documented playbook beyond just backup/recovery. |

---

## Security Score Progression

A note on methodology: the scoring below is a weighted assessment developed for this series based on the severity distribution and count of open findings at each phase. It is not an industry-standard benchmark, certification metric, or vendor score -- it's a narrative device to track remediation progress.

| Phase | Score | Key Change |
|---|---|---|
| Baseline (pre-remediation) | 6.0 | 15 open vulnerabilities |
| Phase 1 -- Sessions + Sign-up | 7.5 | Terminated users lose access within 1h |
| Phase 2 -- TLS + Rate Limiting | 8.0 | All traffic encrypted, brute-force blocked |
| Phase 3 -- Prometheus Auth + Networks | 8.5 | No unauthenticated data access, lateral movement restricted |
| Phase 4 -- OpenBAO Secrets | 9.0 | No plaintext secrets on disk or in metadata |
| Phase 5 -- Container Hardening | 9.5 | Minimal capabilities, resource limits, no privilege escalation |
| Phase 6 -- Exporters + Logging + Backups | 9.8 | Full exporter lockdown, persistent audit trail, recovery path |

---

## What's Still Missing

The stack went from 6.0 to 9.8. The remaining 0.2 is:

**MFA enforcement on the local admin account.** Authentik SSO handles MFA for OAuth users, but the local admin login form bypasses SSO entirely. Either disable it (`GF_AUTH_DISABLE_LOGIN_FORM=true`) or enforce TOTP through Authentik for all authentication paths. We left it enabled during hardening because locking yourself out of the local admin during a TLS misconfiguration is a bad time.

**12-month log retention with central forwarding.** The 30-day on-disk retention meets most operational needs but falls short of PCI 10.5.1's 12-month requirement. Forwarding to Loki or a SIEM with long-term storage closes this.

**A documented incident response plan.** Backup scripts and recovery procedures exist, but a full IR playbook -- who gets notified, what gets contained, how evidence is preserved -- doesn't. That's an organizational deliverable, not a technical one.

**OpenBAO gets its own dedicated series.** The AppRole integration shown here is the tip of the iceberg -- PKI certificate lifecycle management, dynamic secret rotation, token provisioning patterns, and the architecture decisions behind each of those are substantial topics that deserve proper treatment rather than being squeezed into a hardening appendix.

The tools didn't change between the assessment and the remediation. Same Grafana version. Same Prometheus. Same Docker Compose file. Not a single binary was upgraded, patched, or replaced. Every vulnerability was a configuration choice someone made -- or more accurately, a configuration choice someone didn't make, because the defaults shipped as-is. Every fix was a configuration change.

That's the uncomfortable truth about monitoring stack security: the gap between "deployed" and "hardened" is entirely made of decisions that nobody forced you to make. The vendors ship permissive defaults because they optimize for ease of setup, not for security. If you don't actively close the gaps, they stay open. Indefinitely. While your monitoring infrastructure quietly catalogs everything an attacker would want to know about your environment.

6.0 to 9.8. Same tools. Different configs. That's it.

---

## References and Resources

**Grafana Configuration Documentation** -- Session timeout variables (`GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION`, `GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION`), logging configuration, snapshot controls, and OAuth settings referenced from [Grafana Configuration](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/).

**Grafana Authentication Documentation** -- OAuth2/OpenID Connect integration, role mapping via `role_attribute_path`, and sign-up behavior documented in [Grafana Authentication](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/).

**HAProxy Configuration Manual** -- TLS termination (`bind ... ssl crt`), stick-table rate limiting, `option forwardfor`, and security header injection referenced from the [HAProxy Configuration Manual](https://docs.haproxy.org/2.8/configuration.html) and [HAProxy Blog](https://www.haproxy.com/blog/).

**Prometheus Web Configuration** -- Basic auth via `web.yml` with bcrypt password hashing documented in [Prometheus Web Configuration](https://prometheus.io/docs/prometheus/latest/configuration/https/). The `--web.config.file` flag and htpasswd bcrypt generation follow the official guide.

**OpenBAO / HashiCorp Vault Documentation** -- AppRole authentication, KV secrets engine, PKI certificate issuance, and policy configuration referenced from [OpenBAO Documentation](https://openbao.org/docs/) and the upstream HashiCorp Vault documentation where OpenBAO maintains API compatibility. The `exec env` pattern for secret injection at container startup was developed through experimentation.

**Docker Compose Specification** -- Network definitions, port binding syntax (`127.0.0.1:port:port`), capability management (`cap_drop`, `cap_add`), security options (`no-new-privileges`), and resource limits referenced from the [Docker Compose Specification](https://docs.docker.com/compose/compose-file/).

**CIS Docker Benchmark v1.6** -- Container hardening recommendations including capability dropping (5.3), memory limits (5.10), privilege escalation prevention (5.26), and network segmentation (5.30) from the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).

**OWASP Secure Headers Project** -- Security header selection and values (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) referenced from the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).

**NIST SP 800-53 Rev 5** -- Control closure verification mapped to [NIST Special Publication 800-53 Revision 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).

**Linux Capabilities (man 7 capabilities)** -- The `DAC_OVERRIDE` requirement for SQLite write operations and the relationship between dropped capabilities and container functionality referenced from the Linux capabilities man page.

**PCI-DSS v4.0** -- Compliance gap analysis mapped to [PCI Security Standards Council](https://www.pcisecuritystandards.org/) requirements.

---

*Published by Oob Skulden™ -- Stay Paranoid.*
