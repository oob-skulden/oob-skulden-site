---
title: "Before You Can Break It, You Have to Build It Wrong"
date: 2026-03-03T00:00:00-06:00
lastmod: 2026-03-03T00:00:00-06:00

# ─── SEO ────────────────────────────────────────────────────────────────────
# description feeds <meta name="description"> and Open Graph og:description.
# Keep under 160 chars. Front-load the primary keyword.
description: "Deploy the intentionally vulnerable Open WebUI v0.6.33 + Ollama 0.1.33 lab stack on Debian 13 from scratch -- Docker, compose file, API account setup, and every gotcha for CVE-2025-64496 lab reproduction."

# summary feeds Hugo list pages and RSS. Can be longer than description.
summary: "Step-by-step build guide for the CVE-2025-64496 vulnerable lab stack: Ollama 0.1.33 zero-auth API + Open WebUI v0.6.33 below the SSE code injection patch threshold. Covers Docker install on Debian 13, compose configuration with correct env vars, admin and victim account creation via API, Direct Connections setup, and the workspace.tools env var that makes the RCE chain work."

# keywords feeds <meta name="keywords"> -- low direct ranking value but
# used by some crawlers and helpful for internal site search (Fuse.js).
# Order: primary term first, then long-tail, then related.
keywords:
  - open webui CVE-2025-64496
  - ollama docker security lab
  - open webui docker install debian
  - ollama 0.1.33 zero auth
  - open webui v0.6.33 vulnerable
  - self-hosted AI security homelab
  - docker compose open webui ollama
  - open webui workspace tools permission
  - AI infrastructure security lab
  - CVE-2025-64496 reproduce
  - ollama unauthenticated API
  - open webui admin account API

# ─── TAXONOMY ────────────────────────────────────────────────────────────────
tags:
  - open-webui
  - ollama
  - ai-infrastructure
  - docker
  - homelab
  - security-audit
  - CVE-2025-64496
  - debian
categories:
  - AI Infrastructure Security
series:
  - AI Infrastructure Security
series_order: 5

# ─── AUTHORSHIP & IDENTITY ──────────────────────────────────────────────────
# author as a list enables PaperMod's multi-author schema.org output.
author: ["Oob Skulden™"]

# canonicalURL prevents duplicate-content penalties if the post is
# syndicated to Substack, Medium, or dev.to.
canonicalURL: "https://oobskulden.com/posts/ep3-2a-build/"

# ─── OPEN GRAPH / TWITTER CARDS (GEO + SEO) ─────────────────────────────────
# images[0] is used by PaperMod for og:image and twitter:image when no
# cover image is present. Provide an absolute URL once you have an image.
# Recommended size: 1200x630px.

# ─── COVER IMAGE ─────────────────────────────────────────────────────────────
cover:
  image: ""
  alt: "Open WebUI and Ollama lab stack architecture: NUC VM at 192.168.100.244 running Ollama 0.1.33 and Open WebUI v0.6.33 in Docker, connected to jump box at 192.168.50.10 and desktop GPU at 192.168.38.215"
  caption: "The vulnerable lab stack before the attacker arrives."
  relative: false
  hidden: true

# ─── PAPERMOD DISPLAY ────────────────────────────────────────────────────────
showToc: true
TocOpen: true
draft: false
hidemeta: false
comments: false
disableHLJS: false
disableShare: false
searchHidden: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: false
ShowRssButtonInSectionTermList: true
UseHugoToc: true

# ─── EDIT LINK ───────────────────────────────────────────────────────────────
---

> **Disclaimer:** All testing was performed against infrastructure owned and operated by the author in a private lab environment. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 103>
>
> This content represents personal educational work conducted in a home lab environment on personal equipment. It does not reflect the views, opinions, or positions of any employer or affiliated organization. All security methodologies >

Every good heist movie starts the same way. The crew cases the joint. They study the layout, map the exits, figure out where the guards are and when they rotate. Nobody shows up with a blowtorch and a prayer.

[Episode 3.2B](/posts/ep3-2b-break/) is the heist. CVE-2025-64496, a fake model server, a stolen JWT, and a chain of escalations that ends with full admin control from a single chat message. It is genuinely alarming and we documented every step.

But first, someone has to build the bank.

This is that episode. No exploits. No CVEs. Just a fresh Debian 13 VM, two Docker containers, and enough deliberate misconfiguration to give 3.2B something worth breaking. If you have wondered what a "vulnerable by design" lab stack actually looks like to set up -- and specifically where the setup itself goes sideways -- you are in the right place.

> **What this post covers:** Installing Docker on Debian 13, writing the correct `docker-compose.yml` for Ollama 0.1.33 and Open WebUI v0.6.33, creating admin and victim accounts via the Open WebUI API, enabling Direct Connections, and setting the `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS` env var that makes the CVE-2025-64496 RCE chain reproducible. Every gotcha documented.


---

## What We Are Deploying

The target is two containers on a single Docker bridge network. No reverse proxy. No TLS. No network segmentation. No authentication on the backend. This is exactly how the internet's 175,000+ exposed Ollama instances are configured right now.

| Component | Version | Port | Auth | CVE Status |
|---|---|---|---|---|
| Ollama | 0.1.33 | 11434 | None | Vulnerable (zero-auth, path traversal) |
| Open WebUI | v0.6.33 | 3000 | Enabled (JWT) | Vulnerable (CVE-2025-64496, below v0.6.35 patch) |

The version numbers are not accidents. According to SentinelOne Labs and Censys, approximately 175,000 Ollama instances were publicly reachable as of January 2026 -- of which 14,000+ had zero authentication enabled on the management API. Ollama 0.1.33 is the version found across a significant share of those zero-auth deployments. Open WebUI v0.6.33 sits one version below the patch threshold for CVE-2025-64496 -- the SSE code injection vulnerability that drives the entire 3.2B attack chain. The patch landed in v0.6.35. We are running v0.6.33. That gap is the whole story.

**Lab network:**

| Role | Host | IP |
|---|---|---|
| Jump box (attacker) | Debian/XFCE | 192.168.50.10 |
| NUC VM (target) | Debian 13 | 192.168.100.244 |
| Desktop (GPU backend) | Windows, RTX 3080 Ti | 192.168.38.215 |

All attack commands originate from `192.168.50.10`. Everything between the jump box and the NUC is, by design, unencrypted and unauthenticated at the Ollama layer.

---

## Installing Docker on Debian 13

The NUC VM came with nothing useful pre-installed. Fresh Debian 13 (Trixie), no Docker, no Compose. The Debian repos carry an older Docker version, so we add Docker's official apt repository to get the current stable release.

```bash
# Install prerequisites
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository
echo \
  "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update and install
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
```

Five packages: the Docker daemon, the CLI, the container runtime, the build plugin, and the Compose plugin. The last one matters. Modern Docker Compose ships as a plugin (`docker compose`) rather than a standalone binary (`docker-compose`). If `docker compose version` returns an error after this, `docker-compose-plugin` is missing.

One thing `/opt` does on a fresh Debian install: it is owned by root. Creating the working directory requires `sudo` followed by a `chown` to hand it back:

```bash
sudo mkdir -p /opt/oob-3.2 && sudo chown oob:oob /opt/oob-3.2 && cd /opt/oob-3.2
```

Add your user to the docker group before touching anything else:

```bash
sudo usermod -aG docker oob && newgrp docker
```

The `newgrp docker` applies the group membership to the current session without requiring a logout. Skip it and every docker command fails with a permissions error until you figure out why.

Verify both tools installed correctly:

```bash
docker --version && docker compose version
```

```
Docker version 29.3.1, build c2be9cc
Docker Compose version v5.1.1
```

---

## The Compose File

Docker Compose is a YAML file that describes what containers to run, how they are configured, and how they talk to each other. One file, two containers, one command to start everything.

```yaml
# /opt/oob-3.2/docker-compose.yml
services:
  ollama:
    image: ollama/ollama:0.1.33
    ports:
      - "11434:11434"
    volumes:
      - ollama:/root/.ollama
    restart: unless-stopped

  open-webui:
    image: ghcr.io/open-webui/open-webui:v0.6.33
    ports:
      - "3000:8080"
    environment:
      - OLLAMA_BASE_URL=http://ollama:11434
      - WEBUI_AUTH=true
      - USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=true
    volumes:
      - open-webui:/app/backend/data
    depends_on:
      - ollama
    restart: unless-stopped

networks:
  default:
    name: lab_default

volumes:
  ollama:
  open-webui:
```

A few things worth explaining before running this.

**`3000:8080`** -- the left side is the host port you browse to. The right side is what Open WebUI listens on inside the container and is fixed at 8080. Change the left side freely. Never change the right side.

**`OLLAMA_BASE_URL=http://ollama:11434`** -- uses the Docker service name `ollama`, not `localhost` or an IP address. Docker's internal DNS resolves service names within a compose network. If you use `localhost` here, both containers start cleanly, Open WebUI loads fine, and then silently fails to reach Ollama on every inference request with no obvious error at startup. The failure only surfaces when you try to run inference and nothing comes back.

**`WEBUI_AUTH=true`** -- auth is on. The 3.2B attack is not a zero-auth story. It is about what happens after authentication, when the trust model falls apart at the application layer.

**`USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=true`** -- this one took a detour to find, documented in full below.

**`lab_default` network name** -- the explicit network block overrides Docker's auto-generated name. Without it, Docker names the network after the directory (`oob-3.2_default`), which creates confusion when blog posts and lab notes reference `lab_default`.

**What is intentionally missing: `ENABLE_SIGNUP=false`.** That line looks like a reasonable security improvement -- disable self-registration so random people cannot create accounts. The problem is that in v0.6.33, it also blocks the very first admin account registration. The signup form accepts your input, posts to `/api/v1/auths/signup`, gets a `403` back from the server, and shows no explanation. The signup flag applies to all signups including the first one. Signup gets disabled through the Admin UI instead, after the admin account already exists.

---

## Bringing It Up

```bash
docker compose up -d
```

Docker pulls both images, creates the network and volumes, and starts the containers. Ollama is around 2GB, Open WebUI around 1GB on the first pull. After that they are cached locally and subsequent restarts are fast.

```bash
docker compose ps
```

```
NAME                  IMAGE                                   STATUS
oob-32-ollama-1       ollama/ollama:0.1.33                    Up 2 minutes
oob-32-open-webui-1   ghcr.io/open-webui/open-webui:v0.6.33   Up 2 minutes (healthy)
```

`(healthy)` on Open WebUI means the internal HTTP health check passed. The application is running and ready to accept connections.

---

## Finding 1: Zero Auth on Ollama Port 11434

Before touching Open WebUI, verify the Ollama attack surface from the jump box. No credentials. No headers. Just curl.

```bash
curl -s http://192.168.100.244:11434/api/tags | python3 -m json.tool
```

```json
{
    "models": []
}
```

Empty model list, full API access, zero authentication required, from a machine on a different network segment. This is the finding -- not the empty list, but the fact that the request worked at all.

Port 11434 responds to anyone who can reach it. No API key, no token, no credentials of any kind. The Ollama management API is completely open. You can enumerate models, pull new ones, delete existing ones, modify system prompts, or trigger inference without a single credential.

That is the 3.1B episode. But it is sitting right here in the 3.2A build, visible before we have done anything interesting.

---

## Pulling the Model (Unauthenticated, From the Jump Box)

The model gets pulled from the jump box. Not from the NUC. From a different machine, across the network, with no credentials.

```bash
curl -s http://192.168.100.244:11434/api/pull \
  -d '{"name":"tinyllama:1.1b"}' | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'status' in d: print(d['status'])
    except: pass
"
```

The pull endpoint streams newline-delimited JSON -- each status update is its own object on its own line. The python one-liner reads each line, parses it, and prints the status field. The `try/except` catches partial chunks that arrive mid-stream before the line terminator. Output ends with:

```
verifying sha256 digest
writing manifest
removing any unused layers
success
```

Note the `verifying sha256 digest` line. Ollama checks the hash of what it downloaded. This matters in Episode 3.5B -- the supply chain episode -- where we look at what Modelscan catches that Ollama's hash check does not. They are different checks that catch different problems.

---

## Creating the Admin Account

Open `http://192.168.100.244:3000` in a browser.

Open WebUI detects that no accounts exist and presents a "Create Admin Account" form. The first account registered is automatically the administrator -- there is no option to make it anything else. Fill in the form, click the button, and the page redirects to the main chat interface.

A banner appears in the bottom right corner: *"A new version (v0.8.12) is now available."* Ignore it. Do not update. That notification is a camera moment for the episode -- the gap between what is running and what is available is precisely the gap that makes 3.2B possible.

---

## Configuring the Admin Panel

Navigate to `http://192.168.100.244:3000/admin/settings/general`.

A few settings on this page are worth understanding before toggling anything.

**Enable New Sign Ups** is off by default after the first account is created. Leave it off.

**Enable API Key** should be on (green). API keys are independent credentials tied to user accounts. They survive password resets. They are the mechanism for the persistent backdoor in 3.2B Step 8. The fact that this is on by default and exposed to any unauthenticated caller via `/api/config` is one of the findings documented in the break episode.

**JWT Expiration** defaults to `-1` -- tokens never expire. A stolen JWT stays valid indefinitely. This is why the account takeover step in 3.2B has no clock on it.

Now go to **Connections** (`http://192.168.100.244:3000/admin/settings/connections`).

Two things to configure here. First, toggle **Direct Connections** on and save. Direct Connections allows any user to add an external OpenAI-compatible model server as a model source. In v0.6.33, that external server's SSE stream gets processed by the browser with no validation of what it contains. That is the CVE-2025-64496 entry point.

Second, add the desktop GPU as a second Ollama backend. Click **+** next to **Manage Ollama API Connections** and add:

```
http://192.168.38.215:11434
```

The desktop runs Ollama 0.17.7 on an RTX 3080 Ti -- around 699 tok/sec versus the NUC's 6 tok/sec on CPU. The NUC stays at 0.1.33 because it is the attack target. The desktop runs current stable because it is the inference backend for demos where you actually want responses this decade.

After saving, both backends are registered:

```
http://ollama:11434            (NUC, local, CPU)
http://192.168.38.215:11434    (desktop, external, GPU)
```

Models from both backends merge in the selector. `tinyllama:1.1b` exists on both, so Open WebUI shows it once and can route to either. `qwen2.5:0.5b`, which only exists on the desktop, shows up as a unique model from the external connection.

---

## Creating the Victim Account

The second account -- `victim@lab.local` -- has to be created through the API. Signup is off, so the registration form is gone. The admin creates accounts programmatically.

This is where we learn something about the Open WebUI router architecture that is not documented anywhere obvious.

From the jump box, get the admin token first:

```bash
export ADMIN_PASS="your_admin_password"

ADMIN_TOKEN=$(curl -s -X POST http://192.168.100.244:3000/api/v1/auths/signin \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"oob@localhost\",\"password\":\"$ADMIN_PASS\"}" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

echo $ADMIN_TOKEN
```

You get back a long `eyJ...` string. That is a JWT -- a base64-encoded credential that proves your identity to the server. Open WebUI stores it in `localStorage` in the browser. It is also what gets stolen in 3.2B Step 3. Store it in the variable and move on.

Now create the victim:

```bash
curl -s -X POST http://192.168.100.244:3000/api/v1/auths/add \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Victim",
    "email": "victim@lab.local",
    "password": "Victim1234!",
    "role": "user"
  }' | python3 -m json.tool
```

The endpoint is `/api/v1/auths/add`. Not `/api/v1/auths/signup`. Not `/api/v1/users/create`. Those both exist and both return errors -- `403` and `Method Not Allowed` respectively. The correct path for admin-created user accounts is `/auths/add`, and you find it by reading the source rather than guessing.

```bash
docker exec oob-32-open-webui-1 grep -n "router.post" \
  /app/backend/open_webui/routers/auths.py | head -20
```

```
464:@router.post("/signin", ...)
565:@router.post("/signup", ...)
747:@router.post("/add", ...)
1037:@router.post("/api_key", ...)
```

Line 747. This is a pattern used throughout the series -- when the API does something unexpected, read the source before assuming it is broken. The router file is the ground truth.

The response includes the victim's user ID:

```json
{
    "id": "69b5a39f-3c59-4616-9a2f-6f3a782f2e6f",
    "email": "victim@lab.local",
    "name": "Victim",
    "role": "user"
}
```

Write down that UUID. It is the payload for the admin JWT forgery in 3.2B Step 10.

---

## The Workspace Tools Problem

After creating the victim account, verify the permissions:

```bash
VICTIM_TOKEN=$(curl -s -X POST http://192.168.100.244:3000/api/v1/auths/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@lab.local","password":"Victim1234!"}' | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

curl -s http://192.168.100.244:3000/api/v1/auths/ \
  -H "Authorization: Bearer $VICTIM_TOKEN" | \
  python3 -c "import json,sys; d=json.load(sys.stdin); \
    print(d['permissions']['workspace'])"
```

```python
{'models': False, 'knowledge': False, 'prompts': False, 'tools': False}
```

`workspace.tools: False`. This is a problem.

The 3.2B RCE chain requires the victim account to be able to create tools. Tools are Python functions that run on the Open WebUI backend server -- no sandbox, no restrictions, running as whatever user the container runs as (root, by default). If `workspace.tools` is false, the stolen JWT cannot be escalated to code execution. The attack chain stops at data theft.

The Admin UI edit dialog for individual users only shows role, name, email, and password -- no permission toggles. There is no `permissions` column in the `user` table. There is no dedicated permissions table in the database at all. Permissions in v0.6.33 are computed at runtime from a config variable called `USER_PERMISSIONS`, which is sourced from the environment:

```bash
docker exec oob-32-open-webui-1 grep -n "USER_PERMISSIONS_WORKSPACE_TOOLS" \
  /app/backend/open_webui/config.py
```

```python
1214: USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS = (
1215:     os.environ.get("USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS", "False").lower() == "true"
```

Default is `False`. Override with an environment variable. That is why `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=true` is in the compose file -- it is not optional, it is what makes the RCE step possible.

> **Lab configuration only.** This setting intentionally enables a permission that allows arbitrary code execution on the server backend. Do not apply it to any production or shared system.

After adding it and restarting:

```bash
docker compose up -d --force-recreate
```

```python
{'models': False, 'knowledge': False, 'prompts': False, 'tools': True}
```

`tools: True`. The attack chain is intact.

The `--force-recreate` flag is required here. Without it, Docker sees no image change and skips the container rebuild. The new env var never gets picked up. Volumes survive, the database survives, only the containers are recreated.

---

## Finding 2: The Unauthenticated Reconnaissance Gift

One final check from the jump box, no credentials required:

```bash
curl -s http://192.168.100.244:3000/api/config | python3 -m json.tool
```

```json
{
    "status": true,
    "name": "Open WebUI",
    "version": "0.6.33",
    "features": {
        "auth": true,
        "enable_api_key": true,
        "enable_signup": false,
        "enable_login_form": true,
        "enable_websocket": true,
        "enable_version_update_check": true
    }
}
```

No token. No credentials. Just an open HTTP request to a publicly documented endpoint.

A scanner that hits this knows: version 0.6.33 is below the CVE-2025-64496 patch threshold of 0.6.35. `enable_api_key: true` means there is a persistent credential mechanism available post-compromise. Signup is off, meaning this is a configured deployment, not an abandoned test install. Auth is on, meaning there is a session layer to attack.

That is the full intelligence picture before the attacker has done anything. One GET request.

This is Finding 6 in the 3.2B report -- LOW severity, version fingerprinting -- but it is worth sitting with. Defenders assume that because authentication is required to *do* anything, an attacker cannot *learn* anything without credentials. The `/api/config` endpoint is a clean counterexample. It is not a bug, it is a feature that happens to tell an attacker exactly what exploit to reach for.

---

## Verifying the Full Chain

End-to-end inference through Open WebUI, routed to the desktop GPU:

```bash
curl -s http://192.168.100.244:3000/api/chat/completions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"qwen2.5:0.5b",
    "messages":[{"role":"user","content":"Say hello in one sentence"}],
    "stream":false
  }' | \
  python3 -c "import json,sys; d=json.load(sys.stdin); \
    print(d['choices'][0]['message']['content'])"
```

```
Hello! How can I assist you today?
```

Jump box to Open WebUI on the NUC to Ollama on the desktop RTX 3080 Ti and back. Full chain confirmed.

---

## Build State Summary

| Item | Value |
|---|---|
| Target IP | 192.168.100.244 |
| Ollama | 0.1.33, port 11434, zero auth |
| Open WebUI | v0.6.33, port 3000, auth on |
| Ollama backend 1 | `http://ollama:11434` (NUC, CPU) |
| Ollama backend 2 | `http://192.168.38.215:11434` (desktop, GPU) |
| Admin account | `oob@localhost` |
| Victim account | `victim@lab.local` |
| Victim user ID | `69b5a39f-3c59-4616-9a2f-6f3a782f2e6f` *(lab-generated, not a real credential)* |
| workspace.tools | True |
| Direct Connections | On |
| JWT Expiration | 1h |
| enable_api_key | True |

Everything is in the wrong configuration for the right reasons. The stack is running exactly the way most organizations deploy it -- auth on the front door, nothing behind it, and a permission model that assumes every user is a trusted developer working alone.

---

## Gotchas Reference

For anyone reproducing this build, here is every place we hit a wall.

**`ENABLE_SIGNUP=false` in compose blocks the first admin registration.** In v0.6.33 this flag applies to all signups including the initial admin. The form silently returns `403`. Omit it from compose and disable signup through the Admin UI after the admin account exists.

**`OLLAMA_BASE_URL=localhost` silently fails.** `localhost` inside the Open WebUI container refers to the container itself, not the host or the Ollama container. Docker's internal DNS resolves the service name `ollama` correctly. Use the service name.

**`/opt` requires `sudo` on a fresh Debian install.** `sudo mkdir -p /opt/oob-3.2 && sudo chown oob:oob /opt/oob-3.2` before trying to write anything there.

**Victim account creation uses `/api/v1/auths/add`, not `/signup` or `/users/create`.** Found by grepping the router source inside the running container. The other paths return `Method Not Allowed` and `403` respectively.

**`workspace.tools` defaults to False.** Not stored in the database. Set via the `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=true` environment variable in the compose file. Required for the 3.2B RCE chain.

**`docker compose up -d` will not pick up new env vars without `--force-recreate`.** If you add an environment variable and restart without the flag, Docker skips the container rebuild and the change never takes effect.

**Admin tokens expire after 1h.** If API commands start returning `Not authenticated` mid-session, the token expired. Re-run the signin command to get a fresh one. The victim token does not include an expiration when created via `/auths/add`, but does when obtained via `/auths/signin` due to the JWT expiration setting.

---

## Frequently Asked Questions

<!-- FAQ structured data: answers are indexed by search engines and AI answer engines.
     Each question/answer pair is designed to be self-contained and extractable. -->

**Why are Ollama 0.1.33 and Open WebUI v0.6.33 specifically used for this lab?**
These versions are pinned deliberately. Ollama 0.1.33 is below the authentication patch threshold and matches versions found running on 14,000+ zero-auth exposed instances in the wild as of January 2026. Open WebUI v0.6.33 is one version below the CVE-2025-64496 patch, which shipped in v0.6.35. Both are intentional -- the goal is a reproducible, documented attack chain, not a current production deployment.

**Can I use newer versions of Ollama and Open WebUI for testing?**
You can deploy newer versions, but the CVE-2025-64496 attack chain documented in Episode 3.2B will not work against patched versions. Ollama 0.7.0+ adds authentication options. Open WebUI v0.6.35+ blocks SSE execute events from Direct Connection servers. If you want to reproduce the full 3.2B chain, use the pinned versions.

**Why does `workspace.tools` default to False in Open WebUI v0.6.33?**
It is a security default. In a properly deployed multi-user environment, regular users probably should not have the ability to run arbitrary Python code on the server backend. The problem is that "properly deployed" and "how most people actually deploy it" are different things -- and the default permission set is what ships to everyone. The 3.2B episode explores what happens when that default is enabled, either intentionally or because an admin changed it for convenience.

**How do you set `workspace.tools` to True for a user in Open WebUI v0.6.33?**
In v0.6.33, workspace permissions are not stored in the database and cannot be set through the Admin UI's individual user edit dialog. They are computed at runtime from the `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS` environment variable. Set it to `true` in `docker-compose.yml` and restart with `docker compose up -d --force-recreate`. This sets the default for all user-role accounts.

**Why is `ENABLE_SIGNUP=false` not in the compose file?**
In Open WebUI v0.6.33, `ENABLE_SIGNUP=false` blocks all signups including the very first admin account registration. The form accepts your input, posts to `/api/v1/auths/signup`, gets a `403` back, and shows no explanation. The correct approach for this version is to omit the flag from compose and disable signup through Admin Settings after the admin account exists.

**What is the correct API endpoint to create users in Open WebUI when signup is disabled?**
`POST /api/v1/auths/add` with an admin Bearer token. Not `/api/v1/auths/signup` (returns 403 when signup is disabled) and not `/api/v1/users/create` (returns Method Not Allowed). This is found by reading the router source: `grep -n "router.post" /app/backend/open_webui/routers/auths.py`.

**Why is the JWT expiration set to 1h instead of -1 (never expire)?**
Personal preference for this lab deployment -- it enforces re-authentication discipline closer to how a real deployment should behave. The 3.2B attack chain runs within a single hour-long session. If you need tokens to survive across multiple lab days, set JWT Expiration to `-1` in Admin Settings. The Open WebUI default is `-1` (never expire), which is the more dangerous configuration and the one documented as a finding in 3.2B.

**What is the difference between the NUC Ollama and the desktop Ollama in this lab?**
The NUC at 192.168.100.244 runs Ollama 0.1.33 -- it is the intentionally vulnerable attack target. The desktop at 192.168.38.215 runs Ollama 0.17.7 with an RTX 3080 Ti GPU at approximately 699 tok/sec -- it is the fast inference backend for demos. Do not run attack commands against the desktop. It is not the target and is not running vulnerable software.

---

## Key Takeaways

For search engines, AI answer engines, and anyone skimming before they commit to the full read:

- **Ollama 0.1.33 has zero authentication on all management API endpoints** -- any host that can reach port 11434 can enumerate models, pull new ones, delete existing ones, and trigger inference without credentials.
- **Open WebUI v0.6.33 is below the CVE-2025-64496 patch threshold** -- SSE execute events from Direct Connection servers are not validated, enabling JavaScript execution in the victim's browser.
- **`ENABLE_SIGNUP=false` in compose breaks the first admin registration** in v0.6.33. Omit it. Disable signup through the Admin UI after the admin account exists.
- **`OLLAMA_BASE_URL=localhost` silently fails inside Docker** -- use the service name `ollama`, not localhost or an IP.
- **Victim account creation requires `/api/v1/auths/add`** -- not `/signup` or `/users/create`. Found by reading the router source inside the running container.
- **`workspace.tools` defaults to False** and is not stored in the database -- set it via `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=true` in the compose environment block.
- **`docker compose up -d` will not pick up new environment variables without `--force-recreate`.**
- **`/api/config` exposes the Open WebUI version unauthenticated** -- a scanner can confirm CVE-2025-64496 exposure in a single GET request.

---

## What Comes Next

The 3.2A build episode exists because the attack does not make sense without context. Knowing that Open WebUI runs as root inside the container, that API keys survive password resets, that the JWT signing secret lives in `/proc/1/environ` -- none of that lands unless you have watched the stack get built and understand why those things are the way they are.

Episode 3.2B picks up from exactly this state. The malicious model server goes up on the jump box. The admin adds it as a Direct Connection. The victim selects `gpt-4o-free` from the model selector, types "Hello," and an SSE execute event fires in their browser before the first token of the response renders.

What happens after that is documented at the link below.

---

*[Continue to Episode 3.2B -- I Broke Into an AI Chatbot Using a Fake Model. Here's Exactly How.](https://oobskulden.com/2026/03/i-broke-into-an-ai-chatbot-using-a-fake-model.-heres-exactly-how./)*

---

## References

| Source | Reference |
|---|---|
| CVE-2025-64496 -- Open WebUI SSE code injection | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-64496) / [Cato CTRL Advisory](https://github.com/advisories/GHSA-qrh3-gqm6-8qq6) |
| SentinelOne/Censys -- 175K exposed Ollama instances, 14K+ zero-auth (Jan 2026) | [SentinelOne Labs](https://www.sentinelone.com/labs/the-shadow-ai-threat/) |
| Open WebUI releases | [GitHub](https://github.com/open-webui/open-webui/releases) |
| Ollama releases | [GitHub](https://github.com/ollama/ollama/releases) |
| Docker install on Debian | [Docker Docs](https://docs.docker.com/engine/install/debian/) |

---

*All testing was performed against infrastructure owned and operated by the author in a private lab environment. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (18 U.S.C. &sect; 1030) and equivalent laws in other jurisdictions. This content is provided for educational and defensive security research purposes only.*

*This content represents personal educational work conducted in a home lab environment on personal equipment. It does not reflect the views, opinions, or positions of any employer or affiliated organization.*

*&copy; 2026 Oob Skulden&trade; | AI Infrastructure Security Series | Episode 3.2A*
