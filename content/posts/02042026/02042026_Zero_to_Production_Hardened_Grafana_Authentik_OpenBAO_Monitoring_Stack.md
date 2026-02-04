---
title: "Zero to Production-Hardened: Grafana + Authentik + OpenBAO Monitoring Stack"
date: 2026-02-04T18:00:00-06:00
draft: false
author: "Oob Skulden™"
description: "A complete 6-phase guide to deploying and hardening a Grafana monitoring stack with Authentik SSO, OpenBAO secrets management, and HAProxy TLS termination — from first docker-compose up to audit-ready, with every security gap documented and fixed."
tags:
  - Security
  - AppSec
  - DevSecOps
  - Monitoring
  - Container Security
  - Secrets Management
  - OAuth2
  - SSO
  - TLS
  - Compliance
  - Homelab
  - Docker
  - Infrastructure as Code
categories:
  - Security
  - Engineering
  - Homelab
# keywords:
#  - grafana security hardening
#  - authentik oauth2 tutorial
#  - openbao secrets management
#  - production monitoring stack
#  - docker container hardening
#  - homelab security hardening
#  - grafana authentik integration
#  - tls certificate automation
#  - nist 800-53 compliance mapping
#  - soc 2 monitoring setup
#  - cis controls homelab
#  - prometheus authentication
#  - haproxy tls termination
#  - zero trust monitoring
#  - container security best practices
#  - oauth2 sso grafana
#  - session hardening grafana
#  - pki certificate management homelab
#  - open source siem stack
#  - defense in depth monitoring
showToc: false
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
---

# Zero to Production-Hardened: Grafana + Authentik + OpenBAO Monitoring Stack

**Published by Oob Skulden™**  
*"Stay paranoid."*

> **Disclaimer:** This guide is independent educational content created on personal time using personal equipment in a personal homelab environment. It is not affiliated with, endorsed by, or representative of any employer or organization. All tools demonstrated are open-source and publicly available. All compliance references cite publicly published frameworks. Readers are solely responsible for ensuring they have proper authorization before applying any techniques described here to systems they access or manage.

---

## Why This Guide Exists

Most Grafana deployment guides end the moment the login page loads. "It works!" and they move on.

That's where the problems start.

I built this monitoring stack in my homelab, got everything running, and then started asking the uncomfortable questions. What happens when I disable a user in Authentik? Does their Grafana session actually die? (Spoiler: it didn't. It survived for days.) What can someone see if they hit Prometheus directly? (Everything. Every host, every service, every version number, completely unauthenticated.) Where's the OAuth client secret? (Sitting in plaintext inside the container, one `docker inspect` away.)

The deployment took a couple hours. Fixing all of that took a few more.

This guide covers the entire journey — from first `docker-compose up` to a stack you'd actually feel okay putting in front of an auditor. Every mistake I made is documented, every dead end is explained, and every fix includes the "why" alongside the "how."

## What You're Building

The stack runs across three VMs on separate VLANs: Grafana and Prometheus for monitoring, Authentik for identity and SSO, and OpenBAO for secrets management and PKI. HAProxy sits in front of Grafana handling TLS termination, security headers, and rate limiting.

By the end, you'll have OAuth2 SSO with group-based role mapping, TLS everywhere with automated certificate renewal, secrets pulled dynamically from OpenBAO at container startup (nothing hardcoded), containers locked down to four Linux capabilities, aggressive session timeouts, audit logging, and the whole thing mapped to NIST 800-53, SOC 2, and CIS Controls because compliance people like tables.

**Total time:** Around 5-8 hours (2-3h deployment, 3-5h hardening).  
**Environment:** Multi-VLAN homelab on Debian 13, Proxmox VE 8.x.

---

## Table of Contents

### Part 1: Initial Deployment (Baseline Functional)

1. [Infrastructure Prerequisites](#infrastructure-prerequisites)
2. [Deploy Authentik](#deploy-authentik)
3. [Deploy OpenBAO](#deploy-openbao)
4. [Deploy Grafana Stack](#deploy-grafana-stack)
5. [Configure OAuth Integration](#configure-oauth)
6. [Initial Validation](#initial-validation)

### Part 2: Security Hardening (Baseline → Production-Hardened)

7. [Phase 1: Session Hardening](#phase-1-sessions)
8. [Phase 2: TLS Encryption](#phase-2-tls)
9. [Phase 3: Prometheus Authentication](#phase-3-prometheus)
10. [Phase 4: Secrets Management](#phase-4-secrets)
11. [Phase 5: Container Hardening](#phase-5-containers)
12. [Phase 6: Production Readiness](#phase-6-production)

### Part 3: Operations

13. [Final Security Posture](#final-posture)
14. [Deployment Checklist](#deployment-checklist)
15. [Maintenance Procedures](#maintenance)
16. [Troubleshooting Guide](#troubleshooting)

---

## Part 1: Initial Deployment

<a name="infrastructure-prerequisites"></a>
## 1. Infrastructure Prerequisites

### Hardware Requirements

**Three Virtual Machines (Proxmox VE 8.x):**

| VM | IP | VLAN | CPU | RAM | Disk | Purpose |
|----|-----|------|-----|-----|------|---------|
| Authentik | 10.10.80.10 | 80 | 2 vCPU | 4GB | 32GB | Identity/OAuth |
| OpenBAO | 10.10.100.10 | 100 | 2 vCPU | 2GB | 20GB | Secrets/PKI |
| Grafana-lab | 10.10.75.10 | 75 | 2 vCPU | 4GB | 32GB | Monitoring |

### Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ VLAN 75: Monitoring Network (10.10.75.0/24)              │
│  Grafana-lab (10.10.75.10)                                │
│  ├── Grafana:3000                                           │
│  ├── Prometheus:9090                                        │
│  ├── Blackbox Exporter:9115                                 │
│  ├── Node Exporter:9100                                     │
│  └── cAdvisor:8080                                          │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ OAuth2/OIDC Flow
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ VLAN 80: Identity & Access (10.10.80.0/24)               │
│  Authentik (10.10.80.10)                                  │
│  ├── Authentik Server:9000                                  │
│  ├── PostgreSQL:5432 (internal)                             │
│  └── Redis:6379 (internal)                                  │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ Secrets + PKI Certificates
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ VLAN 100: Secrets Management (10.10.100.0/24)            │
│  OpenBAO (10.10.100.10)                                  │
│  ├── OpenBAO:8200                                           │
│  ├── KV Secrets Engine v2                                   │
│  ├── PKI Engine (internal CA)                               │
│  └── AppRole Authentication                                 │
└─────────────────────────────────────────────────────────────┘
```

### Software Prerequisites

**On ALL three hosts:**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
sudo apt install -y docker.io docker-compose

# Start and enable Docker
sudo systemctl enable docker
sudo systemctl start docker

# Verify installation
docker --version
docker-compose --version

# Install utilities
sudo apt install -y curl wget jq net-tools openssl apache2-utils

# Optional: Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in for this to take effect
```

### Firewall Configuration

**If using UniFi or similar:**

```
Rule: Authentik_OAuth_Access
  Source: 10.10.75.10 (Grafana)
  Destination: 10.10.80.10:9000 (Authentik)
  Protocol: TCP
  Action: Allow

Rule: OpenBAO_Secrets_Access
  Source: 10.10.75.10 (Grafana)
  Destination: 10.10.100.10:8200 (OpenBAO)
  Protocol: TCP
  Action: Allow

Rule: OpenBAO_PKI_Access
  Source: 10.10.75.10 (Grafana)
  Destination: 10.10.100.10:8200 (OpenBAO)
  Protocol: TCP
  Action: Allow
```

---

<a name="deploy-authentik"></a>
## 2. Deploy Authentik

**On Authentik host (10.10.80.10):**

### Step 1: Create Directory Structure

```bash
mkdir -p ~/authentik/{media,certs,custom-templates}
cd ~/authentik
```

### Step 2: Generate Secure Secrets

```bash
# PostgreSQL password (alphanumeric only)
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9')
echo "PostgreSQL Password: $POSTGRES_PASSWORD"

# Authentik secret key (alphanumeric only)
AUTHENTIK_SECRET_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9')
echo "Authentik Secret Key: $AUTHENTIK_SECRET_KEY"

# SAVE THESE IN PASSWORD MANAGER IMMEDIATELY
```

### Step 3: Create Environment File

```bash
cat > .env << EOF
# PostgreSQL Configuration
POSTGRES_DB=authentik
POSTGRES_USER=authentik
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# Redis Configuration
REDIS_HOST=redis

# Authentik Configuration
AUTHENTIK_SECRET_KEY=$AUTHENTIK_SECRET_KEY
AUTHENTIK_ERROR_REPORTING__ENABLED=false
AUTHENTIK_LOG_LEVEL=info
AUTHENTIK_COOKIE_DOMAIN=10.10.80.10
EOF

chmod 600 .env
```

### Step 4: Create Docker Compose File

```bash
cat > docker-compose.yml << 'EOF'
version: '3.7'

services:
  postgresql:
    image: postgres:16-alpine
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d $${POSTGRES_DB} -U $${POSTGRES_USER}"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 5s
    volumes:
      - database:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_USER: ${POSTGRES_USER:-authentik}
      POSTGRES_DB: ${POSTGRES_DB:-authentik}
    networks:
      - authentik_network

  redis:
    image: redis:alpine
    command: --save 60 1 --loglevel warning
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep PONG"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 3s
    volumes:
      - redis:/data
    networks:
      - authentik_network

  server:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: server
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: ${POSTGRES_USER:-authentik}
      AUTHENTIK_POSTGRESQL__NAME: ${POSTGRES_DB:-authentik}
      AUTHENTIK_POSTGRESQL__PASSWORD: ${POSTGRES_PASSWORD}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_ERROR_REPORTING__ENABLED: ${AUTHENTIK_ERROR_REPORTING__ENABLED:-false}
      AUTHENTIK_LOG_LEVEL: ${AUTHENTIK_LOG_LEVEL:-info}
      AUTHENTIK_COOKIE_DOMAIN: ${AUTHENTIK_COOKIE_DOMAIN}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    ports:
      - "9000:9000"
      - "9443:9443"
    depends_on:
      - postgresql
      - redis
    networks:
      - authentik_network

  worker:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: ${POSTGRES_USER:-authentik}
      AUTHENTIK_POSTGRESQL__NAME: ${POSTGRES_DB:-authentik}
      AUTHENTIK_POSTGRESQL__PASSWORD: ${POSTGRES_PASSWORD}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_ERROR_REPORTING__ENABLED: ${AUTHENTIK_ERROR_REPORTING__ENABLED:-false}
      AUTHENTIK_LOG_LEVEL: ${AUTHENTIK_LOG_LEVEL:-info}
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./media:/media
      - ./certs:/certs
      - ./custom-templates:/templates
    depends_on:
      - postgresql
      - redis
    networks:
      - authentik_network

volumes:
  database:
  redis:

networks:
  authentik_network:
    driver: bridge
EOF
```

### Step 5: Deploy Authentik

```bash
# Validate configuration
docker-compose config

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Step 6: Create Initial Admin Account

```bash
# Wait for services to be healthy (30-60 seconds)
sleep 60

# Create admin user
docker-compose exec server ak create_admin_user \
  --username akadmin \
  --email admin@example.com \
  --password YourStrongPasswordHere

# Verify
docker-compose logs server | grep "Created user"
```

### Step 7: Access Authentik Web UI

```
Browser: http://10.10.80.10:9000
Username: akadmin
Password: YourStrongPasswordHere
```

**Initial setup wizard:**
1. Set display name
2. Configure default tenant
3. Skip email for now (configure later)
4. Complete setup

---

<a name="deploy-openbao"></a>
## 3. Deploy OpenBAO

**On OpenBAO host (10.10.100.10):**

### Step 1: Create Directory Structure

```bash
mkdir -p ~/openbao/{config,data,logs}
cd ~/openbao
```

### Step 2: Create OpenBAO Configuration

```bash
cat > config/openbao.hcl << 'EOF'
# Published by Oob Skulden™

storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://10.10.100.10:8200"
ui = true
EOF
```

### Step 3: Create Docker Compose File

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  openbao:
    image: openbao/openbao:latest
    container_name: openbao
    restart: unless-stopped
    ports:
      - "8200:8200"
    volumes:
      - ./config:/openbao/config:ro
      - ./data:/openbao/data
      - ./logs:/openbao/logs
    cap_add:
      - IPC_LOCK
    command: server
    environment:
      - BAO_ADDR=http://0.0.0.0:8200
    networks:
      - openbao_network

networks:
  openbao_network:
    driver: bridge
EOF
```

### Step 4: Deploy OpenBAO

```bash
# Start container
docker-compose up -d

# Verify running
docker-compose ps

# View logs
docker-compose logs -f openbao
```

### Step 5: Initialize OpenBAO

```bash
# Access container
docker exec -it openbao sh

# Set environment
export BAO_ADDR='http://127.0.0.1:8200'

# Initialize (save output!)
bao operator init

# Output will look like:
# Unseal Key 1: base64encodedkey1
# Unseal Key 2: base64encodedkey2
# Unseal Key 3: base64encodedkey3
# Unseal Key 4: base64encodedkey4
# Unseal Key 5: base64encodedkey5
# 
# Initial Root Token: s.YourRootTokenHere

# CRITICAL: Save these immediately in password manager!
```

### Step 6: Unseal OpenBAO

```bash
# Still in container shell
# Unseal with 3 of 5 keys (default threshold)

bao operator unseal [Unseal Key 1]
bao operator unseal [Unseal Key 2]
bao operator unseal [Unseal Key 3]

# Verify unsealed
bao status
# Sealed: false ✓
```

### Step 7: Enable Secrets Engines

```bash
# Login with root token
bao login s.YourRootTokenHere

# Enable KV v2 secrets engine
bao secrets enable -version=2 -path=secret kv

# Enable PKI engine
bao secrets enable pki

# Configure PKI
bao secrets tune -max-lease-ttl=87600h pki

# Generate root CA
bao write -field=certificate pki/root/generate/internal \
  common_name="OpenBAO Root CA" \
  ttl=87600h > /tmp/ca_cert.crt

# Configure URLs
bao write pki/config/urls \
  issuing_certificates="http://10.10.100.10:8200/v1/pki/ca" \
  crl_distribution_points="http://10.10.100.10:8200/v1/pki/crl"

# Create role for Grafana certificates
bao write pki/roles/grafana-server \
  allowed_domains="10.10.75.10" \
  allow_bare_domains=true \
  allow_ip_sans=true \
  max_ttl=720h \
  require_cn=false

# Test certificate issuance
bao write pki/issue/grafana-server \
  common_name="10.10.75.10" \
  ip_sans="10.10.75.10" \
  ttl="720h"
```

### Step 8: Enable AppRole Authentication

```bash
# Still logged in as root

# Enable AppRole auth method
bao auth enable approle

# Create policy for Grafana secrets
cat > /tmp/grafana-policy.hcl << 'POLICY'
path "secret/data/grafana/*" {
  capabilities = ["read"]
}

path "secret/metadata/grafana/*" {
  capabilities = ["read", "list"]
}
POLICY

bao policy write grafana-policy /tmp/grafana-policy.hcl

# Create AppRole
bao write auth/approle/role/grafana \
  token_policies="grafana-policy" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0 \
  secret_id_num_uses=0

# Get role_id (save this)
bao read auth/approle/role/grafana/role-id
# role_id: <your-grafana-role-id>

# Generate secret_id (save this)
bao write -f auth/approle/role/grafana/secret-id
# secret_id: <your-grafana-secret-id>

# Exit container
exit
```

**Save these credentials securely - you'll need them for Grafana deployment.**

---

<a name="deploy-grafana-stack"></a>
## 4. Deploy Grafana Stack

**On Grafana-lab host (10.10.75.10):**

### Step 1: Create Directory Structure

```bash
mkdir -p ~/monitoring/{grafana,prometheus}
cd ~/monitoring
```

### Step 2: Create Grafana Entrypoint Script

This script retrieves the OAuth secret from OpenBAO at container startup:

```bash
cat > grafana/entrypoint.sh << 'EOF'
#!/usr/bin/with-contenv bash
# Grafana Dynamic Secret Injection
# Published by Oob Skulden™

set -e

# AppRole credentials from environment
ROLE_ID="${BAO_ROLE_ID}"
SECRET_ID="${BAO_SECRET_ID}"
BAO_ADDR="http://10.10.100.10:8200"

echo "=== Retrieving OAuth secret from OpenBAO ==="

# Authenticate with AppRole
TOKEN_JSON=$(curl -s -X POST \
  -d "{\"role_id\":\"${ROLE_ID}\",\"secret_id\":\"${SECRET_ID}\"}" \
  ${BAO_ADDR}/v1/auth/approle/login)

TOKEN=$(echo "$TOKEN_JSON" | jq -r '.auth.client_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "ERROR: Failed to authenticate with OpenBAO"
  exit 1
fi

echo "Authenticated successfully, retrieving OAuth secret..."

# Retrieve OAuth secret
SECRET_JSON=$(curl -s -H "X-Vault-Token: ${TOKEN}" \
  ${BAO_ADDR}/v1/secret/data/grafana/oauth)

CLIENT_SECRET=$(echo "$SECRET_JSON" | jq -r '.data.data.client_secret')

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
  echo "ERROR: Failed to retrieve OAuth client secret"
  exit 1
fi

echo "Secret retrieved successfully, starting Grafana..."

# CRITICAL: exec env pattern ensures variable persists to Grafana process
exec env GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="$CLIENT_SECRET" /run.sh
EOF

chmod 755 grafana/entrypoint.sh
```

### Step 3: Create Prometheus Configuration

```bash
cat > prometheus/prometheus.yml << 'EOF'
# Prometheus Configuration
# Published by Oob Skulden™

global:
  scrape_interval: 30s
  evaluation_interval: 30s
  external_labels:
    monitor: 'grafana-lab-monitor'

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
  
  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
  
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
  
  - job_name: 'blackbox-http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - http://10.10.75.10:3000
          - http://10.10.80.10:9000
          - http://10.10.100.10:8200
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
EOF
```

### Step 4: Create Environment File

```bash
cat > .env << 'EOF'
# Grafana Admin Credentials
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=YourStrongGrafanaPassword

# OpenBAO AppRole Credentials
BAO_ROLE_ID=<your-grafana-role-id>
BAO_SECRET_ID=<your-grafana-secret-id>
EOF

chmod 600 .env
```

### Step 5: Create Docker Compose File

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    user: "0"
    entrypoint: ["/entrypoint.sh"]
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/entrypoint.sh:/entrypoint.sh:ro
    environment:
      # Admin Credentials
      - GF_SECURITY_ADMIN_USER=${GF_SECURITY_ADMIN_USER}
      - GF_SECURITY_ADMIN_PASSWORD=${GF_SECURITY_ADMIN_PASSWORD}
      
      # Server
      - GF_SERVER_ROOT_URL=http://10.10.75.10:3000
      - GF_SERVER_SERVE_FROM_SUB_PATH=false
      
      # Security
      - GF_USERS_ALLOW_SIGN_UP=false
      
      # OpenBAO AppRole (for entrypoint script)
      - BAO_ROLE_ID=${BAO_ROLE_ID}
      - BAO_SECRET_ID=${BAO_SECRET_ID}
    networks:
      - grafana_network

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    networks:
      - grafana_network
      - prometheus_network

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    container_name: blackbox-exporter
    restart: unless-stopped
    ports:
      - "9115:9115"
    networks:
      - grafana_network

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    ports:
      - "9100:9100"
    networks:
      - prometheus_network

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    networks:
      - prometheus_network

networks:
  grafana_network:
    driver: bridge
  prometheus_network:
    driver: bridge

volumes:
  grafana-data:
  prometheus-data:
EOF
```

### Step 6: Deploy Stack

```bash
# Validate configuration
docker-compose config

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View Grafana logs
docker-compose logs -f grafana
```

### Step 7: Initial Grafana Access

```
Browser: http://10.10.75.10:3000
Username: admin
Password: YourStrongGrafanaPassword
```

**You should now have:**
- Grafana login page
- Prometheus collecting metrics
- All exporters running

---

<a name="configure-oauth"></a>
## 5. Configure OAuth Integration

### Step 1: Create OAuth Provider in Authentik

**Access Authentik:** `http://10.10.80.10:9000`

1. Navigate to: **Admin Interface → Applications → Providers**
2. Click **Create** → **OAuth2/OpenID Provider**
3. Configure:
   - **Name:** `grafana-oidc-provider`
   - **Authorization flow:** `default-provider-authorization-implicit-consent`
   - **Client Type:** `Confidential`
   - **Client ID:** `grafana-client`
   - **Redirect URIs:** `http://10.10.75.10:3000/login/generic_oauth`
   - **Signing Key:** `authentik Self-signed Certificate`
   - **Subject mode:** `Based on User's UPN`
   - **Include claims in id_token:** ✅ Enabled

4. Click **Create**

### Step 2: Retrieve OAuth Client Secret

**CRITICAL:** Authentik UI truncates the displayed secret!

**Correct procedure:**
1. Click on the provider you just created
2. Click **Edit**
3. Scroll to **Client Secret**
4. Click the **eye icon** to reveal
5. Click **Copy** button (NOT selecting and copying text)
6. Paste into text editor
7. Verify it's 128 characters long

**Save this secret - you'll store it in OpenBAO next.**

### Step 3: Store OAuth Secret in OpenBAO

**On OpenBAO host:**

```bash
# Access container
docker exec -it -e BAO_ADDR='http://127.0.0.1:8200' openbao sh

# Login
bao login s.YourRootToken

# Store OAuth secret
bao kv put secret/grafana/oauth \
  client_id=grafana-client \
  client_secret=Your128CharacterSecretHere

# Verify storage
bao kv get secret/grafana/oauth

# Exit
exit
```

### Step 4: Create Authentik Application

Back in Authentik UI:

1. Navigate to: **Applications → Applications**
2. Click **Create**
3. Configure:
   - **Name:** `Grafana`
   - **Slug:** `grafana`
   - **Provider:** Select `grafana-oidc-provider`
   - **Launch URL:** `http://10.10.75.10:3000`

4. Click **Create**

### Step 5: Create Groups

1. Navigate to: **Directory → Groups**
2. Create **Grafana Admins** group:
   - Name: `Grafana Admins`
   - Parent: (none)
3. Create **Grafana Viewers** group:
   - Name: `Grafana Viewers`
   - Parent: (none)

### Step 6: Create Test Users

1. Navigate to: **Directory → Users**
2. Create admin test user:
   - Username: `alice`
   - Name: `Alice Admin`
   - Email: `alice@example.com`
   - Set password
   - Groups: Add to **Grafana Admins**

3. Create viewer test user:
   - Username: `bob`
   - Name: `Bob Viewer`
   - Email: `bob@example.com`
   - Set password
   - Groups: Add to **Grafana Viewers**

### Step 7: Configure Grafana OAuth

**On Grafana host, update docker-compose.yml:**

```yaml
services:
  grafana:
    environment:
      # ... existing environment variables ...
      
      # OAuth Configuration
      - GF_AUTH_GENERIC_OAUTH_ENABLED=true
      - GF_AUTH_GENERIC_OAUTH_NAME=Authentik
      - GF_AUTH_GENERIC_OAUTH_CLIENT_ID=grafana-client
      # CLIENT_SECRET injected by entrypoint.sh from OpenBAO
      - GF_AUTH_GENERIC_OAUTH_SCOPES=openid profile email groups
      - GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://10.10.80.10:9000/application/o/authorize/
      - GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://10.10.80.10:9000/application/o/token/
      - GF_AUTH_GENERIC_OAUTH_API_URL=http://10.10.80.10:9000/application/o/userinfo/
      - GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=contains(groups[*], 'Grafana Admins') && 'Admin' || 'Viewer'
      - GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true
      - GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN=false
```

Restart Grafana:

```bash
docker-compose up -d --force-recreate grafana
```

---

<a name="initial-validation"></a>
## 6. Initial Validation

### Test 1: Local Admin Login

```
Browser: http://10.10.75.10:3000
Username: admin
Password: YourStrongGrafanaPassword
Result: Logged in successfully ✓
```

### Test 2: OAuth Login (Admin User)

```
1. Logout from Grafana
2. Click "Sign in with Authentik"
3. Redirected to Authentik
4. Login as: alice / [password]
5. Redirected back to Grafana
6. Check user role: Admin ✓
```

### Test 3: OAuth Login (Viewer User)

```
1. Logout
2. Sign in with Authentik
3. Login as: bob / [password]
4. Check user role: Viewer ✓
```

### Test 4: Prometheus Connectivity

```
Grafana UI:
1. Go to Connections → Data Sources
2. Click "Add data source"
3. Select Prometheus
4. URL: http://prometheus:9090
5. Click "Save & test"
Result: "Data source is working" ✓
```

### Test 5: Create Test Dashboard

```
1. Create → Dashboard
2. Add visualization
3. Query: up
4. Should show all targets (prometheus, grafana, exporters)
Result: Metrics displaying ✓
```

### Current Security Posture: Baseline Functional

**What's working:**
- OAuth authentication ✓
- Group-based authorization ✓
- Metrics collection ✓
- Multi-VLAN segmentation ✓

**What's vulnerable:**
- All traffic cleartext HTTP ❌
- Sessions persist indefinitely ❌
- Prometheus unauthenticated ❌
- OAuth secret visible in container ❌
- Container running as root ❌
- No resource limits ❌

**Time to deployment:** ~2-3 hours

**Next: Part 2 - Security Hardening**

---

## Part 2: Security Hardening

<a name="phase-1-sessions"></a>
## 7. Phase 1: Session Hardening

**Goal:** Force session expiration and implement token rotation.

**Duration:** ~15 minutes

### The Problem

Testing revealed that disabling a user account in Authentik didn't immediately revoke their Grafana session. Sessions remained valid for 7+ days after account deletion - a critical security gap.

### Implementation

**Update docker-compose.yml:**

```yaml
services:
  grafana:
    environment:
      # ... existing vars ...
      
      # Phase 1: Session Hardening
      - GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=1h
      - GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h
      - GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES=10
```

**What these do:**
- `MAXIMUM_INACTIVE_LIFETIME_DURATION=1h` - Session expires after 1 hour of inactivity
- `MAXIMUM_LIFETIME_DURATION=24h` - Absolute maximum session lifetime (even if active)
- `TOKEN_ROTATION_INTERVAL_MINUTES=10` - OAuth tokens rotate every 10 minutes

**Apply changes:**

```bash
docker-compose up -d --force-recreate grafana
```

### Validation

**Test 1: Inactivity timeout**
```
1. Login to Grafana
2. Leave browser open for 65 minutes (no activity)
3. Try to navigate to dashboard
Result: Forced redirect to login page ✓
```

**Test 2: Maximum lifetime**
```
1. Login to Grafana
2. Actively use dashboards for 25 hours
Result: Session expired, forced re-login ✓
```

**Test 3: OAuth still functional**
```
1. Click "Sign in with Authentik"
2. Redirected to Authentik → back to Grafana
Result: Logged in successfully ✓
```

### What We Learned

**Initial timeout of 15 minutes was too aggressive** - users complained of constant re-authentication interrupting dashboard analysis.

**Final balance:**
- 1 hour inactivity = reasonable for analyst workflows
- 24 hour max = catches abandoned sessions
- 10 minute token rotation = limits stolen token abuse window

**Security improvement:** Sessions now have defined lifecycle, reducing unauthorized access window from days to hours.

**Security posture: Baseline Functional → Session-Controlled**

---

<a name="phase-2-tls"></a>
## 8. Phase 2: TLS Encryption

**Goal:** Eliminate cleartext HTTP traffic with TLS termination.

**Duration:** ~1-2 hours

### The Problem

All traffic was cleartext HTTP:
- Session cookies (sniffable on network)
- OAuth tokens (visible in transit)
- Dashboard data (infrastructure topology exposed)

Wireshark capture showed everything in plaintext:
```
Cookie: grafana_session=5e8d7f9a2b1c3d4e...
Authorization: Bearer eyJhbGci...
```

### Implementation

**Step 1: Issue Certificate from OpenBAO**

On OpenBAO host:

```bash
docker exec -it -e BAO_ADDR='http://127.0.0.1:8200' openbao sh

bao login s.YourRootToken

# Issue certificate
bao write -format=json pki/issue/grafana-server \
  common_name="10.10.75.10" \
  ip_sans="10.10.75.10" \
  ttl="720h" > /tmp/grafana-cert.json

# Extract components
jq -r '.data.certificate' /tmp/grafana-cert.json > /tmp/grafana.crt
jq -r '.data.private_key' /tmp/grafana-cert.json > /tmp/grafana.key
jq -r '.data.issuing_ca' /tmp/grafana-cert.json > /tmp/grafana-ca.crt

# Create HAProxy bundle (ORDER MATTERS!)
cat /tmp/grafana.crt /tmp/grafana.key /tmp/grafana-ca.crt > /tmp/grafana.pem

# Verify
openssl x509 -in /tmp/grafana.pem -noout -subject -dates

exit
```

**Step 2: Copy Certificate to Grafana Host**

```bash
# On OpenBAO host
scp /tmp/grafana.pem user@10.10.75.10:/tmp/

# On Grafana host
sudo mkdir -p /etc/haproxy/certs
sudo cp /tmp/grafana.pem /etc/haproxy/certs/
sudo chown haproxy:haproxy /etc/haproxy/certs/grafana.pem
sudo chmod 600 /etc/haproxy/certs/grafana.pem
```

**Step 3: Install HAProxy**

```bash
sudo apt update
sudo apt install haproxy -y
haproxy -v  # Should be 2.x or 3.x
```

**Step 4: Configure HAProxy**

```bash
sudo nano /etc/haproxy/haproxy.cfg
```

**Add this configuration:**

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL Configuration
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

# HTTP frontend - redirect to HTTPS
frontend http_grafana
    bind *:80
    redirect scheme https code 301

# HTTPS frontend - TLS termination
frontend https_grafana
    bind *:443 ssl crt /etc/haproxy/certs/grafana.pem
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    
    # Rate limiting: 100 requests per 10 seconds per IP
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
    
    default_backend grafana_backend

# Backend - Grafana on localhost
backend grafana_backend
    mode http
    balance roundrobin
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    server grafana 127.0.0.1:3000 check

# Stats page (localhost only!)
frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
```

**Step 5: Validate and Start HAProxy**

```bash
# Test configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Enable and start
sudo systemctl enable haproxy
sudo systemctl start haproxy

# Check status
sudo systemctl status haproxy

# Verify listening ports
sudo ss -tlnp | grep haproxy
# Should show: 80, 443, 8404 (localhost only)
```

**Step 6: Update Grafana Configuration**

```yaml
# docker-compose.yml
services:
  grafana:
    ports:
      - "127.0.0.1:3000:3000"  # Localhost only now
    environment:
      # ... existing vars ...
      
      # Update root URL to HTTPS
      - GF_SERVER_ROOT_URL=https://10.10.75.10
      
      # Enable secure cookies (only after HAProxy is working!)
      - GF_SECURITY_COOKIE_SECURE=true
```

**Step 7: Update Authentik OAuth Redirect**

In Authentik UI:

1. Navigate to: **Applications → Providers → grafana-oidc-provider → Edit**
2. Update **Redirect URIs:**
   - Remove: `http://10.10.75.10:3000/login/generic_oauth`
   - Add: `https://10.10.75.10/login/generic_oauth`
3. Save

**Step 8: Restart Grafana**

```bash
docker-compose up -d --force-recreate grafana
```

### Validation

**Test 1: HTTP redirects to HTTPS**
```bash
curl -I http://10.10.75.10
# HTTP/1.1 301 Moved Permanently
# Location: https://10.10.75.10/ ✓
```

**Test 2: TLS handshake**
```bash
openssl s_client -connect 10.10.75.10:443 -showcerts
# Verify return code: 0 (ok) ✓
```

**Test 3: Security headers**
```bash
curl -I https://10.10.75.10
# Strict-Transport-Security: max-age=31536000 ✓
# X-Frame-Options: SAMEORIGIN ✓
```

**Test 4: Rate limiting**
```bash
# Rapid requests
for i in {1..150}; do curl -s https://10.10.75.10 > /dev/null; done
# Around request 101+: HTTP 429 Too Many Requests ✓
```

**Test 5: OAuth via HTTPS**
```
Browser: https://10.10.75.10
Click "Sign in with Authentik"
Redirected to Authentik → back to Grafana
Logged in successfully ✓
```

### What We Learned

**1. Certificate order in PEM bundle is critical**

Wrong: `cat key crt ca` = HAProxy failure

Correct: `cat crt key ca` = Works

HAProxy parses sequentially: server cert → private key → CA chain.

**2. OAuth migration sequence matters**

Wrong sequence:
1. Enable secure cookies
2. Update Authentik URIs
Result: "redirect_uri_mismatch" error

Correct sequence:
1. Deploy HAProxy
2. Update Authentik URIs to HTTPS
3. Test OAuth
4. Then enable secure cookies

**3. Stats page must be localhost-only**

`bind *:8404` exposes backend status to network (information disclosure).

`bind 127.0.0.1:8404` = Access only via SSH tunnel.

**4. systemctl reload vs restart**

`restart` = Downtime (all connections dropped)

`reload` = Zero downtime:
- New workers start with new cert
- Old connections continue on old workers
- New connections use new workers
- Graceful switchover

**Security posture: Session-Controlled → Transport-Secured**

---

<a name="phase-3-prometheus"></a>
## 9. Phase 3: Prometheus Authentication

**Goal:** Prevent unauthorized infrastructure enumeration.

**Duration:** ~15 minutes

### The Problem

Prometheus exposed complete infrastructure topology without authentication:

```bash
curl http://10.10.75.10:9090/api/v1/targets | jq
# Returns: All monitored systems, software versions, network map
```

### Implementation

**Step 1: Generate Bcrypt Password**

```bash
sudo apt install apache2-utils

# Generate strong password
PROMETHEUS_PASSWORD=$(openssl rand -base64 32)
echo "Prometheus Password: $PROMETHEUS_PASSWORD"
# Save in password manager!

# Generate bcrypt hash
htpasswd -nbBC 10 prometheus "$PROMETHEUS_PASSWORD"
# Output: prometheus:$2y$10$hash...
```

**Step 2: Create Prometheus Web Config**

```bash
cat > ~/monitoring/prometheus/web-config.yml << EOF
basic_auth_users:
  prometheus: <your-bcrypt-hash-from-htpasswd>
EOF

chmod 600 ~/monitoring/prometheus/web-config.yml
```

**Step 3: Update docker-compose.yml**

```yaml
services:
  prometheus:
    ports:
      - "127.0.0.1:9090:9090"  # Localhost only
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/web-config.yml:/etc/prometheus/web-config.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--web.config.file=/etc/prometheus/web-config.yml'  # Add this
```

**Step 4: Create Grafana Datasource Provisioning**

```bash
mkdir -p ~/monitoring/grafana/provisioning/datasources

cat > ~/monitoring/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    basicAuth: true
    basicAuthUser: prometheus
    secureJsonData:
      basicAuthPassword: \${PROMETHEUS_PASSWORD}
    jsonData:
      httpMethod: POST
      timeInterval: 30s
EOF
```

**Step 5: Update .env file**

```bash
# Add to ~/monitoring/.env
PROMETHEUS_PASSWORD=YourGeneratedPasswordHere
```

**Step 6: Update docker-compose.yml to mount provisioning**

```yaml
services:
  grafana:
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/entrypoint.sh:/entrypoint.sh:ro
      - ./grafana/provisioning:/etc/grafana/provisioning:ro  # Add this
```

**Step 7: Restart Stack**

```bash
docker-compose down
docker-compose up -d
```

### Validation

**Test 1: Unauthenticated access blocked**
```bash
curl http://localhost:9090/metrics
# 401 Unauthorized ✓
```

**Test 2: Authenticated access works**
```bash
curl -u prometheus:$PROMETHEUS_PASSWORD http://localhost:9090/metrics
# Returns metrics ✓
```

**Test 3: Grafana queries work**
```
Grafana UI → Explore
Query: up
Result: Shows all targets ✓
```

**Test 4: External access blocked**
```bash
# From different machine
curl http://10.10.75.10:9090
# Connection refused ✓
```

### What We Learned

**1. Localhost binding = defense-in-depth**

Even with auth, `0.0.0.0:9090` exposes service to network scanners.

`127.0.0.1:9090` = Network can't reach it at all.

**2. Provisioned datasources prevent credential leakage**

Manual datasource in UI → password visible in dashboard JSON export.

Provisioned with `secureJsonData` → password encrypted, never exported.

**Security posture: Transport-Secured → Access-Controlled**

---

<a name="phase-4-secrets"></a>
## 10. Phase 4: Secrets Management

**Goal:** Eliminate all hardcoded secrets.

**Duration:** ~30 minutes

### The Problem

Secrets still visible:

```bash
docker compose config  # Shows all environment variables
docker inspect grafana  # "Env": ["PASSWORD=..."]
```

### Implementation

**Already implemented in initial deployment:**

The entrypoint.sh script retrieves OAuth secret from OpenBAO at startup using AppRole authentication. This pattern eliminates hardcoded secrets.

**Verification:**

```bash
# Secret not in compose file
docker compose config | grep client_secret
# No results ✓

# Secret not in container inspect
docker inspect grafana | grep -i oauth | grep -i secret
# No client secret visible ✓

# OAuth login still works
# Browser → Sign in with Authentik → Success ✓
```

### What We Learned

**Secret rotation simplified:**

Before:
1. Generate in Authentik
2. Update docker-compose.yml
3. Restart Grafana
4. Hope no typos

After:
1. Generate in Authentik
2. `bao kv put secret/grafana/oauth client_secret=NewSecret`
3. Restart Grafana (auto-retrieves)

Auditable, no compose edits, version controlled in OpenBAO.

**Security posture: Access-Controlled → Secrets-Managed**

---

<a name="phase-5-containers"></a>
## 11. Phase 5: Container Hardening

**Goal:** Apply least-privilege container security.

**Duration:** ~20 minutes

### The Problem

Container running as root with all Linux capabilities = If Grafana is compromised, attacker has full container access and potential host breakout.

### Implementation (Iterative)

**Attempt 1: Full hardening**

```yaml
services:
  grafana:
    user: "472:472"
    read_only: true
    cap_drop:
      - ALL
```

**Result:** Crash loop

```
Error: ✗ attempt to write a readonly database
```

**Cause:** Grafana uses SQLite which requires write operations even with writable volume.

**Attempt 2: Add necessary capabilities**

```yaml
services:
  grafana:
    user: "0"  # Still root, but restricted
    cap_drop:
      - ALL
    cap_add:
      - CHOWN        # File ownership
      - SETGID       # Set GID
      - SETUID       # Set UID
      - DAC_OVERRIDE # Bypass file permissions (SQLite needs this!)
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

**Result:** Success!

**Apply:**

```bash
docker-compose up -d --force-recreate grafana
```

### Validation

```bash
# Capabilities verified
docker inspect grafana --format='{{json .HostConfig.CapDrop}}' | jq
# ["ALL"] ✓

docker inspect grafana --format='{{json .HostConfig.CapAdd}}' | jq
# ["CHOWN","SETGID","SETUID","DAC_OVERRIDE"] ✓

# No privilege escalation
docker inspect grafana --format='{{json .HostConfig.SecurityOpt}}' | jq
# ["no-new-privileges:true"] ✓

# Resource limits
docker inspect grafana --format='{{.HostConfig.Memory}}'
# 2147483648 (2GB) ✓

# Grafana functions normally
# Login, dashboards, queries all work ✓
```

### What We Learned

**Application architecture defines security boundaries**

Grafana with SQLite cannot use read-only root filesystem. No workarounds change this.

Alternative: PostgreSQL backend (requires Grafana Enterprise or external DB).

**Test incrementally**

Applied capabilities one at a time, tested each addition. If all applied at once → combinatorial troubleshooting nightmare.

**Backups before risky changes**

Pre-Phase 5: Backed up compose file, volumes, database.

When read-only attempt corrupted database → restored in < 5 minutes.

**Security posture: Secrets-Managed → Containment-Hardened**

---

<a name="phase-6-production"></a>
## 12. Phase 6: Production Readiness

**Goal:** Automation, audit logging, final security controls.

**Duration:** ~1 hour

### Phase 6.1: Automated Certificate Renewal

**Problem:** 30-day certificates require manual renewal → outage risk.

**Create dedicated PKI AppRole:**

```bash
docker exec -it -e BAO_ADDR='http://127.0.0.1:8200' openbao sh

bao login s.YourRootToken

# Create policy
cat > /tmp/pki-policy.hcl << 'EOF'
path "pki/issue/grafana-server" {
  capabilities = ["create", "update"]
}
EOF

bao policy write pki-renew-grafana /tmp/pki-policy.hcl

# Create AppRole
bao write auth/approle/role/pki-grafana-renew \
  token_policies="pki-renew-grafana" \
  token_ttl=5m

# Get credentials (save these)
bao read auth/approle/role/pki-grafana-renew/role-id
bao write -f auth/approle/role/pki-grafana-renew/secret-id

exit
```

**Create renewal script:**

```bash
sudo nano /usr/local/bin/renew-grafana-cert.sh
```

```bash
#!/bin/bash
set -e

OPENBAO_ADDR="http://10.10.100.10:8200"
ROLE_ID="your-pki-role-id"
SECRET_ID="your-pki-secret-id"
CERT_PATH="/etc/haproxy/certs/grafana.pem"

# Authenticate
TOKEN=$(curl -s -X POST \
  -d "{\"role_id\":\"${ROLE_ID}\",\"secret_id\":\"${SECRET_ID}\"}" \
  ${OPENBAO_ADDR}/v1/auth/approle/login | jq -r '.auth.client_token')

# Issue certificate
CERT_JSON=$(curl -s -H "X-Vault-Token: ${TOKEN}" -X POST \
  -d '{"common_name":"10.10.75.10","ip_sans":"10.10.75.10","ttl":"720h"}' \
  ${OPENBAO_ADDR}/v1/pki/issue/grafana-server)

# Extract and bundle
CERT=$(echo "$CERT_JSON" | jq -r '.data.certificate')
KEY=$(echo "$CERT_JSON" | jq -r '.data.private_key')
CA=$(echo "$CERT_JSON" | jq -r '.data.issuing_ca')

cat > /tmp/new.pem << EOF
${CERT}
${KEY}
${CA}
EOF

# Install
cp /tmp/new.pem "$CERT_PATH"
chmod 600 "$CERT_PATH"
chown haproxy:haproxy "$CERT_PATH"

# Reload HAProxy (zero downtime)
systemctl reload haproxy

echo "Certificate renewed: $(date)"
```

```bash
sudo chmod 700 /usr/local/bin/renew-grafana-cert.sh

# Schedule cron (every 20 days at 2 AM)
sudo crontab -e
# Add: 0 2 */20 * * /usr/local/bin/renew-grafana-cert.sh >> /var/log/grafana-cert-renewal.log 2>&1
```

### Phase 6.2: Audit Logging

```yaml
# docker-compose.yml
services:
  grafana:
    environment:
      # ... existing ...
      
      # Audit Logging
      - GF_LOG_MODE=console file
      - GF_LOG_LEVEL=info
      - GF_LOG_FILE_FORMAT=json
      - GF_LOG_FILE_LOG_ROTATE=true
      - GF_LOG_FILE_MAX_DAYS=30
```

```bash
docker-compose up -d --force-recreate grafana
```

### Phase 6.3: Snapshot Security

```yaml
services:
  grafana:
    environment:
      # ... existing ...
      
      # Snapshot Security
      - GF_SNAPSHOTS_EXTERNAL_ENABLED=false
      - GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_URL=
```

```bash
docker-compose up -d --force-recreate grafana
```

### Validation

```bash
# Certificate renewal works
sudo /usr/local/bin/renew-grafana-cert.sh
# Certificate renewed: ... ✓

# Logs in JSON format
docker exec grafana cat /var/log/grafana/grafana.log | jq
# Valid JSON ✓

# External snapshots disabled
# Grafana UI → Share → Snapshot
# "External snapshot service is disabled" ✓
```

**Security posture: Containment-Hardened → Production-Hardened**

---

## Part 3: Operations

<a name="final-posture"></a>
## 13. Final Security Posture

### Security Posture Journey

| Phase | Posture | Time | Focus |
|-------|---------|------|-------|
| **Initial** | Baseline Functional | 2-3h | Deployment |
| **Phase 1** | Session-Controlled | 15m | Sessions |
| **Phase 2** | Transport-Secured | 1-2h | TLS |
| **Phase 3** | Access-Controlled | 15m | Prometheus |
| **Phase 4** | Secrets-Managed | 30m | Secrets |
| **Phase 5** | Containment-Hardened | 20m | Containers |
| **Phase 6** | Production-Hardened | 1h | Production |

**Total: ~5-8 hours (2-3h deploy + 3-5h harden)**

### Defense-in-Depth Layers

1. **Network:** Multi-VLAN, localhost binding, rate limiting
2. **Transport:** TLS 1.2+, HSTS, modern ciphers
3. **Application:** OAuth SSO, session timeouts, token rotation
4. **Secrets:** OpenBAO centralized, AppRole, dynamic injection
5. **Container:** Minimal capabilities, no escalation, resource limits
6. **Audit:** JSON logs, 30d retention, comprehensive events
7. **Operational:** Automated lifecycle, tested procedures

### Compliance Mapping

> **Source References:** All compliance mappings below reference publicly available frameworks. See [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) · [AICPA Trust Services Criteria (SOC 2)](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services) · [CIS Controls v8](https://www.cisecurity.org/controls)

**NIST 800-53 ([SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)):**
- AC-2(3): Session termination
- AC-12: 1h inactive, 24h max
- AU-2: Audit logging
- IA-5: AppRole rotation
- SC-8: TLS encryption
- SC-28: Secrets encrypted

**SOC 2 ([AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)):**
- CC6.1: OAuth SSO, session limits
- CC6.2: AppRole, bcrypt passwords
- CC6.6: TLS + OpenBAO encryption
- CC7.2: Audit logs, monitoring

**CIS Controls ([CIS Controls v8](https://www.cisecurity.org/controls)):**
- 3.3: Hardened containers
- 6.2: Centralized secrets
- 6.4: Short-lived credentials
- 8.2: Audit log collection

### Attack Surface

**Before (Baseline Functional):**
- Session hijacking: Easy (network sniffing)
- Credential theft: Easy (docker inspect)
- Prometheus enumeration: Trivial (no auth)
- Container breakout: Medium (root + all caps)

**After (Production-Hardened):**
- Session hijacking: Hard (TLS 1.2+ required)
- Credential theft: Very Hard (not in metadata)
- Prometheus enumeration: Hard (auth + localhost)
- Container breakout: Very Hard (4 caps only)

---

<a name="deployment-checklist"></a>
## 14. Deployment Checklist

### Pre-Deployment

**Infrastructure:**
- [ ] 3 VMs provisioned (Authentik, OpenBAO, Grafana)
- [ ] VLANs configured (75, 80, 100)
- [ ] Firewall rules tested
- [ ] NTP synchronized
- [ ] Backup storage ready

**Secrets:**
- [ ] All passwords in password manager
- [ ] OpenBAO root token offline backup
- [ ] OAuth secret in OpenBAO
- [ ] AppRole credentials in .env (600)

**Certificates:**
- [ ] OpenBAO PKI configured
- [ ] Renewal script tested
- [ ] Cron scheduled

### Deployment Steps

1. [ ] Deploy Authentik
2. [ ] Deploy OpenBAO
3. [ ] Deploy Grafana stack
4. [ ] Configure OAuth
5. [ ] Validate integration
6. [ ] Apply all hardening phases
7. [ ] Final validation

### Post-Deployment

- [ ] Security headers present
- [ ] Rate limiting works
- [ ] Sessions timeout
- [ ] Prometheus auth required
- [ ] Snapshots disabled
- [ ] Audit logs generated

---

<a name="maintenance"></a>
## 15. Maintenance Procedures

**Daily:**
- Spot-check container health
- Review failed login attempts

**Weekly:**
- Certificate expiration dates
- Disk space usage
- Backup verification

**Monthly:**
- OAuth flow test
- Rotate AppRole credentials
- Update software

**Quarterly:**
- Policy review
- Access review
- Restore test

---

<a name="troubleshooting"></a>
## 16. Troubleshooting Guide

### OAuth "redirect_uri_mismatch"

**Cause:** Authentik redirect URI doesn't match Grafana configuration.

**Fix:**
1. Check Grafana root URL: `http` vs `https`
2. Verify Authentik redirect URI matches exactly
3. Restart Grafana after changes

### Certificate "unable to load SSL certificate"

**Cause:** Wrong order in PEM bundle.

**Fix:**
```bash
# Correct order: cert → key → CA
cat grafana.crt grafana.key grafana-ca.crt > grafana.pem
```

### Container crash loop "readonly database"

**Cause:** Grafana SQLite incompatible with read-only filesystem.

**Fix:** Remove `read_only: true`, keep capability restrictions.

### Prometheus "401 Unauthorized" from Grafana

**Cause:** Missing or incorrect basicAuth in datasource.

**Fix:** Check provisioned datasource has `basicAuthPassword` in `secureJsonData`.

---

## Conclusion

### What You Built

A production-grade monitoring stack:
- Production-hardened through 6 phases of defense-in-depth
- Enterprise SSO (Authentik)
- Secrets management (OpenBAO)
- Automated operations
- Compliance ready

### Skills Demonstrated

- Multi-VLAN networking
- OAuth2/OIDC integration
- PKI certificate management
- Container security
- Secrets management
- TLS configuration
- Infrastructure-as-code
- Compliance mapping

### Next Steps

1. Add more exporters (MySQL, Redis, etc.)
2. Implement Authentik webhooks for real-time session revocation
3. Migrate to PostgreSQL for Grafana (enable read-only filesystem)
4. Add SIEM integration for centralized logging
5. Implement service mesh for mTLS between services

---

**Published by Oob Skulden™**  
**"Stay paranoid."**  
**Complete Journey: Zero → Production-Hardened**  
**Total Time: ~5-8 hours**  
**Date: February 4, 2026**

**Tags:** grafana, authentik, oauth2, openbao, vault, haproxy, tls, docker, container-security, secrets-management, monitoring, prometheus, homelab, cybersecurity, infrastructure-as-code, compliance, nist-800-53, soc2, devops, zero-trust

**SEO Keywords:** complete grafana deployment guide, authentik oauth tutorial, openbao secrets management, production monitoring stack, docker security best practices, homelab security hardening, zero to production grafana, container hardening guide, tls certificate automation, compliance monitoring setup
