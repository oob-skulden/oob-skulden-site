---
title: "Ultimate Security Audit Script"
description: "Pre-push security sweep for Hugo sites and web projects (secrets, backups, exposure risks)."
date: 2025-12-24
tags: ["security", "bash", "hugo"]
---

## What it does

A fast, local audit script you run before pushing changes—focused on common “oops” moments:
- secrets and credentials patterns
- backup / temp files
- risky permissions / exposures
- metadata leaks

## Download

- **Script:** `/tools/ultimate-security-audit.sh`

## Usage

```bash
# from your repo root
chmod +x ultimate-security-audit.sh
./ultimate-security-audit.sh .

# or run the hosted copy after you download it
chmod +x ultimate-security-audit.sh
./ultimate-security-audit.sh /path/to/site
