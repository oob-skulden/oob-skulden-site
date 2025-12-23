---
title: "Top 10 Steampipe Queries Every AWS Team Needs"
date: 2024-12-23
draft: true
tags: ["steampipe", "aws", "detection", "query-library"]
categories: ["Detection"]
author: "Oob Skulden"
ShowToc: true
TocOpen: true
---

## Why This Matters

[Hook: specific problem this solves]

## Prerequisites

- AWS account (free tier is fine)
- Steampipe installed
- AWS CLI configured with read-only credentials

## The Queries

### 1. Public S3 Buckets

**What it detects:** S3 buckets with public access

**Compliance:** NIST 800-53 AC-3, SOC 2 CC6.1, PCI-DSS 1.2.1
```sql
SELECT 
  name,
  region,
  bucket_policy_is_public,
  arn
FROM 
  aws_s3_bucket
WHERE 
  bucket_policy_is_public = true
ORDER BY 
  name;
```

**Why it matters:** [Explain the risk]

**Remediation:** [Cloud Custodian policy to fix]

[Continue with 9 more queries...]

## Running These Queries

[Usage instructions]

## Next Steps

- Fork the query library: [GitHub link]
- Set up automated scanning: [Link to pipeline article]
- Map to your compliance framework: [Link to compliance article]
