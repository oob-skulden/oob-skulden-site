---
title: "Why Static Site Security Is a Lie We Tell Ourselves"
date: 2026-01-05T18:00:00-06:00
draft: false
author: "Oob Skulden�"
description: "Static sites aren�t dangerous because they�re dynamic. They�re dangerous because they�re trusted, ignored, and quietly connected to everything else."
tags:
  - Security
  - AppSec
  - DevSecOps
  - Static Sites
  - Cloud Security
categories:
  - Security
  - Engineering
showToc: false
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
---

Let’s get one thing straight up front:  
no one who’s worked in security for more than five minutes thinks static sites are “secure.”

What we *do* think — quietly, implicitly — is that they’re **less worth worrying about**.

That’s the lie.

Not an obvious one. Not a malicious one. Just a comfortable assumption that goes unchallenged because static sites don’t *look* dangerous.

They don’t crash databases.  
They don’t process payments.  
They don’t have login screens screaming “hack me.”

So they slide past scrutiny.

## “Static” Is a Marketing Term, Not a Property

Modern static sites are not static. They’re *assembled*.

A typical setup today includes:

- A generator (Hugo, Jekyll, Gatsby, etc.)
- A theme pulled from somewhere on the internet
- JavaScript that talks to APIs
- CI/CD pipelines that build and deploy
- Environment variables injected at build time
- Preview environments and webhooks
- A CDN with security headers someone copied once

At no point does any of this stop being software.  
We just call it static because it makes us relax.

## The Theme Problem Nobody Talks About

Here’s an uncomfortable pattern you notice once you start paying attention:

Static site themes are effectively **third-party software supply chains**, and they’re rarely treated as such.

Many themes:

- Ship with outdated JavaScript libraries
- Include unsafe default configurations
- Assume permissive CSPs (or none at all)
- Encourage inline scripts “for convenience”
- Haven’t been meaningfully reviewed in years

They’re popular because they work.  
They’re risky because they’re trusted blindly.

When a vulnerability exists in a theme, it doesn’t stay theoretical. It gets replicated across thousands of sites — many of which will never update.

Static sites don’t need zero-days to be exploitable.  
They just need inertia.

## “But It’s Just a Website”

This is where the conversation usually stops.

So let’s slow it down and actually unpack what that website can do.

That website:

- **Can leak credentials**  
  Build-time secrets, API keys, and tokens often end up committed, logged, or exposed in client-side JavaScript.

- **Can expose infrastructure details**  
  Repo structure, IaC files, build configs, and comments quietly document how your environment works.

- **Can be abused as a pivot point**  
  A public repo or site often has just enough access to help an attacker move laterally into CI, cloud, or SaaS tooling.

- **Can enable supply-chain attacks**  
  Compromised dependencies, themes, or pipelines can turn a “content site” into a distribution mechanism.

- **Can become a long-term reconnaissance asset**  
  Static sites change slowly. Attackers love that. They can study them indefinitely without triggering alarms.

None of this requires breaking into anything.  
It just requires reading what’s already there.

## Security by Neglect (For Everyone)

“Security by neglect” isn’t just a professional failure mode. It’s a human one.

In organizations, static sites often fall into the gap between:

- “Production systems”
- “Marketing content”

For individuals, it’s even worse.

Personal blogs, portfolios, and small business sites are usually built once, deployed, and forgotten — not out of malice, but out of busyness, optimism, or trust in defaults.

Which means:

- Old themes linger
- Secrets don’t get rotated
- Pipelines never get reviewed
- Warnings go unnoticed

Attackers don’t need sophisticated targets.  
They need unattended ones.

## This Isn’t Speculation — It’s History

Static sites *have* been part of real incidents.

Compromised static pages have been used to deliver malicious JavaScript through vulnerable dependencies. Popular generators and themes have shipped XSS issues that quietly propagated across thousands of sites before patches landed. CI/CD pipelines used to build static sites have been abused to leak secrets or publish malicious content. Third-party scripts embedded in otherwise “safe” pages have been hijacked overnight.

Often, the breach doesn’t happen *on* the site.  
The site is just where the consequences become visible.

## Static Sites Are Still Trust Boundaries

Whether we acknowledge it or not, static sites sit at the intersection of:

- Source code
- Infrastructure
- Automation
- Identity
- Third-party services

They’re often the **first thing exposed publicly** and the **last thing audited**.

That’s not an accident.  
It’s an optimization problem we solved for speed instead of safety.

This gap is part of why I eventually built a small static analysis tool for my own use.

Not because static sites are special, but because they were consistently skipped. After seeing the same patterns repeat — forgotten secrets, risky pipelines, inherited themes, and quiet misconfigurations — it became easier to automate the boring checks than to keep rediscovering them manually.

That tool became **[Zimara](https://github.com/oob-skulden/zimara)**. It’s not magic, and it doesn’t “secure” anything by itself. It just scans repositories — code, configs, CI, and infrastructure — for the kinds of issues people assume aren’t there because the site is “just static.”

## What Actually Helps (Without Drama)

You don’t need to turn your blog into a hardened fortress.

But you do need to stop pretending it’s inert.

Some unglamorous, effective steps:

- Scan repositories, not just running services
- Treat CI/CD and IaC as part of the attack surface
- Review themes and dependencies like real software
- Assume anything public will be read carefully by someone you don’t know
- Revisit static sites periodically, not just at launch

None of this is exciting.  
That’s why it works.

## The Takeaway

Static site security isn’t fake.

It’s quiet.

And quiet problems last longer than loud ones.

If your security posture relies on the phrase  
“it’s just a static site,”  
that’s not strategy.

That’s optimism.

I’ve written before about building tooling like this out of mild paranoia and impatience —  
specifically in  
[*How I Built a Pre-Commit Security Audit on a Flight to Houston (Because I’m Cheap and Paranoid)*]({{< relref "posts/zimara-origin-story.md" >}}).

The motivation hasn’t changed. Static sites just happen to be where that neglect shows up most clearly.

---

*Published by Oob Skulden™*