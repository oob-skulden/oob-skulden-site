---
title: "AI Infrastructure Isn’t Magic — It’s the Same Problems You Already Know, Stacked Differently"
date: 2026-02-27T12:00:00-05:00
draft: false
author: "Oob Skulden™"
description: "Understanding how self-hosted AI is built is the fastest way to understand what ChatGPT, Claude, and Gemini are actually doing with your data — and where your discipline’s failure mode lives."
tags:

  - ai-infrastructure
  - series
  - ai-security
  - ollama
  - open-webui
  - homelab
  - cve
  - waf
categories:
  - AI Infrastructure
  - Security
keywords:
  - ollama unauthenticated access
  - ollama exposed internet security
  - self-hosted AI security risks
  - open webui cve-2025-64496
  - open webui account takeover exploit
  - ai infrastructure attack surface
  - rag pipeline security
  - chromadb no authentication default
  - llm security homelab
  - saas ai trust model
  - chatgpt data security architecture
  - claude ai infrastructure
  - ai gateway security litellm
  - modsecurity waf ai application
  - prompt injection rag
  - self-hosted llm hardening guide
  - ollama shodan exposure
  - open webui hardening
  - ai security series
  - llm threat modeling
schema:
  type: TechArticle
  datePublished: "2026-02-27"
  author: "Oob Skulden"
  publisher: "Oob Skulden"
  proficiencyLevel: Advanced
showToc: true
tocOpen: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowShareButtons: false
summary: "The same architectural patterns behind ChatGPT, Claude, and Gemini exist in open source. Build it yourself, break it yourself, and suddenly you know exactly what question to ask your AI vendor."

---
<!--
SEO / AEO (Answer Engine Optimization) Summary Block
=====================================================
Target queries this post should rank for:

- "ollama exposed internet no authentication"
- "self-hosted AI security risks"
- "open webui CVE-2025-64496"
- "AI infrastructure attack surface"
- "how does ChatGPT infrastructure work"
- "RAG pipeline security risks"
- "ChromaDB default no authentication"
- "LLM security homelab"
- "ollama shodan unauthenticated"
- "self-hosted LLM hardening"
- "AI gateway security"
- "prompt injection RAG pipeline"

Featured Snippet / AEO targets:

Q: Is Ollama secure by default?
A: No. Ollama ships with no authentication by default. The project's design
   intentionally delegates auth to a proxy layer in front of it -- a reasonable
   architectural choice that predictably fails when most deployers have never
   heard that guidance. Shodan finds tens of thousands of unauthenticated Ollama
   inference endpoints reachable from the public internet.

Q: What is CVE-2025-64496?
A: CVE-2025-64496 is a vulnerability in Open WebUI (CVSS 7.3-8.0) that has been
   demonstrated to chain account takeover into remote code execution. It affects
   a large install base that has not patched. Check your version and apply
   available patches before deploying in any environment handling real data.

Q: How does self-hosted AI relate to SaaS AI security?
A: Self-hosted AI stacks (Ollama, Open WebUI, LiteLLM, ChromaDB) use the same
   architectural patterns as the infrastructure behind ChatGPT, Claude, and
   Gemini -- model runtime, API gateway, RAG pipeline, DLP layer. Building and
   breaking the open-source version teaches you what failure modes look like
   across all of them, including the black-box SaaS tools you can't inspect.

Q: What is a RAG pipeline and why is it a security risk?
A: Retrieval-Augmented Generation (RAG) pipelines retrieve documents from a
   vector store (like ChromaDB) and feed them to an LLM alongside the user
   prompt. The security risk: the model trusts that retrieved content. Malicious
   content embedded in indexed documents can inject instructions the model
   executes -- a class of attack called indirect prompt injection. ChromaDB
   ships with no authentication and no encryption at rest by default.
-->


> ⚠️ **Important Disclaimers**
> 
> **Personal Capacity:** This content represents personal educational work created independently in my own time, on personal equipment, for home lab and self-study purposes. It does not reflect the views, positions, or practices of any employer, client, or affiliated organization. I am not providing professional security consulting services. All security methodologies are derived from publicly available frameworks and open-source tool documentation.
> 
> **Lab Environment Warning:** All vulnerability demonstrations, exploitation techniques, and security testing described in this series are conducted in an isolated, air-gapped home lab environment with no connection to production systems or real user data. Do not attempt these techniques against systems you do not own or have explicit written authorization to test. Unauthorized access to computer systems is illegal.
> 
> **CVE Disclosure Note:** This post references CVE-2025-64496 affecting Open WebUI. This vulnerability has been publicly disclosed. Check the [NVD entry](https://nvd.nist.gov) and your installed version before proceeding. Patch before deploying in any environment handling real data.
> 
> **Scope:** This series covers open-source, self-hosted, homelab infrastructure only. It does not address enterprise cloud architectures, managed AI services, or organizational security programs.

---
## The Number That Should Bother You

Depending on which scanner you trust and when they ran it, somewhere between 12,000 and 175,000 Ollama instances are reachable from the public internet with no authentication required. You send a request, you get a response. No token, no password, no nothing. Shodan puts the total number of running Ollama instances at around 270,000. A meaningful chunk of those are wide open.

That’s not a misconfiguration story. Multiple contributors submitted pull requests to add authentication directly to Ollama. They were rejected. The project’s official position is that auth belongs in a proxy in front of it. Which is a reasonable design choice — and an absolutely predictable disaster when most people deploying it have never heard that guidance.

Ollama is the model runtime behind a huge chunk of self-hosted AI deployments. It’s also the same *type* of layer sitting underneath the infrastructure that powers the SaaS AI tools most of us use every day — just with someone else’s security controls on top. Controls you can’t see, can’t test, and are largely taking on faith.

That’s the problem with black boxes. Not that they’re dangerous. That they’re *unexaminable*. You can read the privacy policy. You can scroll through the terms. But you can’t actually watch what happens between the moment you type a message and the moment a response comes back.

Turns out you can build something structurally analogous to that. In a lab, if you want. Which is exactly what this series does.

---
## The Glass Box Version

Self-hosted AI — Ollama running the model, Open WebUI sitting in front of it, a RAG pipeline pulling in your documents, an API gateway managing the traffic, a DLP layer theoretically catching the sensitive stuff — uses the same *architectural patterns* as the infrastructure behind ChatGPT, Claude, and Gemini.

Not identical deployments. The same *patterns*, derived from the same publicly documented approaches to model serving, retrieval augmentation, and API gateway design that are described in vendor documentation, academic literature, and open-source implementations alike.

The difference is you can see every moving part. You can watch the request leave the browser, hit the gateway, pass through the guardrails, reach the model, and come back. You can see what the logs capture and what they miss. You can see what happens when authentication is configured wrong, or when a token doesn’t expire, or when the RAG pipeline trusts its inputs a little too much.

One honest caveat worth stating up front: SaaS AI providers operate these patterns with dedicated security teams, abuse detection, rate limiting infrastructure, and incident response pipelines that a homelab setup obviously doesn’t have. The *architectural patterns* rhyme. The *operational maturity* does not — and that’s entirely the point. You’re learning the patterns without the safety net, which means you get to see every seam clearly. Once you’ve seen the glass box version, the black box stops being a mystery. You already know what’s in there, and you know what questions to ask about the parts you can’t see.

---
## Your Background Has a Seat at This Table

AI infrastructure security isn’t a new problem. It’s every existing problem, stacked on top of each other, with a chatbot in front.

Depending on where your head lives, you’ll find something familiar in this stack — and something wrong with it.

**If you’ve spent time in identity and access**, you’ll look at Open WebUI’s authentication flow and see OAuth implemented by people who had other things on their mind. Tokens that outlive the sessions they were issued for. The same failure mode you’ve seen in a dozen other web apps, except this one has access to everything you fed the RAG pipeline.

**If networking is your thing**, you’ll run a Shodan search for Ollama’s default port and find tens of thousands of model inference endpoints sitting on the public internet with no authentication required. Not misconfigured. Default. That’s the shipped behavior.

**If you lean AppSec**, the RAG pipeline is your playground. What happens when the documents feeding your AI contain malicious content? What happens when retrieval returns something it shouldn’t? What does the model do with instructions embedded in a PDF? These aren’t hypothetical — they’re reproducible in a lab in about an afternoon.

**If you’ve done any DevOps work**, you’re looking at a fifteen-container stack with secrets passed as environment variables, no rotation policy, and an update cadence that can be charitably described as "whenever someone notices something is broken."

**If database security is your background**, ChromaDB is storing the vectorized version of everything you’ve fed the RAG pipeline — your documents, your prompts, your conversation history depending on configuration. Default ChromaDB ships with no authentication and no encryption at rest. It’s the same conversation you’ve had about MongoDB or Redis: a data store holding sensitive content, trusted implicitly by everything upstream, secured by nobody. PostgreSQL shows up too if you’re running persistent storage for audit logs and spend tracking, and the default credentials story there is as old as databases.

**If you work in vulnerability management**, the failure mode here isn’t that nobody’s scanning. It’s that the scanners don’t know what to look for yet. Trivy will check your container images. Nuclei has some Ollama templates. But the actual attack surfaces — prompt injection paths, RAG retrieval manipulation, token theft chains — don’t appear in a CVE feed the way a patched library does. The vuln management person gets a green dashboard while CVE-2025-64496 sits unpatched because nobody mapped Open WebUI versions to the asset inventory. That gap between "scanner says clean" and "actually exploitable" is a recurring theme across this entire series.

**If you’re just curious how this stuff actually works** — what’s really happening when you type into a chat interface — building it yourself is the fastest way to find out. And breaking it is a close second.

None of these are different problems. They’re the same stack viewed from different angles. That’s what makes it worth covering properly.

---
## Why SaaS AI Is the Same Conversation

When you use ChatGPT, Claude, or Gemini, someone else is running the infrastructure. That’s the deal. You get the convenience, they handle the stack.

What they’re running isn’t magic. The architectural patterns are publicly described — in research papers, vendor documentation, and the open-source projects those providers have contributed to or drawn from. The API gateway handling your request solves the same routing, rate limiting, and logging problems that LiteLLM OSS solves in a self-hosted setup. The RAG pipeline pulling in documents operates on the same retrieval trust assumptions whether it’s running on a homelab box or in a data center you’ll never see. The authentication layer is working through the same OAuth implementation challenges either way.

The failure modes rhyme because the patterns rhyme. The attack surfaces have the same shapes. The difference is you can reproduce them in your own lab, examine exactly why they fail, and walk away knowing what questions to actually ask about the tools you’re trusting with your data.

That’s the value here. Not "self-hosted AI is more secure" — that’s not the argument, and it’s not true by default. The argument is that building it yourself teaches you how to think about it when you can’t.

---
## What This Series Covers

The full stack, layer by layer. Every component gets built properly first — because you can’t break something you don’t understand — then attacked in an isolated lab, then hardened with configs and compliance mappings you can actually use.

**Foundation** starts before we touch a config file. Threat modeling, attack surface mapping, understanding what we’re actually building before we build it. This is the part most people skip, which is why most deployments look the way they do.

**Ollama** is the model runtime. The exposure numbers above live here. We’ll get into why the default behavior is what it is, what someone can actually do with an unauthenticated inference endpoint in a homelab context, and what a properly locked-down deployment looks like.

**Open WebUI** is the interface layer most people interact with. It has 110,000 GitHub stars, hundreds of millions of downloads, a publicly disclosed CVE (CVE-2025-64496, CVSS 7.3–8.0) that has been demonstrated to chain account takeover into remote code execution, and a large install base that hasn’t patched. We’ll cover what the CVE does, how to reproduce it in an isolated lab, and how to remediate it. **If you are running Open WebUI in any environment, check your version and apply available patches before continuing.**

**WAF — ModSecurity + OWASP Core Rule Set** sits in front of Open WebUI and inspects every request before it gets anywhere near the model. ModSecurity is free, open source (Apache 2.0), and has been the standard in web application firewalls long enough that it’s what production environments actually use. Paired with the OWASP Core Rule Set — also free, also open source — you get a working ruleset that covers injection attacks, protocol anomalies, scanner detection, and AI-specific patterns the community is actively developing as the threat model catches up. The practical value: you can watch it interact with the CVE-2025-64496 exploit chain in an isolated lab environment, tune the rules, then observe what slips through. That before/after is the whole point.

**RAG Pipeline** is where your documents meet a model that trusts them a bit too much. ChromaDB, embeddings, retrieval — and what happens when the content being retrieved contains instructions the model decides to follow.

**AI Gateway** is LiteLLM OSS — routing, rate limiting, guardrails, logging. The layer that’s supposed to catch the problems the other layers create. We’ll find out what it misses.

**DLP and Data Flow** is Presidio doing PII masking. There’s a meaningful gap between "we have a DLP layer" and "our DLP layer is working correctly." This episode lives in that gap.

**Multi-User and Shared Access** covers what happens when the single-user assumptions baked into most of this stack meet more than one person. Authentication, access controls, session management — the places where "it works for me" quietly stops being the whole story.

**Integrations and Tool Use** is MCP servers, agent frameworks, and CrewAI. The part of the stack where the AI can take actions on your behalf, and the trust model is still being worked out in public. This is the frontier episode.

Each topic: build it, break it, fix it. The blog carries the full runbook. The videos carry the reasoning.

---
## Who This Is For

If you deployed Ollama and moved on, this is for you.

If you’ve ever wondered what’s actually happening when you type into a chat interface — not the marketing version, the real version — this is for you.

If you work in security and need to get up to speed on AI infrastructure without starting from scratch, this is for you.

If you’re just the kind of person who wants to break things in a lab before trusting them in the wild, you’re in the right place.

---
## One Last Thing

Most people using AI tools have no real mental model of what’s happening between the prompt and the response. That’s not a criticism — the tools are designed that way. Type, wait, read. The infrastructure is intentionally invisible.

The problem is that invisible infrastructure still has failure modes. It still has authentication layers that can be misconfigured, data flows that can be intercepted, trust boundaries that can be crossed. Not understanding how it works doesn’t make those things go away. It just means someone else is thinking about them — or nobody is.

Building this stack yourself changes that. When you’ve stood up each layer, broken it deliberately, and fixed it with intention, the black box isn’t black anymore. You know what an AI gateway is supposed to do and what happens when it doesn’t. You know where PII goes when someone uploads a document. You know what a WAF sees and what it misses. You know which parts of the stack your background gives you instincts about — and which parts you need to learn.

That’s the goal of this series. Not "here’s a homelab project." It’s a working model of the architectural patterns behind the tools most people use every day, built in the open so you can see every seam.

Once you’ve seen it, you’ll never look at a chat interface the same way again.

---
> ⚠️ **Reminder:** All techniques described in this series are demonstrated in an isolated, air-gapped home lab environment. Do not attempt these against systems you do not own or have explicit written authorization to test.

---
*Published by Oob Skulden™ — Security research and education for homelab enthusiasts and security professionals. All content represents personal educational work conducted independently on personal equipment and personal time. Views expressed do not reflect those of any employer or affiliated organization. All techniques demonstrated in an isolated home lab environment. Not professional security consulting.*
