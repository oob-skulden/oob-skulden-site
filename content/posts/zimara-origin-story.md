

---
title: "How I Built a Pre-Commit Security Audit on a Flight to Houston (Because I'm Cheap and Paranoid)"
date: 2024-12-29T02:00:00-06:00
draft: false
tags: ["security-tools", "static-sites", "bash", "hugo", "jekyll", "git-hooks", "devops", "pre-commit", "tool-development", "origin-story"]
categories: ["Security", "Tools"]
author: "Oob Skulden™"
description: "From 'ultimate-security-audit.sh' to Zimara: A Christmas Eve tale of bash scripts, static sites, and questionable life choices"
cover:
    image: "" # Add if you have a cover image
    alt: ""
    caption: ""
showToc: true
TocOpen: false
---


**From “ultimate-security-audit.sh” to Zimara: A Christmas Eve tale of bash scripts, static sites, and questionable life choices**

**Published by Oob Skulden™**

-----

## The Incident That Started Nothing

Let me tell you about the security incident that *didn’t* happen to me.

I didn’t commit an API key to GitHub. I didn’t wake up to a $4,000 AWS bill. I didn’t have to explain to anyone why some bot in Kazakhstan was mining cryptocurrency on my dime.

Why? Not because I’m particularly careful. Not because I follow best practices.

I’m just **really, really cheap.**

And paranoid. Mostly cheap.

See, I work in cyber. Which means I’ve seen every flavor of “oops I committed the secret” disaster. I’ve been in the postmortems. I’ve read the incident reports. The ones where someone hardcoded an AWS key “just for testing” and three hours later there’s a $47,000 bill and a very uncomfortable call with the CFO.

And I thought: “Man, I am absolutely going to do this to myself someday.”

But unlike most people who have that realization and do nothing, I was stuck on a plane with nothing better to do.

-----

## Christmas Eve, MSP to HOU, Seat 17A

**Wednesday, December 24th, 2024. 2:47 PM.**

I’m on a flight from Minneapolis to Houston with my wife and two daughters. Christmas Eve. Family visit. I’m on PTO. Explicitly *not* working.

Here’s the seating situation: My youngest wanted to sit with her older sister. Non-negotiable. So they’re in the back together. My wife is with them, white noise headphones on, eye mask deployed, completely checked out. She’s mastered the art of sleeping through air travel.

Which means I got bumped to my older daughter’s original seat. Front of the cabin. Seat 17A.

The in-flight WiFi is free. I’m VPN’d into my Debian VM from my iPad because even on vacation, I’m not doing *anything* on airline WiFi without a VPN. Professional paranoia.

The person in 17B is browsing Amazon. Judging by their cart, they have some truly questionable gift-giving instincts. I’m trying not to judge. I’m failing.

I have three hours, an iPad connected to a proper dev environment, and too much time to think.

Thinking is dangerous.

Naturally, I decided to start a website.

If my wife was awake, she’d ask “What are you doing?”

“Building a security tool.”

“On Christmas Eve?”

“It’s vacation. This is fun.”

But she’s asleep. So I just get to work.

-----

**The Stack Decision (Made Over Free WiFi):**

- **Hugo** for static site generation (fast, simple, doesn’t make me want to throw my iPad)
- **GitHub** for version control (free, ubiquitous)
- **Netlify** for hosting (also free, deploys on push, generous free tier because *did I mention I’m cheap?*)

I picked **PaperMod theme** because it looked clean and I wasn’t trying to win design awards. This was about content, not spending three weeks tweaking CSS.

Then came the hard part: **What do I call this thing?**

I work in cyber. I can’t just use my real name because (a) my employer might have opinions, and (b) if I’m going to write about how people screw up security, I’d prefer not to be instantly Google-able when I inevitably screw something up myself.

After 20 minutes of increasingly desperate brainstorming that involved rejected gems like “CyberGuyWhoKnowsStuff” and “CloudDefenderDave,” I landed on **Oob Skulden™**.

(We’re not discussing how I arrived at that name. It’s a whole thing. Moving on.)

-----

## The Actual Problem I Was Trying to Solve

Somewhere over Nebraska, I had an epiphany:

**I was about to put my code on GitHub.**

And I work in cyber.

Which means I’ve seen what happens when developers push code without thinking. Hardcoded API keys. AWS credentials. SSH private keys. Database passwords. That `.env` file you “definitely gitignored” but actually didn’t. Backup files ending in `.bak` containing production secrets from six months ago.

The usual suspects.

Now, there are tools for this. **Gitleaks. TruffleHog. GitGuardian.** They’re excellent. They catch secrets in commits, scan git history, integrate with CI/CD.

But they all have the same problem:

**They run in CI. After you’ve pushed.**

By the time they catch your secret, it’s already in git history. Too late. You can delete the file in the next commit, but it doesn’t matter—it’s still there, forever, until you rewrite history with `git filter-repo` or BFG and force-push to every branch and hope nobody cloned in the last 47 seconds.

And even then, if your repo was public for even a moment, assume the secret is compromised. Bots scrape GitHub constantly. They’ll find your AWS key before you finish typing your commit message.

**What I needed was something that ran *before* the commit.**

A pre-commit hook. Something local. Something that would yell at me *before* I did something stupid, not *after* when it requires tickets, flame wars, and apologetic Slack threads.

And because I’m cheap (have I mentioned this?), I didn’t want to pay for a SaaS service. I wanted something I could just… run.

**So I decided to build it.**

On a plane.

On Christmas Eve.

While someone three rows back argued with a flight attendant about whether cookies count as a meal.

-----

## Why Bash (And Why Everyone Would Tell Me Not To)

I opened VS Code in my browser (thanks, iPad and SSH). Cursor blinking. Ready to build a security tool.

**First decision: What language?**

The obvious choices:

- **Python** (I’m okay with it, everyone has it, plenty of libraries)
- **Go** (fast, compiles to a binary, modern and hip)
- **Rust** (even more modern, even more hip, would make me look impressive)

I picked **bash**.

Let me explain before you close this tab.

### Why bash won:

**1. It’s already there**

Every developer machine has bash. macOS, Linux, WSL2 on Windows. It’s just… there. No `pip install`. No `go get`. No `cargo install`. No “works on my machine” because you’re on Python 3.11 and they’re on 3.9 and your f-strings are a war crime against backwards compatibility.

You download the script. You run it. Done.

(Yes, different bash versions exist between OSes—Windows, Mac with ZSH default, Linux variants. This was built on Debian Linux. But bash is bash.)

**2. It’s fast where it matters**

For pattern matching and file scanning—which is 90% of what this tool does—bash + grep + find is *screaming fast*. No interpreter startup cost. No GIL. Just your CPU and some regex patterns having a conversation.

I wanted something that would run in **under 2 seconds**. Bash delivered.

**3. Security tools should be readable**

If I’m telling you to run a security script before every commit, you should be able to read that script and verify it’s not doing anything sketchy. With bash, you can. With a compiled Go binary, you’re trusting me. With Python and 47 dependencies from PyPI, you’re trusting me *and* 47 random package maintainers.

**4. I was on a plane with WiFi, but…**

Yeah, the WiFi was free. But I still didn’t want to deal with virtual environments or dependency management. I wanted to write code that scanned for secrets, not debug why `pip` can’t find a wheel that works with my iPad’s SSH session to a Debian VM.

**5. Portability and security were the goal**

I wanted something that:

- Runs anywhere (macOS, Linux, any Unix-like system)
- Has no dependencies beyond standard Unix tools
- Can be audited by reading the source
- Doesn’t require elevated privileges
- Can’t be easily hijacked or exploited (well, I learned my earlier versions *had* exploits)

Bash checked every box.

-----

**The trade-offs:**

**Bash is verbose.** What’s three lines in Python is ten in bash.

**Bash is finicky.** Spaces matter. Quotes matter. Everything matters in ways that feel personally vindictive.

**Bash is not “modern.”** You will not get upvotes on Hacker News for writing bash in 2024.

But you know what bash is?

**Boring. Reliable. Everywhere. Secure when done right.**

And for a security tool that needs to run on every developer’s machine without friction, boring wins.

-----

## Five Checks and a Dream

I started simple. **Five checks.**

That’s it. Just five things I wanted to catch before committing.

This was specifically for **static site generators**—Hugo, Jekyll, Astro, Eleventy, Next.js static exports. The tools that build websites from markdown and templates. The kind of projects where you’re not running a database or handling authentication, but you can still leak secrets like a pro.

Here’s what made the cut:

### CHECK 1: Secrets in Configuration Files

The obvious one. Scan config files for API keys, access tokens, passwords. The patterns that make security teams cry:

```bash
"['\"]?api[_-]?key['\"]?\s*=\s*['\"][^'\"]+['\"]"
"AKIA[0-9A-Z]{16}"  # AWS keys (pattern example)
"xox[baprs]-[a-zA-Z0-9-]+"  # Slack tokens
"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
```

I threw every secret pattern I could think of into an associative array. AWS keys, GitHub tokens, Slack webhooks, database URLs. The usual suspects.

### CHECK 2: Private Keys Anywhere

Not just in config files—*anywhere*. Every file. Every directory (except `.git` and `node_modules` because I’m not a masochist).

This was the “hard stop” check. If this found something, you were done. No commit. No push. Go fix your life choices.

### CHECK 3: Backup Files in Git

The `.bak`, `.old`, `.backup`, `.tmp` files everyone creates and forgets about. The ones that contain production credentials from “just that one time I was debugging.”

```bash
git ls-files | grep -E '\.(backup|bak|old|orig|tmp)'
```

If git is tracking it, you’re gonna hear about it.

### CHECK 4: Sensitive Files in Public Output

The crown jewel of “how did this even happen” checks.

Is `.git` in your `public/` directory? Because if it is, congratulations—you’ve just published your entire git history to the internet. Every commit. Every secret you deleted “six months ago.” All of it.

This check also looked for config files (`.toml`, `.env`, `.key`, `.pem`) that somehow made it into your build output. Because apparently that happens more than you’d think with Hugo and Jekyll builds.

### CHECK 5: Internal URLs and IPs Exposed

The check that catches localhost references, `127.0.0.1`, `192.168.x.x`, private network IPs—anything that screams “I was testing this locally and forgot to change it back.”

```bash
grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.0\.)" public/
```

Because nothing says “professional deployment” like hardcoded references to your laptop’s IP address in your static site.

-----

That was it. Five checks. About **200 lines of bash**. Color-coded output because why not make security auditing slightly less depressing.

The whole thing was organized by severity:

- **CRITICAL** (exit code 3): Stop everything, fix immediately
- **HIGH** (exit code 2): Fix before you push
- **MEDIUM** (exit code 1): Address when you can
- **LOW** (exit 0): Nice-to-have improvements

And it ran in about **2 seconds**. Fast enough that you’d forget it was even running.

I wrote those 200 lines somewhere over Oklahoma. By the time we landed in Houston, I had a script that would at least prevent me from committing my SSH key.

Good enough.

-----

## Why “Ultimate” Was Wildly Optimistic

I called it `ultimate-security-audit.sh`.

Let’s be clear: it was not ultimate. It wasn’t even particularly comprehensive. It was **five grep commands** with decent error handling and a lot of optimism.

But you know what? **It worked.**

It caught the stuff that mattered for static sites. It ran blazing fast—about 2 seconds on my Hugo site. It didn’t require dependencies beyond standard Unix tools.

And most importantly, when I ran it on my own repository that first night in Houston, **it found things**.

Not secrets. Not private keys. But backup files I didn’t know were tracked. Mixed content references. Missing `.gitignore` patterns. The boring stuff that becomes un-boring when it’s public.

I fixed them all. Re-ran the script. Green checkmarks everywhere.

Committed. Pushed to GitHub. First deployment to Netlify.

**Success.**

And then I kept building.

Because that’s what happens when you give someone who works in cyber a vacation and a side project. It metastasizes.

-----

## Houston, We Have a Static Site

**21:37. The kids are asleep. My wife is asleep. I am not asleep.**

I’m in the guesthouse living room at my parents’ place with my iPad, the glow of VS Code reflecting off my increasingly questionable decision to do this instead of, I don’t know, sleeping before Christmas morning chaos with two daughters who will be up at an ungodly hour.

But I had momentum.

I had Hugo installed. PaperMod configured. A bare-bones site with a homepage that said “Coming Soon” and an About page that said absolutely nothing useful.

Time for the moment of truth:

**Push to GitHub.**

I initialized the repo. Staged the files. Wrote a commit message.

And then I remembered: **I have a security script.**

Right. The thing I built on the plane. Let me actually… use it.

I ran what I was calling at the time (and I am not proud of this) **`ultimate-security-audit.sh`**.

Yes. **Ultimate**.

I was feeling ambitious.

The script ran in under 2 seconds.

And oh boy, did it have opinions.

**Findings:**

- Three backup files (`.bak`) I didn’t know were there
- A test `.env` file with placeholder values that *looked* like secrets
- Mixed HTTP/HTTPS content references in my theme config
- No `.gitignore` (how did I forget this)

Nothing *catastrophic*. No actual secrets. But enough to make me realize: “Oh, this thing actually works.”

I cleaned up the findings. Added a proper `.gitignore`. Removed the backup files. Fixed the theme config.

Ran the script again. Clean. Still 2 seconds.

Committed. Pushed.

**First deployment to Netlify: Success.**

I had a website. I had a security script. I had validation that maybe, just maybe, this wasn’t a terrible idea.

And then I kept building.

-----

## Scope Creep, But Make It Security

Here’s the thing about building tools on your own time when you’re on PTO visiting family for Christmas: **you keep thinking of stuff.**

And nobody can tell you to stop. Nobody can say “that’s not in scope” or “we need to prioritize other features.” It’s your vacation. You can spend it however you want…

*(OUCH, just got slapped in the head by my wife.)*

Even if that means writing bash scripts at 0200 while your family sleeps.

Even if your wife occasionally asks “Are you still awake?” and you insist “It’s fun.”

Even if Christmas morning happens and you’re thinking about git history checks while the kids open presents.

I’d be in the shower and think: “Wait, should I check for Slack tokens?”

I’d be making tea (I’m strictly a tea person—white tea, if you must know) while my wife and mother handled breakfast and think: “What about git history? Deleted files are still in history.”

I’d be trying to fall asleep and think: “Oh god, what if someone puts their private key in a Hugo theme override?”

So I kept adding checks.

This is what happens when you give someone who works in cyber five days off for Christmas and a side project. It metastasizes.

I was the only tester. No QA team. No code reviews. No sprint planning. Just me, my Debian VM, and an increasingly long list of “wait, should I also check for…” ideas.

-----

## The Five-Day Sprint

That first version was clean. Simple. Focused. **Fast.**

**Wednesday, December 24th (Flight day):** 5 checks, 200 lines, ~2 seconds runtime

**Monday, December 29th at 2 AM (5 days later):** 45 checks, 2,000+ lines, still <3 seconds runtime

Yeah, you read that right. I spent my entire Christmas vacation building this thing. I 9x’d the number of checks and added 1,800 lines of code, and the runtime only increased by about a second.

**That’s not an accident. That’s intentional.**

If your security tool takes 30 seconds to run, developers will bypass it. If it takes 5 seconds, they’ll tolerate it. If it takes 3 seconds, they forget it’s even running.

Speed matters. Especially for static site builds that are already fast—you don’t want your security audit taking longer than your actual Hugo build.

What happened between December 24th and December 29th at 0200 was pure scope creep—the good kind, fueled by tea and the particular obsession that happens when you should be sleeping but instead you’re thinking “wait, should I also check for…?”

-----

### Day 1 (December 24th - The Flight)

- Built the core: 5 checks, 200 lines
- Basic secret patterns (AWS, Slack, GitHub, private keys)
- Git backup file detection
- Public directory exposure checks (specific to Hugo/Jekyll builds)
- **Runtime: ~2 seconds**
- **Tester count: 1 (me)**

### Day 2-3 (December 25th-26th - Post-Landing)

- Ran first version on my own repo (found issues, felt validated)
- Added git history scanning (deleted secrets still in history)
- Extended secret pattern detection
- Added generator auto-detection (Hugo vs Jekyll vs Next.js vs Astro vs Eleventy)
- Started Netlify config validation (since I was using Netlify)
- **Runtime: ~2-3 seconds**
- **Tester count: Still just me**

The generator detection was key—static site generators all have different output directories (`public/` for Hugo, `_site/` for Jekyll, `dist/` for Astro, `out/` for Next.js). I needed to know where to look for built files.

### Day 4 (December 27th - Deep Dive)

- GitHub Actions security patterns (`pull_request_target` dangers)
- Security header validation (HSTS, CSP, X-Frame-Options)
- Output directory comprehensive scanning
- Non-interactive mode for git hooks
- Execution safety hardening (command hijacking prevention, secure PATH handling, temp file cleanup)
- **Ran every version through AI code review** to catch vulnerabilities in the script itself
- **Runtime: <3 seconds**
- **Tester count: Me, myself, and I**

The execution safety stuff was critical—I didn’t want my security tool to be exploitable. Things like:

- Sanitizing PATH to prevent command hijacking
- Validating temp files aren’t symlinks
- Checking binary permissions before execution
- Proper cleanup on script exit

### Day 5 (December 28th-29th - The Final Push)

- SOC 2 and NIST framework alignment
- Exfiltration endpoint detection ([webhook.site](http://webhook.site), requestbin, etc.)
- Lockfile hygiene checks
- Git hook permission validation
- CI/CD integration patterns
- Severity-based exit codes refined
- Final safety hardening
- **Stopped at 2 AM December 29th**
- **Final count: 45 checks, 2,000+ lines**
- **Runtime: 3-5 seconds depending on repo size**
- **Tester count: One guy at his in-laws**

-----

I used **SOC 2** and **NIST frameworks** as references—not because I’m trying to achieve compliance (this is a personal blog, not a fintech startup), but because those frameworks document the boring security stuff that actually matters for static sites.

Things like:

- Are your dependencies up to date? (`npm audit`)
- Do you have version control?
- Are you using secure transport? (no HTTP git remotes)
- Are sensitive files excluded from builds?

The unsexy checklist items that prevent 90% of incidents.

**Three consecutive late nights over Christmas week.** A concerning amount of tea. My wife wondering why I was typing at 2 AM on December 29th instead of sleeping like a normal person. The kids asking “Why is Babu on the computer so much?”

“Daddy’s building something.”

“What?”

“A tool that yells at people before they make mistakes.”

They thought that was hilarious. They’re not wrong.

And then, at 0200 on Monday, December 29th, while everyone slept, I had something that actually felt… complete.

Built in five days. Tested by one person (me). On vacation. At the in-laws.

As one does.

-----

## The Name Journey (A Tragedy in Three Acts)

Remember how I called it `ultimate-security-audit.sh`?

Yeah. That lasted about 2 days before I realized:

1. It’s not “ultimate” (nothing is)
2. It’s incredibly generic
3. It’s a terrible name to type repeatedly
4. I cannot, with a straight face, tell people “Yeah, just run ultimate-security-audit.sh before you commit”

**Act I: The Hubris**

`ultimate-security-audit.sh` – Full of confidence. Completely unmarketable. Destined for the trash.

**Act II: The False Start**

`Rivus` – I liked this one! Latin for “stream” (as in, stream of checks). Sounded sophisticated. Rolled off the tongue.

Then I Googled it.

Turns out there’s already a thing called Rivus. Multiple things, actually. Very taken.

Back to the drawing board.

**Act III: The Redemption**

`Zimara` – Not taken (I checked *extensively* this time). Sounds slightly mysterious. Easy to type. Doesn’t oversell what it does.

Done. We have a name.

(If you’re wondering what Zimara means: nothing specific. It’s a name. Sometimes a name is just a name.)

-----

## Making It Actually Useful

Having a script is one thing. Having a script people will actually use is another.

**I did three things to reduce friction:**

### 1. Made it executable everywhere

```bash
chmod +x zimara.sh
sudo cp zimara.sh /usr/local/bin/zimara
```

Now you can just type `zimara` from any directory. No `./` or remembering where you put the script.

### 2. Integrated it with git hooks

Created a pre-commit hook that runs Zimara automatically:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
zimara --non-interactive
exit $?
EOF

chmod +x .git/hooks/pre-commit
```

Now **every commit** goes through Zimara first. If it finds critical issues, the commit is blocked. No “I’ll fix it later.” No “Just this once.”

### 3. Made failures actionable

Early versions would just say: `❌ Secret detected`

Current version says:

```
⚠ Possible secrets detected [HIGH]
Files:
  ./config.js:42: AKIA0123456789EXAMPLE

Actions:
  • Remove secrets from source
  • Rotate exposed credentials
  • Use env vars / secret manager
```

Tell people *what’s wrong* and *how to fix it*. Don’t just scream and leave them to figure it out.

This was especially important for static site-specific issues. When Zimara finds `.git/` in your Hugo `public/` directory, it explains exactly why that’s catastrophic and how your build config should exclude it.

-----

## What Zimara Actually Catches (The Boring Stuff That Matters)

Here’s the thing: **Zimara doesn’t catch zero-days.**

It doesn’t find novel attack vectors. It won’t help you pwn a server or win a CTF.

It catches the boring stuff that happens with static sites. The stuff you already know is bad but somehow still ends up in production:

### The “How Did This Happen” Tier:

- Private keys committed to git (CHECK 03)
- `.git` directory in Hugo’s `public/` output (CHECK 07)
- API keys in client-side JavaScript bundles (CHECK 20)

### The “We’ll Fix It Later” Tier:

- Secrets hardcoded in `netlify.toml` (CHECK 25)
- Backup files with production credentials (CHECK 05)
- Git history containing deleted secret files (CHECK 17)

### The “Nobody Remembers to Check This” Tier:

- Missing security headers in Netlify config (CHECK 10, 38, 39)
- Unpinned GitHub Actions (CHECK 35)
- Sensitive paths in sitemap.xml (CHECK 40)

### The “This Seems Fine But Isn’t” Tier:

- HTTP git remotes (CHECK 18)
- Mixed content in static site output (CHECK 08)
- `pull_request_target` without trust boundaries (CHECK 34)

Each check is boring. None of them will get you a CVE. Most security engineers would say “well obviously you shouldn’t do that.”

And yet.

And yet, I’ve seen all of these in production static sites. Multiple times. At companies with security teams.

Because knowing something is bad and catching it before your Hugo build deploys are very different things.

-----

## The Reality of Adoption

**What I expected:**
“Wow, this is amazing! Everyone will use it immediately!”

**What actually happened:**

**Day 1 (December 24th):** Built first version on plane. Felt clever.

**Day 1 (11:37 PM):** Used it. Caught three things I would have committed to my Hugo site.

**Day 5 (2 AM):** Shipped v0.47 with 45 checks. Still only testing on my own repos.

**Current state:** Still primarily testing on my own static sites.

### Lessons learned:

**1. Speed matters**

If your security tool takes 30 seconds to run, developers will bypass it. If it takes 3 seconds, they’ll let it run.

Zimara’s runtime: **~2 seconds initially, <3 seconds at v0.47**

Fast enough that bypassing it is more effort than just letting it run. Faster than most people’s Hugo builds.

**2. Actionable beats accurate**

I could make Zimara more accurate with machine learning and semantic analysis and all sorts of fancy stuff.

Or I could tell people exactly what’s wrong and how to fix it in plain English, with examples specific to their static site generator.

Guess which one actually gets used?

**3. Severity levels build trust**

Early versions blocked on everything. Every finding was treated as critical.

Result: I didn’t trust my own tool. False positives got treated the same as actual secrets.

Current version has four severity levels:

- **CRITICAL** (private keys, `.git` exposure in static output) → hard block
- **HIGH** (API keys, secrets in code) → hard block
- **MEDIUM** (backup files, missing headers) → warning, allow with prompt
- **LOW** (missing `.gitignore`, documentation) → informational

I trust it more because it respects my judgment on non-critical issues.

**4. Local-first actually works**

The tool runs before CI. Before git history. Before deployment. Before anyone else sees your mistake. Very shift-left.

That psychological safety—knowing you can catch things before they’re public—actually makes you more likely to use the tool.

**5. Solo development is fast but risky**

Building this alone in five days meant:

- No meetings
- No code reviews slowing me down
- No “let’s discuss the architecture” debates
- But also no second pair of eyes catching my mistakes
- And no real-world testing beyond my own Hugo sites

I’m releasing this as v0.47 knowing it’s been tested by exactly one person (me) on a handful of static site projects. That’s the trade-off of speed.

-----

## Why This Matters (The Boring Answer)

Most security incidents with static sites don’t happen because of sophisticated attacks.

They happen because of stupid mistakes.

A developer hardcoding a Netlify build token “just for testing.”  
A backup file that didn’t get added to `.gitignore`.  
A git commit that seemed fine but contained a secret in history.  
A Hugo build that accidentally copied `.git/` to `public/`.

**CI catches these after they’re committed.** By then, the secret is in git history. You have to rotate credentials, rewrite history, coordinate with your team to re-clone.

**Zimara catches them before the commit is created.** The secret never leaves your laptop. You fix it now, while you still have context. No incident report. No postmortem. No “how did this happen?” Slack thread.

Prevention > cleanup.

-----

## What’s Next

**Current state:** v0.47.1, 45 checks, stable enough for my own use (tested primarily on Debian 13.x)

**The tool works.** For me. On my static sites. Tested by one person over five days.

**What I’m not doing:**

- Adding a GUI
- Making it a SaaS
- Adding ML/AI detection
- Supporting non-static site projects *(well, this may change… soon)*
- Pivoting to anything
- Pretending this is enterprise-ready

**What I’m doing:**

- Releasing it publicly for others to try
- Documenting everything extensively
- Being honest about the five-day, solo-developer reality
- Hoping other people find it useful
- Accepting that it probably has bugs I haven’t found yet

**What might happen:**

- Community contributions for additional static site generators
- Bug reports from people who aren’t me
- More checks specific to Gatsby, SvelteKit, Docusaurus
- Better documentation of which checks map to which compliance controls
- Actual testing by people with different use cases

But honestly? It does what I need. Five checks on a plane became 45 checks over five days, and that’s enough for now.

I built it. I use it. It catches things. That’s success.

If other people find it useful? Bonus.

-----

## Try It (With Appropriate Expectations)

**Want to catch secrets before they leave your laptop?**

Zimara is specifically designed for static site projects—Hugo, Jekyll, Astro, Eleventy, Next.js static exports. If you’re building with these tools, this might be for you.

**Fair warning:** This was built in five days by one person on Christmas vacation. It’s been tested on exactly one person’s repos (mine). It works for me. Your mileage may vary.

```bash
# Clone the tool
git clone https://github.com/oob-skulden/zimara
cd zimara
chmod +x zimara.sh

# Run it
./zimara.sh

# Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./zimara.sh --non-interactive
exit $?
EOF
chmod +x .git/hooks/pre-commit
```

Full documentation at [OobSkulden repo](https://github.com/oob-skulden/zimara/)

**Three design principles:**

1. **Easy** - Download and run. No dependencies. No setup wizard.
2. **Portable** - Works on any Unix-like system. Same script everywhere.
3. **Secure** - Readable source code. No network calls. Safe execution.

**One reality check:**

- Built in 5 days
- Tested by 1 person
- Works great for Hugo/Jekyll/static sites
- Probably has bugs
- Definitely has room for improvement

-----

## The Actual Takeaway

I built this tool because I’m cheap and didn’t want to pay for secret scanners.

I built it in five days because I had PTO and nothing better to do.

I built it over Christmas at my parents’ house.

I built it for static sites because that’s what I was deploying.

I tested it on exactly my own repos because I was the only developer available.

But the real reason it works is simpler:

**It runs before you make a mistake, not after.**

Most security tools are designed to catch you after you’ve already screwed up. They’re incident response masquerading as prevention.

Zimara is actual prevention. It’s the friend who stops you before you send that drunk text. Before you commit that API key. Before GitHub sees it. Before git history remembers it forever.

And it does it in 3 seconds.

Fast enough you don’t notice. Effective enough you don’t have to explain to anyone why your personal blog project leaked AWS credentials.

That’s the whole point.

Is it perfect? No. It was built in five days by one guy on vacation.

Does it work? Yes. It’s caught every mistake I’ve tried to commit since December 24th.

Will it work for you? Probably. But I’m just one person with a handful of Hugo sites, so test it yourself.

-----

**What started on a plane on Christmas Eve:**

- 5 checks
- 200 lines of bash
- 2 seconds runtime
- An iPad VPN’d to a Debian VM
- Questionable gift choices happening in seat 17B
- Absolutely not doing actual work because vacation
- “Are you seriously writing bash on Christmas Eve?” “Yes.”

**What I shipped at 0200 on Monday, December 29th:**

- 45 checks
- 2,000+ lines of bash
- 3 seconds runtime
- Zero secrets committed
- One fewer thing to worry about
- A very patient wife
- Two daughters who think “Daddy’s mistake-yelling tool” is funny
- Exactly one person’s worth of testing

Worth it.

-----

**Published by Oob Skulden™**  
*The threats you don’t see coming.*

Stay vigilant. Stay submerged.

-----

**Zimara will be released publicly soon at [github.com/oob-skulden/zimara](https://github.com/oob-skulden/zimara). Full documentation, source code, and setup guides coming with the release.**

**Built in 5 days. Tested by 1 person. Works for static sites. Use at your own risk. Contributions welcome.**
