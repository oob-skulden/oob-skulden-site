#!/bin/bash

cd ~/overlooked-cloud-security

echo "Updating social links with your accounts..."

# Backup current config
cp hugo.toml hugo.toml.backup-$(date +%Y%m%d_%H%M%S)

# Update hugo.toml with your actual social links
cat > hugo.toml << 'EOF'
baseURL = 'http://localhost:1313/'
languageCode = 'en-us'
title = 'The Overlooked Cloud Security Expert'
theme = 'PaperMod'

relativeURLs = false
canonifyURLs = false

[pagination]
  pagerSize = 10

[taxonomies]
  tag = "tags"
  category = "categories"

[params]
  description = "Practical cloud security guidance for teams with limited budgets"
  author = "Wayne"
  ShowReadingTime = true
  ShowShareButtons = true
  ShowPostNavLinks = true
  ShowBreadCrumbs = true
  ShowCodeCopyButtons = true
  ShowRssButtonInSectionTermList = true
  defaultTheme = "auto"
  ShowSearchPage = true
  
  # Profile mode - shows intro AND posts
  [params.profileMode]
    enabled = true
    title = "Security Without the Enterprise Budget"
    subtitle = """
Practical cloud security for small teams. Open source tools. Free tier architectures.
Real detection queries. Actual remediation code.

**No theory. No vendor pitches. Just working solutions.**
    """
    
    [[params.profileMode.buttons]]
      name = "Articles"
      url = "/posts"
    [[params.profileMode.buttons]]
      name = "Tools"
      url = "/tools"
    [[params.profileMode.buttons]]
      name = "About"
      url = "/about"

  # Your actual social media accounts
  [[params.socialIcons]]
    name = "linkedin"
    url = "https://www.linkedin.com/in/stonepedal/"
  
  [[params.socialIcons]]
    name = "reddit"
    url = "https://www.reddit.com/user/oobskulden/"
  
  [[params.socialIcons]]
    name = "x"
    url = "https://x.com/oobskulden"
  
  [[params.socialIcons]]
    name = "rss"
    url = "/index.xml"

[menu]
  [[menu.main]]
    identifier = "posts"
    name = "Articles"
    url = "/posts/"
    weight = 10

  [[menu.main]]
    identifier = "tools"
    name = "Tools"
    url = "/tools/"
    weight = 20
  
  [[menu.main]]
    identifier = "tags"
    name = "Tags"
    url = "/tags/"
    weight = 30

  [[menu.main]]
    identifier = "about"
    name = "About"
    url = "/about/"
    weight = 40
  
  [[menu.main]]
    identifier = "search"
    name = "Search"
    url = "/search/"
    weight = 50

[outputs]
  home = ["HTML", "RSS", "JSON"]

[markup]
  [markup.highlight]
    style = "monokai"
    lineNos = true
    lineNumbersInTable = true
    noClasses = false
  
  [markup.goldmark]
    [markup.goldmark.renderer]
      unsafe = true

[permalinks]
  posts = "/:year/:month/:title/"
EOF

echo "✓ Social links updated in hugo.toml"

# Create custom share buttons: LinkedIn, Reddit, HackerNews
mkdir -p layouts/partials

cat > layouts/partials/share_icons.html << 'EOF'
{{- $pageurl := .Permalink }}
{{- $title := .Title }}

<div class="share-buttons">
    <span style="font-weight: 500; margin-right: 10px; color: var(--secondary);">Share:</span>
    
    <!-- LinkedIn -->
    <a target="_blank" rel="noopener noreferrer" aria-label="share on LinkedIn"
        href="https://www.linkedin.com/sharing/share-offsite/?url={{ $pageurl }}"
        title="Share on LinkedIn">
        <svg viewBox="0 0 512 512" height="30" width="30" fill="currentColor">
            <path d="M449.446,0c34.525,0 62.554,28.03 62.554,62.554l0,386.892c0,34.524 -28.03,62.554 -62.554,62.554l-386.892,0c-34.524,0 -62.554,-28.03 -62.554,-62.554l0,-386.892c0,-34.524 28.029,-62.554 62.554,-62.554l386.892,0Zm-288.985,423.278l0,-225.717l-75.04,0l0,225.717l75.04,0Zm270.539,0l0,-129.439c0,-69.333 -37.018,-101.586 -86.381,-101.586c-39.804,0 -57.634,21.891 -67.617,37.266l0,-31.958l-75.021,0c0.995,21.181 0,225.717 0,225.717l75.02,0l0,-126.056c0,-6.748 0.486,-13.492 2.474,-18.315c5.414,-13.475 17.767,-27.434 38.494,-27.434c27.135,0 38.007,20.707 38.007,51.037l0,120.768l75.024,0Zm-307.552,-334.556c-25.674,0 -42.448,16.879 -42.448,39.002c0,21.658 16.264,39.002 41.455,39.002l0.484,0c26.165,0 42.452,-17.344 42.452,-39.002c-0.485,-22.092 -16.241,-38.954 -41.943,-39.002Z" />
        </svg>
    </a>

    <!-- Reddit -->
    <a target="_blank" rel="noopener noreferrer" aria-label="share on Reddit"
        href="https://reddit.com/submit?url={{ $pageurl }}&title={{ $title }}"
        title="Share on Reddit">
        <svg viewBox="0 0 512 512" height="30" width="30" fill="currentColor">
            <path d="M449.446,0c34.525,0 62.554,28.03 62.554,62.554l0,386.892c0,34.524 -28.03,62.554 -62.554,62.554l-386.892,0c-34.524,0 -62.554,-28.03 -62.554,-62.554l0,-386.892c0,-34.524 28.029,-62.554 62.554,-62.554l386.892,0Zm-3.446,265.638c0,-22.964 -18.616,-41.58 -41.58,-41.58c-11.211,0 -21.361,4.457 -28.841,11.666c-28.424,-20.508 -67.586,-33.757 -111.204,-35.278l18.941,-89.121l61.884,13.157c0.756,15.734 13.642,28.29 29.56,28.29c16.407,0 29.706,-13.299 29.706,-29.701c0,-16.403 -13.299,-29.702 -29.706,-29.702c-11.666,0 -21.657,6.792 -26.515,16.578l-69.105,-14.69c-1.922,-0.418 -3.939,-0.042 -5.585,1.036c-1.658,1.073 -2.811,2.761 -3.224,4.686l-21.152,99.438c-44.258,1.228 -84.046,14.494 -112.837,35.232c-7.468,-7.164 -17.589,-11.591 -28.757,-11.591c-22.965,0 -41.585,18.616 -41.585,41.58c0,16.896 10.095,31.41 24.568,37.918c-0.639,4.135 -0.99,8.328 -0.99,12.576c0,63.977 74.469,115.836 166.33,115.836c91.861,0 166.334,-51.859 166.334,-115.836c0,-4.218 -0.347,-8.387 -0.977,-12.493c14.564,-6.47 24.735,-21.034 24.735,-38.001Zm-119.474,108.193c-20.27,20.241 -59.115,21.816 -70.534,21.816c-11.428,0 -50.277,-1.575 -70.522,-21.82c-3.007,-3.008 -3.007,-7.882 0,-10.889c3.003,-2.999 7.882,-3.003 10.885,0c12.777,12.781 40.11,17.317 59.637,17.317c19.522,0 46.86,-4.536 59.657,-17.321c3.016,-2.999 7.886,-2.995 10.885,0.008c3.008,3.011 3.003,7.882 -0.008,10.889Zm-5.23,-48.781c-16.373,0 -29.701,-13.324 -29.701,-29.698c0,-16.381 13.328,-29.714 29.701,-29.714c16.378,0 29.706,13.333 29.706,29.714c0,16.374 -13.328,29.698 -29.706,29.698Zm-160.386,-29.702c0,-16.381 13.328,-29.71 29.714,-29.71c16.369,0 29.689,13.329 29.689,29.71c0,16.373 -13.32,29.693 -29.689,29.693c-16.386,0 -29.714,-13.32 -29.714,-29.693Z" />
        </svg>
    </a>

    <!-- Hacker News (Y Combinator) -->
    <a target="_blank" rel="noopener noreferrer" aria-label="share on Hacker News"
        href="https://news.ycombinator.com/submitlink?u={{ $pageurl }}&t={{ $title }}"
        title="Share on Hacker News">
        <svg viewBox="0 0 512 512" height="30" width="30" fill="currentColor">
            <path d="M0 32v448h448V32H0zm21.2 197.2H21c.1-.1.2-.3.3-.4 0 .1 0 .3-.1.4zm218 53.9V384h-31.4V281.3L128 128h37.3l52.7 115.6 52.7-115.6h37.3l-79.8 154.1z"/>
        </svg>
    </a>

    <!-- X/Twitter -->
    <a target="_blank" rel="noopener noreferrer" aria-label="share on X"
        href="https://twitter.com/intent/tweet/?text={{ $title }}&url={{ $pageurl }}"
        title="Share on X">
        <svg viewBox="0 0 512 512" height="30" width="30" fill="currentColor">
            <path d="M389.2 48h70.6L305.6 224.2 487 464H345L233.7 318.6 106.5 464H35.8l164.9-188.5L26.8 48h145.6l100.5 132.9L389.2 48zm-24.8 373.8h39.1L151.1 88h-42l255.3 333.8z"/>
        </svg>
    </a>
</div>
EOF

echo "✓ Share buttons created (LinkedIn, Reddit, HackerNews, X)"

# Update About page with your links
cat > content/about.md << 'EOF'
---
title: "About"
date: 2024-12-23
draft: false
showToc: false
hidemeta: true
---

# The Mission

Enterprise-grade security shouldn't require enterprise budgets. This site demonstrates how small teams can implement robust cloud security using:

- **Open source detection tools** (Steampipe, TruffleHog, Checkov)
- **Cloud provider free tiers** (AWS, GCP, Azure)
- **Automation that actually works**
- **Compliance mapping that auditors accept**

## Who This Is For

- Security engineers at companies with 1-5 person security teams
- DevSecOps practitioners drowning in SaaS sprawl
- CISOs who need to justify security investments
- Anyone tired of "best practices" that cost $50K+/year

## What You'll Find Here

Every article includes:

✅ **Working detection queries** you can copy-paste  
✅ **Complete remediation pipelines** with code  
✅ **Honest tool comparisons** (including limitations)  
✅ **Compliance mappings** (NIST, SOC 2, PCI-DSS)  
✅ **Free tier architecture** designs

## The Approach

1. **No vendor pitches** - Tools are evaluated objectively
2. **No theory without practice** - Every recommendation is tested
3. **No expensive solutions** - Free tier first, always
4. **No generic advice** - Specific tools, specific commands, specific results

## About Wayne

Security practitioner focused on the "boring but critical" components that organizations deploy without proper security consideration.

**Homelab environment:** Proxmox cluster, HashiCorp Vault, multi-cloud free tier deployments

**Current focus:** Building practical security tooling that small teams can actually implement

---

**Connect:**
- [LinkedIn](https://www.linkedin.com/in/stonepedal/) - Professional updates
- [Reddit](https://www.reddit.com/user/oobskulden/) - Community discussions
- [X/Twitter](https://x.com/oobskulden) - Quick updates
- [RSS](/index.xml) - Get every article
EOF

echo "✓ About page updated with your social links"

# Enhanced CSS for share buttons with brand colors
cat >> assets/css/extended/custom.css << 'CSS'

/* Share buttons - professional styling with brand colors */
.share-buttons {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
  flex-wrap: wrap;
}

.share-buttons span {
  font-size: 0.9rem;
}

.share-buttons a {
  transition: transform 0.2s ease, opacity 0.2s ease;
  opacity: 0.7;
  display: inline-flex;
  align-items: center;
}

.share-buttons a:hover {
  transform: scale(1.15);
  opacity: 1;
}

.share-buttons svg {
  vertical-align: middle;
}

/* LinkedIn blue */
.share-buttons a:nth-child(2):hover svg {
  fill: #0077b5;
}

/* Reddit orange */
.share-buttons a:nth-child(3):hover svg {
  fill: #ff4500;
}

/* Hacker News orange */
.share-buttons a:nth-child(4):hover svg {
  fill: #ff6600;
}

/* X/Twitter black */
.share-buttons a:nth-child(5):hover svg {
  fill: #000000;
}

/* Dark mode adjustments */
.dark .share-buttons a:nth-child(5):hover svg {
  fill: #ffffff;
}
CSS

echo "✓ Share button styling updated"

echo ""
echo "============================================"
echo "✓ All social links updated successfully!"
echo "============================================"
echo ""
echo "Your accounts configured:"
echo "  • LinkedIn: https://www.linkedin.com/in/stonepedal/"
echo "  • Reddit: https://www.reddit.com/user/oobskulden/"
echo "  • X/Twitter: https://x.com/oobskulden"
echo ""
echo "Share buttons on posts:"
echo "  • LinkedIn - Professional sharing"
echo "  • Reddit - Community discussions (r/netsec, r/cybersecurity)"
echo "  • Hacker News - Submit to Y Combinator"
echo "  • X/Twitter - Quick shares"
echo ""
echo "Social icons in header:"
echo "  • All four accounts visible in site header"
echo "  • RSS feed for subscribers"
echo ""
echo "Restart your server to see changes:"
echo "  ./start-server.sh"
echo ""

