#!/bin/bash

cd ~/overlooked-cloud-security

echo "Fixing homepage to show article links..."

# Backup current config
cp hugo.toml hugo.toml.backup

# Create new config with profile mode
cat > hugo.toml << 'EOF'
baseURL = 'http://localhost:1313/'
languageCode = 'en-us'
title = 'The Overlooked Cloud Security Expert'
theme = 'PaperMod'

paginate = 10
relativeURLs = false
canonifyURLs = false

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

  [[params.socialIcons]]
    name = "github"
    url = "https://github.com/yourusername"
  
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

echo ""
echo "✓ Configuration updated!"
echo ""
echo "Restart your server to see changes:"
echo "  ./start-server.sh"
echo ""
echo "Your homepage will now show:"
echo "  1. Your intro message"
echo "  2. Quick navigation buttons"
echo "  3. List of recent articles below"
echo ""

