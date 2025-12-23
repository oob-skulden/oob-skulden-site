#!/bin/bash

cd ~/overlooked-cloud-security

echo "Fixing Hugo configuration for v0.153..."

# Get actual VM IP
VM_IP=$(hostname -I | awk '{print $1}')

# Create corrected hugo.toml
cat > hugo.toml << 'EOF'
baseURL = 'http://localhost:1313/'
languageCode = 'en-us'
title = 'The Overlooked Cloud Security Expert'
theme = 'PaperMod'

relativeURLs = false
canonifyURLs = false

# Fixed: Use pagination.pagerSize instead of paginate
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

echo "✓ Configuration fixed!"
echo ""
echo "Your VM IP is: $VM_IP"
echo ""

# Update start-server.sh with correct command
cat > start-server.sh << 'SERVEREOF'
#!/bin/bash
VM_IP=$(hostname -I | awk '{print $1}')
echo "Starting Hugo server..."
echo "Access at: http://${VM_IP}:1313"
hugo server -D --bind 0.0.0.0 --baseURL "http://${VM_IP}:1313"
SERVEREOF

chmod +x start-server.sh

echo "✓ start-server.sh updated!"
echo ""
echo "Now run:"
echo "  ./start-server.sh"
echo ""

