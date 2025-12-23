#!/bin/bash

cd ~/overlooked-cloud-security

echo "=========================================="
echo "Replacing 'Wayne' with 'Oob Skulden'"
echo "=========================================="
echo ""

# Create backup first
echo "Creating backup..."
BACKUP_FILE=~/hugo-backup-before-wayne-replacement-$(date +%Y%m%d_%H%M%S).tar.gz
tar -czf "$BACKUP_FILE" .
echo "✓ Backup created: $BACKUP_FILE"
echo ""

# Replace in hugo.toml
echo "Updating hugo.toml..."
sed -i 's/author = "Wayne"/author = "Oob Skulden"/' hugo.toml
echo "✓ hugo.toml updated"
echo ""

# Replace in all content files
echo "Updating content files..."
find content/ -type f -name "*.md" -exec sed -i 's/author: "Wayne"/author: "Oob Skulden"/' {} \;
find content/ -type f -name "*.md" -exec sed -i "s/author: 'Wayne'/author: 'Oob Skulden'/" {} \;
find content/ -type f -name "*.md" -exec sed -i 's/author: Wayne/author: Oob Skulden/' {} \;
echo "✓ Post author fields updated"
echo ""

# Update About page
echo "Updating About page..."
sed -i 's/## About Wayne/## About Oob Skulden/' content/about.md
sed -i 's/About Wayne/About Oob Skulden/' content/about.md
sed -i 's/\*\*About Wayne\*\*/\*\*About Oob Skulden\*\*/' content/about.md
echo "✓ About page updated"
echo ""

# Check for any remaining Wayne references in content
echo "Checking for remaining 'Wayne' references..."
echo ""

REMAINING=$(grep -r "Wayne" content/ 2>/dev/null | grep -v "Binary file" || true)

if [ -n "$REMAINING" ]; then
    echo "⚠ Found remaining references (review these manually):"
    echo "$REMAINING"
    echo ""
    echo "These might be legitimate mentions in article content."
    echo "Review and update manually if needed."
else
    echo "✓ No remaining 'Wayne' references in content/"
fi

echo ""
echo "=========================================="
echo "Replacement Summary"
echo "=========================================="
echo ""
echo "✓ Author name in hugo.toml: Oob Skulden"
echo "✓ Author field in posts: Oob Skulden"
echo "✓ About page: About Oob Skulden"
echo ""
echo "Backup saved to: $BACKUP_FILE"
echo ""
echo "Restart your server to see changes:"
echo "  ./start-server.sh"
echo ""

