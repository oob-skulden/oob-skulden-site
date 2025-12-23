#!/bin/bash

cd ~/overlooked-cloud-security

echo "Replacing 'Bob' references with 'Oob Skulden'..."
echo ""

# Backup first
echo "Creating backup..."
tar -czf ~/hugo-backup-$(date +%Y%m%d_%H%M%S).tar.gz .
echo "✓ Backup created in home directory"
echo ""

# Replace in content files
find content/ -type f -name "*.md" -exec sed -i 's/Bob-A-potamus/Oob Skulden/g' {} \;
find content/ -type f -name "*.md" -exec sed -i 's/Bob A potamus/Oob Skulden/g' {} \;
find content/ -type f -name "*.md" -exec sed -i 's/bob-a-potamus/oobskulden/g' {} \;

# Replace author field if it says Bob
find content/ -type f -name "*.md" -exec sed -i 's/author: "Bob"/author: "Oob Skulden"/g' {} \;
find content/ -type f -name "*.md" -exec sed -i 's/author: Bob/author: Oob Skulden/g' {} \;

# Check hugo.toml
if grep -q 'author = "Bob"' hugo.toml; then
    sed -i 's/author = "Bob"/author = "Oob Skulden"/' hugo.toml
    echo "✓ Updated author in hugo.toml"
fi

echo ""
echo "Replacement complete!"
echo ""
echo "Verify changes:"
echo "  grep -r 'Oob Skulden' content/"
echo ""

