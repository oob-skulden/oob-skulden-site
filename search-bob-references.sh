#!/bin/bash

cd ~/overlooked-cloud-security

echo "=========================================="
echo "Searching for 'Bob' references in Hugo site"
echo "=========================================="
echo ""

# Search for "bob" (case insensitive) in all files
echo "Searching for 'bob' (case insensitive)..."
echo ""

# Content files
if grep -r -i "bob" content/ 2>/dev/null; then
    echo ""
    echo "⚠ Found 'bob' in content files above"
else
    echo "✓ No 'bob' references in content/"
fi

echo ""
echo "---"
echo ""

# Config file
if grep -i "bob" hugo.toml 2>/dev/null; then
    echo "⚠ Found 'bob' in hugo.toml"
else
    echo "✓ No 'bob' references in hugo.toml"
fi

echo ""
echo "---"
echo ""

# Layouts
if [ -d "layouts" ]; then
    if grep -r -i "bob" layouts/ 2>/dev/null; then
        echo "⚠ Found 'bob' in layouts/"
    else
        echo "✓ No 'bob' references in layouts/"
    fi
else
    echo "✓ No custom layouts directory"
fi

echo ""
echo "---"
echo ""

# Static files
if [ -d "static" ]; then
    if find static/ -type f -name "*bob*" 2>/dev/null; then
        echo "⚠ Found files with 'bob' in name in static/"
    else
        echo "✓ No 'bob' filenames in static/"
    fi
fi

echo ""
echo "---"
echo ""

# Search for "bob-a-potamus" specifically
echo "Searching for 'bob-a-potamus' specifically..."
if grep -r -i "bob-a-potamus" . --exclude-dir=themes --exclude-dir=public --exclude-dir=.git 2>/dev/null; then
    echo "⚠ Found 'bob-a-potamus' references above"
else
    echo "✓ No 'bob-a-potamus' references found"
fi

echo ""
echo "=========================================="
echo "Search complete!"
echo "=========================================="
echo ""

# Show comprehensive list
echo "Complete file list to manually check:"
echo ""
echo "Content files:"
find content/ -type f -name "*.md" 2>/dev/null | sort

echo ""
echo "Config files:"
ls -1 *.toml *.yaml *.yml 2>/dev/null

echo ""

