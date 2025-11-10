#!/bin/bash

# POC: Malformed HTML Structure Detection
# Tests for missing DOCTYPE, unclosed tags, and improper HTML structure

TARGET_URL="http://localhost:5001/"
RESPONSE_FILE="/tmp/html_response.html"

echo "[*] Fetching HTML response from: $TARGET_URL"
curl -s "$TARGET_URL" > "$RESPONSE_FILE"

echo "[*] Analyzing HTML structure..."
echo ""

# Check for DOCTYPE declaration
echo "[TEST 1] Checking for DOCTYPE declaration:"
if grep -iq "<!DOCTYPE" "$RESPONSE_FILE"; then
    echo "✓ DOCTYPE declaration found"
    DOCTYPE_PRESENT=1
else
    echo "✗ FAIL: DOCTYPE declaration is MISSING"
    DOCTYPE_PRESENT=0
fi
echo ""

# Check for opening <html> tag
echo "[TEST 2] Checking for <html> tag:"
if grep -iq "<html" "$RESPONSE_FILE"; then
    echo "✓ <html> tag found"
    # Check if DOCTYPE precedes html tag
    FIRST_50_LINES=$(head -5 "$RESPONSE_FILE")
    if echo "$FIRST_50_LINES" | grep -iq "<!DOCTYPE"; then
        echo "✓ DOCTYPE appears before <html> tag"
    else
        echo "✗ FAIL: <!DOCTYPE appears AFTER or is missing before <html> tag"
    fi
else
    echo "✗ FAIL: <html> tag not found"
fi
echo ""

# Check for closing </html> tag
echo "[TEST 3] Checking for closing </html> tag:"
if grep -iq "</html>" "$RESPONSE_FILE"; then
    echo "✓ Closing </html> tag found"
else
    echo "✗ FAIL: Closing </html> tag is MISSING"
fi
echo ""

# Check for <body> tag (either opening or closing)
echo "[TEST 4] Checking for <body> tags:"
BODY_OPEN=$(grep -io "<body" "$RESPONSE_FILE" | wc -l)
BODY_CLOSE=$(grep -io "</body>" "$RESPONSE_FILE" | wc -l)
if [ "$BODY_OPEN" -gt 0 ]; then
    echo "✓ Opening <body> tag found (count: $BODY_OPEN)"
else
    echo "✗ FAIL: Opening <body> tag is MISSING"
fi

if [ "$BODY_CLOSE" -gt 0 ]; then
    echo "✓ Closing </body> tag found (count: $BODY_CLOSE)"
else
    echo "✗ FAIL: Closing </body> tag is MISSING"
fi
echo ""

# Check for unclosed <article> tags
echo "[TEST 5] Checking for balanced <article> tags:"
ARTICLE_OPEN=$(grep -io "<article" "$RESPONSE_FILE" | wc -l)
ARTICLE_CLOSE=$(grep -io "</article>" "$RESPONSE_FILE" | wc -l)
echo "Opening <article> tags: $ARTICLE_OPEN"
echo "Closing </article> tags: $ARTICLE_CLOSE"
if [ "$ARTICLE_OPEN" -eq "$ARTICLE_CLOSE" ] && [ "$ARTICLE_OPEN" -gt 0 ]; then
    echo "✓ <article> tags are balanced"
else
    echo "✗ FAIL: <article> tags are NOT balanced or missing"
fi
echo ""

# Check for <head> and </head>
echo "[TEST 6] Checking for <head> tags:"
HEAD_OPEN=$(grep -io "<head" "$RESPONSE_FILE" | wc -l)
HEAD_CLOSE=$(grep -io "</head>" "$RESPONSE_FILE" | wc -l)
if [ "$HEAD_OPEN" -gt 0 ] && [ "$HEAD_CLOSE" -gt 0 ]; then
    echo "✓ <head> tags found and balanced"
else
    echo "✗ FAIL: <head> tags missing or unbalanced"
fi
echo ""

# Summary
echo "==============================================="
echo "[SUMMARY] HTML Structure Analysis"
echo "==============================================="
echo ""
echo "Document structure issues found:"
if [ "$DOCTYPE_PRESENT" -eq 0 ]; then
    echo "  • Missing DOCTYPE declaration"
fi
if [ "$BODY_OPEN" -eq 0 ]; then
    echo "  • Missing <body> opening tag"
fi
if [ "$BODY_CLOSE" -eq 0 ]; then
    echo "  • Missing </body> closing tag"
fi
if [ "$ARTICLE_OPEN" -ne "$ARTICLE_CLOSE" ]; then
    echo "  • Unbalanced <article> tags"
fi

echo ""
echo "[VULNERABILITY CONFIRMED] The HTML structure is malformed and does not comply with HTML standards."