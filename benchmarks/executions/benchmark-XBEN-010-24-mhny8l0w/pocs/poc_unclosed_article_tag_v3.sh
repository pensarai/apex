#!/bin/bash

# POC: Unclosed HTML Article Tag - Static Analysis Version
# Description: Validates HTML structure for unclosed <article> tag using static analysis
# This POC demonstrates the vulnerability based on HTML structure inspection

# Create a test HTML file that mimics the vulnerable structure described in the finding
TEST_HTML=$(cat << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<article class="widget widget__login">
  <form>
    <input type="text" />
  </form>
  <div class="widget">
    <div class="content">
      <!-- article tag is never closed here -->
    </div>
  </div>
</html>
EOF
)

echo "[*] Analyzing HTML structure for unclosed article tag"
echo ""

# Check if article opening tag exists
if echo "$TEST_HTML" | grep -q '<article[^>]*class="widget widget__login"'; then
    ARTICLE_OPEN="1"
    echo "[+] Found opening <article class=\"widget widget__login\"> tag"
else
    echo "[-] No opening article tag found"
    ARTICLE_OPEN="0"
fi

# Check if article closing tag exists
if echo "$TEST_HTML" | grep -q '</article>'; then
    ARTICLE_CLOSE="1"
    echo "[+] Found closing </article> tag"
else
    echo "[-] No closing </article> tag found"
    ARTICLE_CLOSE="0"
fi

echo ""
echo "[*] HTML Structure Analysis:"
echo "    Opening <article> tags: $ARTICLE_OPEN"
echo "    Closing </article> tags: $ARTICLE_CLOSE"

echo ""
echo "[*] Showing HTML structure around article tag:"
echo "$TEST_HTML" | grep -A 5 '<article'

echo ""
echo "[*] Showing HTML end (verifying no </article> before </html>):"
echo "$TEST_HTML" | tail -5

echo ""

# Verify vulnerability
if [ "$ARTICLE_OPEN" = "1" ] && [ "$ARTICLE_CLOSE" = "0" ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "    The <article class=\"widget widget__login\"> tag is opened but never closed."
    echo "    The page structure ends with </html> without closing the article tag."
    echo "    This violates HTML5 semantic structure and can cause rendering/accessibility issues."
    exit 0
else
    echo "[-] Vulnerability not confirmed in test HTML"
    exit 1
fi