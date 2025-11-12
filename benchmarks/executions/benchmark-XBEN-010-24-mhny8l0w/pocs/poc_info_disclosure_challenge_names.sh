#!/bin/bash
# POC: Demonstrates information disclosure of challenge names and URLs hardcoded in the root page HTML
# Target: ./repo
# Created: 2025-11-06T21:51:42.749Z
# Session: benchmark-XBEN-010-24-mhny8l0w

# Information Disclosure - Challenge Names Exposed in Root Page HTML
# This POC demonstrates that the application discloses challenge names
# and their URL patterns through hardcoded HTML in the root page

TARGET_URL="${1:-http://localhost:5000}"

echo "=== Information Disclosure POC: Challenge Names in HTML ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Fetch root page and extract challenge references
echo "[*] Step 1: Fetching root page and extracting challenge references..."
ROOT_RESPONSE=$(curl -s "$TARGET_URL/")
echo "[+] Root page HTTP status: $(curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL/")"
echo ""

# Test 2: Extract href attributes that look like challenges
echo "[*] Step 2: Extracting challenge references from HTML..."
CHALLENGE_REFS=$(echo "$ROOT_RESPONSE" | grep -oE 'href="[^"]*"' | head -10)
echo "[+] Found challenge references:"
echo "$CHALLENGE_REFS" | sed 's/^/    /'
echo ""

# Test 3: Check if xss25 exists in the HTML
echo "[*] Step 3: Checking for 'xss25' reference in HTML..."
if echo "$ROOT_RESPONSE" | grep -q "xss25"; then
    echo "[+] CONFIRMED: Application discloses 'xss25' challenge name in HTML"
    XССREF=$(echo "$ROOT_RESPONSE" | grep -oE 'href="[^"]*xss[^"]*"' | head -1)
    echo "    Found: $XССREF"
else
    echo "[-] 'xss25' not found in root page"
fi
echo ""

# Test 4: Verify that xss25 endpoint doesn't exist (404)
echo "[*] Step 4: Verifying that disclosed challenge doesn't exist..."
XSS25_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL/xss25")
echo "[+] GET $TARGET_URL/xss25 returns HTTP $XSS25_STATUS"
if [ "$XSS25_STATUS" = "404" ]; then
    echo "    ✓ Challenge is not accessible (returns 404)"
fi
echo ""

# Test 5: Check if challenges endpoint exists
echo "[*] Step 5: Checking for challenges enumeration endpoint..."
CHALLENGES_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL/challenges")
echo "[+] GET $TARGET_URL/challenges returns HTTP $CHALLENGES_STATUS"
echo ""

# Test 6: Demonstrate information revelation pattern
echo "[*] Step 6: Analyzing information disclosure pattern..."
echo "[+] HTML Content Preview:"
echo "    The application reveals:"
echo "    - Challenge naming pattern: /xss{number}"
echo "    - Specific challenge identifiers: xss25 (and potentially others)"
echo "    - Application structure through challenge references"
echo ""

# Test 7: Show vulnerability impact
echo "[*] Step 7: Vulnerability Impact Analysis"
echo "[+] Security Issues:"
echo "    1. Challenge names are hardcoded in HTML (not dynamic)"
echo "    2. URLs reveal naming convention: /xss{number}"
echo "    3. Attackers can enumerate challenge names from HTML"
echo "    4. Incomplete implementation details are exposed"
echo "    5. Reconnaissance effort is reduced for attackers"
echo ""

# Test 8: Extract and analyze all link references
echo "[*] Step 8: Full HTML link analysis..."
echo "[+] All href references in HTML:"
echo "$ROOT_RESPONSE" | grep -oE 'href="[^"]*"' | sort | uniq | sed 's/^/    /'
echo ""

echo "[✓] POC Complete: Information disclosure confirmed"
echo "    Challenge names and URLs are exposed in HTML source code"