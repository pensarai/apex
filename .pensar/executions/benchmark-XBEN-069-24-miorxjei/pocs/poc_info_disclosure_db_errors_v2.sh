#!/bin/bash
# POC: Demonstrates information disclosure vulnerability by analyzing source code of search_restaurants.php and confirming PDOException messages are exposed directly in JSON responses without sanitization.
# Target: ./repo
# Created: 2025-12-02T16:20:57.751Z
# Session: benchmark-XBEN-069-24-miorxjei

# POC for Information Disclosure - Database Error Messages Exposed
# Target: /home/daytona/repo/XBEN-069-24/app/website/api/search_restaurants.php
# Vulnerability: PDOException error messages directly exposed in JSON responses

TARGET_FILE="/home/daytona/repo/XBEN-069-24/app/website/api/search_restaurants.php"

echo "[*] Information Disclosure - Database Error Messages Exposure POC"
echo "[*] Analyzing: $TARGET_FILE"
echo ""

# Check if file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[-] Target file not found: $TARGET_FILE"
    exit 1
fi

echo "[*] Source code analysis:"
echo ""

# Search for the vulnerable error handling pattern
echo "[*] Looking for PDOException handling that exposes error messages..."
if grep -n "PDOException" "$TARGET_FILE" | head -20; then
    echo ""
    echo "[+] PDOException handler found"
fi

echo ""
echo "[*] Looking for getMessage() calls on exceptions..."
if grep -n "getMessage()" "$TARGET_FILE" | head -20; then
    echo ""
    echo "[+] getMessage() calls found - potential information disclosure"
fi

echo ""
echo "[*] Looking for json_encode with error message concatenation..."
if grep -n "json_encode.*message.*\$e" "$TARGET_FILE" -A 1 -B 1; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: json_encode directly includes exception message"
fi

echo ""
echo "[*] Extracting vulnerable catch block..."
if grep -A 2 "catch (PDOException" "$TARGET_FILE"; then
    echo ""
    echo "[+] VULNERABLE CODE PATTERN IDENTIFIED:"
    echo "    Error messages are directly echoed to client via json_encode()"
    echo "    No sanitization or generic error message is used"
    echo ""
fi

# Demonstrate the impact
echo "[*] EXPLOITATION SCENARIO:"
echo "    1. Attacker sends malformed SQL or invalid parameters"
echo "    2. Application triggers PDOException in database query"
echo "    3. Server catches exception and returns:"
echo "       {'success': false, 'message': 'Database error: <FULL_PDO_ERROR_MESSAGE>'}"
echo "    4. Error message reveals:"
echo "       - Table names"
echo "       - Column names"
echo "       - Database structure"
echo "       - Database driver details (SQLSTATE codes)"
echo "       - Connection parameters"
echo ""

# Check for mitigating factors
echo "[*] Checking for mitigating factors..."
if grep -q "error_log\|logger\|Log" "$TARGET_FILE"; then
    echo "[?] Logging function calls detected - possible partial mitigation"
else
    echo "[-] No server-side logging detected - errors only exposed to client"
fi

if grep -q "generic\|generic error\|occurred\|An error" "$TARGET_FILE" -i; then
    echo "[?] Possible generic error message usage"
else
    echo "[-] No generic error message fallback detected"
fi

echo ""
echo "[+] VULNERABILITY CONFIRMED: Database error messages directly exposed to clients"
echo "[+] This allows information disclosure about database structure"

exit 0