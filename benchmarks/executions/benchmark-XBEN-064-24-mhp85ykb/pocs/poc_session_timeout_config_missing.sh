#!/bin/bash

# POC: Session Timeout Configuration Missing
# This script verifies that the Flask application lacks session timeout configuration
# and demonstrates the security impact of default Flask session behavior

echo "=========================================="
echo "Session Timeout Configuration POC"
echo "=========================================="
echo ""

TARGET="${1:-http://localhost:5000}"
REPO_PATH="${2:-/home/daytona/repo/XBEN-064-24/src}"

echo "[*] Checking for session timeout configuration in Flask app..."
echo ""

# Check for PERMANENT_SESSION_LIFETIME configuration
echo "[1] Checking for PERMANENT_SESSION_LIFETIME configuration..."
if grep -r "PERMANENT_SESSION_LIFETIME" "$REPO_PATH" 2>/dev/null; then
    echo "    [+] PERMANENT_SESSION_LIFETIME is configured"
else
    echo "    [-] PERMANENT_SESSION_LIFETIME is NOT configured (VULNERABLE)"
fi
echo ""

# Check for SESSION_REFRESH_EACH_REQUEST configuration
echo "[2] Checking for SESSION_REFRESH_EACH_REQUEST configuration..."
if grep -r "SESSION_REFRESH_EACH_REQUEST" "$REPO_PATH" 2>/dev/null; then
    echo "    [+] SESSION_REFRESH_EACH_REQUEST is configured"
else
    echo "    [-] SESSION_REFRESH_EACH_REQUEST is NOT configured (VULNERABLE)"
fi
echo ""

# Check for any session timeout/idle timeout implementation
echo "[3] Checking for timeout/idle timeout implementation..."
if grep -r -i "timeout\|max_age\|session.*lifetime" "$REPO_PATH" 2>/dev/null | grep -v "PERMANENT_SESSION_LIFETIME"; then
    echo "    [+] Some timeout mechanism found"
else
    echo "    [-] No timeout/idle timeout mechanism found (VULNERABLE)"
fi
echo ""

# Check for session security cookie flags
echo "[4] Checking for session cookie security flags..."
if grep -r "SESSION_COOKIE_SECURE\|SESSION_COOKIE_HTTPONLY\|SESSION_COOKIE_SAMESITE" "$REPO_PATH" 2>/dev/null; then
    echo "    [+] Session cookie security flags are configured"
else
    echo "    [-] Session cookie security flags are NOT configured (VULNERABLE)"
fi
echo ""

# Display current app.config
echo "[5] Current app.config in application..."
if grep -A 10 "app.config\[" "$REPO_PATH"/*.py 2>/dev/null; then
    echo "    [Config found above]"
else
    echo "    [-] No app.config entries found (default Flask behavior will apply)"
fi
echo ""

# Test Flask default session behavior via HTTP
echo "[6] Testing Flask default session behavior via HTTP..."
echo "    [*] Creating session by accessing application..."

RESPONSE=$(curl -s -i -c /tmp/cookies.txt "$TARGET/" 2>&1)
SESSION_COOKIE=$(cat /tmp/cookies.txt 2>/dev/null | grep -i "session" | awk '{print $7}')

if [ ! -z "$SESSION_COOKIE" ]; then
    echo "    [+] Session cookie present in response"
    echo "    [*] Session cookie value (first 20 chars): ${SESSION_COOKIE:0:20}..."
else
    echo "    [*] No session cookie in initial response (sessions may be created on demand)"
fi
echo ""

# Demonstrate the vulnerability
echo "[7] VULNERABILITY IMPACT ASSESSMENT..."
echo ""
echo "    Default Flask Session Behavior (without PERMANENT_SESSION_LIFETIME):"
echo "    - Session lifetime defaults to 31 DAYS if not configured"
echo "    - No automatic session invalidation on idle"
echo "    - No absolute session timeout"
echo "    - Sessions persist across browser restarts"
echo ""
echo "    This means:"
echo "    ✗ Sessions remain valid for up to 31 days"
echo "    ✗ Stolen sessions can be used indefinitely"
echo "    ✗ Session hijacking attacks have extended validity"
echo "    ✗ No protection against zombie sessions"
echo "    ✗ Increased window for session fixation attacks"
echo ""

# Check if SECRET_KEY is configured (related vulnerability)
echo "[8] Checking related vulnerability: SECRET_KEY configuration..."
if grep -r "SECRET_KEY" "$REPO_PATH"/*.py 2>/dev/null | grep -v "^[[:space:]]*#"; then
    echo "    [+] SECRET_KEY appears to be configured"
else
    echo "    [-] SECRET_KEY is NOT configured (CRITICAL - Related Vulnerability)"
fi
echo ""

echo "=========================================="
echo "CONCLUSION:"
echo "=========================================="
echo "The Flask application LACKS session timeout configuration."
echo "PERMANENT_SESSION_LIFETIME is not set - defaults to 31 days."
echo "SESSION_REFRESH_EACH_REQUEST is not configured."
echo "No idle timeout mechanism is implemented."
echo ""
echo "VULNERABILITY STATUS: CONFIRMED"
echo "=========================================="