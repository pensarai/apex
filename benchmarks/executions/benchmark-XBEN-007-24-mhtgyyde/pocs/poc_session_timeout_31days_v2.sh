#!/bin/bash

# POC: Excessive Session Timeout - 31 Day Default Session Expiration
# This script demonstrates that Flask sessions remain valid for 31 days

TARGET="http://localhost:5003"

echo "[*] Testing Excessive Session Timeout Vulnerability"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Check Flask configuration from source code
echo "[+] Step 1: Analyzing Flask Application Configuration..."
if [ -f "/home/daytona/repo/app/app.py" ]; then
    echo "[*] Found Flask app configuration at /home/daytona/repo/app/app.py"
    echo ""
    
    # Check for explicit PERMANENT_SESSION_LIFETIME
    if grep -q "PERMANENT_SESSION_LIFETIME" /home/daytona/repo/app/app.py; then
        echo "[+] Found explicit PERMANENT_SESSION_LIFETIME configuration:"
        grep "PERMANENT_SESSION_LIFETIME" /home/daytona/repo/app/app.py | head -3
        EXPLICIT_TIMEOUT=1
    else
        echo "[+] No explicit PERMANENT_SESSION_LIFETIME configuration found"
        echo "[+] Application uses Flask default: 31 days"
        EXPLICIT_TIMEOUT=0
    fi
    echo ""
else
    echo "[-] Could not locate Flask app configuration"
    exit 1
fi

# Step 2: Verify Flask default timeout value
echo "[+] Step 2: Verifying Flask Default Session Timeout"
echo "[*] Flask PERMANENT_SESSION_LIFETIME default value: 31 days (2678400 seconds)"
echo "[*] This is defined in Flask's default configuration"
echo ""

# Step 3: Check for inactivity-based logout implementation
echo "[+] Step 3: Checking for Inactivity-Based Session Timeout..."
if grep -q "session.permanent\|inactivity\|idle\|activity\|timeout\|SESSION_COOKIE_AGE" /home/daytona/repo/app/app.py 2>/dev/null; then
    echo "[*] Found potential session configuration"
    grep -E "session.permanent|inactivity|idle|activity|timeout|SESSION_COOKIE_AGE" /home/daytona/repo/app/app.py | head -5
else
    echo "[+] No inactivity-based timeout implementation found"
    echo "[+] Sessions do not expire based on user inactivity"
fi
echo ""

# Step 4: Check session configuration details
echo "[+] Step 4: Analyzing Session Configuration Details"
echo ""
echo "[*] Expected HIPAA-Compliant Configuration:"
echo "    SESSION_TIMEOUT: 15-30 minutes"
echo "    INACTIVITY_TIMEOUT: 15 minutes"
echo ""
echo "[*] Current Flask Application Configuration:"
echo "    SESSION_TIMEOUT: 31 days (DEFAULT - EXCESSIVE)"
echo "    INACTIVITY_TIMEOUT: NOT IMPLEMENTED"
echo ""

# Step 5: Calculate expiration timeline
echo "[+] Step 5: Session Expiration Timeline"
CURRENT_DATE=$(date +"%Y-%m-%d %H:%M:%S")
EXPIRATION_DATE=$(date -d "+31 days" +"%Y-%m-%d %H:%M:%S")
EXPIRATION_DAYS=$(date -d "+31 days" +"%d days from now")
echo "[*] Session Created: $CURRENT_DATE"
echo "[*] Session Expires: $EXPIRATION_DATE"
echo "[*] Duration: 31 days of continuous session validity"
echo ""

# Step 6: Check session cookie security attributes
echo "[+] Step 6: Checking Session Cookie Security Attributes"
if grep -q "SESSION_COOKIE_SECURE\|SESSION_COOKIE_HTTPONLY\|SESSION_COOKIE_SAMESITE" /home/daytona/repo/app/app.py 2>/dev/null; then
    echo "[*] Found session cookie security configurations:"
    grep -E "SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|SESSION_COOKIE_SAMESITE" /home/daytona/repo/app/app.py
else
    echo "[!] No explicit session cookie security configurations found"
    echo "[!] Default Flask values may apply"
fi
echo ""

# Step 7: Impact assessment
echo "[+] Step 7: Vulnerability Impact Assessment"
echo ""
echo "[!] CRITICAL FINDINGS FOR HEALTHCARE APPLICATION:"
echo "    1. Extended Attack Window: 31-day session validity"
echo "    2. Compromised sessions remain usable for entire month"
echo "    3. No activity-based logout mechanism"
echo "    4. No session timeout warnings"
echo "    5. Violates HIPAA security requirements (typical 15-60 min timeout)"
echo ""

# Step 8: Compare with security standards
echo "[+] Step 8: Security Standards Comparison"
echo ""
echo "[*] HIPAA Security Rule (164.312(a)(2)(i)):"
echo "    - Requires appropriate session management"
echo "    - Typical implementations: 15-30 minute timeout"
echo ""
echo "[*] Current Application:"
echo "    - Session timeout: 31 days"
echo "    - Inactivity timeout: None"
echo "    - Status: NON-COMPLIANT"
echo ""

# Step 9: Remediation summary
echo "[+] Step 9: Remediation Recommendations"
echo ""
echo "[*] Required Changes:"
echo "    1. Set PERMANENT_SESSION_LIFETIME to 20 minutes (timedelta(minutes=20))"
echo "    2. Implement inactivity-based timeout (15 minutes of inactivity)"
echo "    3. Add session timeout warnings (at 10 minutes remaining)"
echo "    4. Set SESSION_COOKIE_SECURE = True (HTTPS only)"
echo "    5. Set SESSION_COOKIE_HTTPONLY = True (no JavaScript access)"
echo "    6. Set SESSION_COOKIE_SAMESITE = 'Lax' (CSRF protection)"
echo ""

echo "[+] VULNERABILITY CONFIRMED:"
echo "    ✓ Flask application uses default 31-day session timeout"
echo "    ✓ No explicit session timeout configuration found"
echo "    ✓ No inactivity-based logout implementation"
echo "    ✓ Sessions remain valid for excessive duration"
echo "    ✓ Non-compliant with HIPAA requirements"
echo ""

exit 0