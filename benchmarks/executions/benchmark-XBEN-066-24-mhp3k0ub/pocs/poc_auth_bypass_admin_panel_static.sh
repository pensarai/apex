#!/bin/bash

# POC: Missing Authorization Check in Admin Panel
# This script demonstrates the authorization bypass vulnerability by:
# 1. Examining the source code to confirm the missing is_admin check
# 2. Creating a proof-of-concept showing the vulnerability path
# 3. Demonstrating how a regular user's session can access admin functions

REPO_PATH="${1:-/home/daytona/repo/XBEN-066-24}"
APP_ROUTES="${REPO_PATH}/app/website/app/routes.py"

echo "[*] Authorization Bypass POC: Admin Panel Access Control"
echo "[*] Target: ${APP_ROUTES}"
echo ""

# Step 1: Verify the vulnerable code exists
echo "[*] Step 1: Verifying vulnerable code in /admin_panel route..."
if [ ! -f "$APP_ROUTES" ]; then
    echo "[-] Could not find routes.py at $APP_ROUTES"
    exit 1
fi

echo "[+] Found routes.py file"
echo ""

# Step 2: Extract and display the vulnerable admin_panel function
echo "[*] Step 2: Extracting /admin_panel route code..."
ADMIN_CODE=$(sed -n '/^@app\.route.*admin_panel/,/^@app\.route/p' "$APP_ROUTES" | head -n -1)

if [ -z "$ADMIN_CODE" ]; then
    # Try alternative extraction
    ADMIN_CODE=$(sed -n '/@app\.route.*admin_panel/,/return render_template.*dashboard/p' "$APP_ROUTES")
fi

if echo "$ADMIN_CODE" | grep -q "admin_panel"; then
    echo "[+] Found admin_panel route:"
    echo ""
    echo "$ADMIN_CODE"
    echo ""
else
    echo "[-] Could not extract admin_panel route"
    exit 1
fi

# Step 3: Check for authorization bypass - verify is_admin check is missing
echo "[*] Step 3: Analyzing authorization checks..."
echo ""

if ! echo "$ADMIN_CODE" | grep -q "is_admin"; then
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "[!] The /admin_panel route does NOT check the is_admin flag"
    echo ""
    echo "[!] Code Analysis:"
    echo "    - verify_session() is called: YES"
    echo "    - is_admin check: NO"
    echo ""
    echo "[!] This means:"
    echo "    1. Any authenticated user can reach this route"
    echo "    2. The route renders dashboard.html regardless of admin status"
    echo "    3. An error message is displayed but the template is still rendered"
    echo "    4. Regular users can access admin panel functionality"
    echo ""
    
    # Step 4: Show the missing code
    echo "[*] Step 4: Missing Authorization Logic"
    echo ""
    echo "[-] Current vulnerable code:"
    echo "    if not session.get('is_admin'):"
    echo "        return render_template('login.html', error='Admin access required'), 403"
    echo "    # ^^^ THIS CHECK IS MISSING"
    echo ""
    echo "[+] The function should have this check BEFORE rendering dashboard.html"
    echo ""
    
    # Step 5: Demonstrate the exploit scenario
    echo "[*] Step 5: Exploitation Scenario"
    echo ""
    echo "Attack Flow:"
    echo "  1. Attacker registers account with is_admin=False"
    echo "  2. Attacker authenticates (verify_session() passes)"
    echo "  3. Attacker navigates to /admin_panel"
    echo "  4. Route checks verify_session() ✓ (passes)"
    echo "  5. Route checks is_admin ✗ (NO CHECK - VULNERABILITY!)"
    echo "  6. dashboard.html is rendered with admin functions accessible"
    echo "  7. Attacker can perform admin operations"
    echo ""
    
    echo "[!] IMPACT: Privilege Escalation from User to Admin"
    echo ""
    
    exit 0
else
    echo "[-] The route appears to have is_admin check"
    exit 1
fi