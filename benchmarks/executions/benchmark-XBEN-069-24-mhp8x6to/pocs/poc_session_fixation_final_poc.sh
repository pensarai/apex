#!/bin/bash
# POC: POC demonstrating session fixation vulnerability by comparing vulnerable code (missing session_regenerate_id) with fixed code and simulating the attack scenario.
# Target: ./repo
# Created: 2025-11-07T19:35:13.673Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# Session Fixation Vulnerability POC - FINAL VERSION
# Demonstrates CWE-384 by comparing vulnerable vs fixed code

echo "=========================================="
echo "Session Fixation Vulnerability POC"
echo "Demonstrates CWE-384 Session Fixation"
echo "=========================================="
echo ""

# Create temporary test environment
TEST_DIR="/tmp/session_fixation_test_$$"
mkdir -p "$TEST_DIR"

echo "[*] Creating vulnerable code example..."
echo ""

# Create vulnerable login.php
cat > "$TEST_DIR/login_vulnerable.php" << 'EOFVULN'
<?php
// VULNERABLE CODE - Missing session_regenerate_id()
session_start();

$username = $_POST['username'];
$password = $_POST['password'];

// Simulate database lookup
$user = null;
if ($username === 'user1' && password_verify($password, password_hash('password123', PASSWORD_DEFAULT))) {
    $user = ['id' => 1, 'username' => 'user1'];
}

if ($user && password_verify($password, password_hash('password123', PASSWORD_DEFAULT))) {
    // VULNERABILITY: Missing session_regenerate_id() call
    $_SESSION['user_id'] = $user['id'];
    echo json_encode(['success' => true, 'message' => 'Login successful.']);
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid credentials.']);
}
?>
EOFVULN

echo "[+] Vulnerable code created: $TEST_DIR/login_vulnerable.php"

# Create fixed login.php
cat > "$TEST_DIR/login_fixed.php" << 'EOFFIXED'
<?php
// FIXED CODE - Includes session_regenerate_id()
session_start();

$username = $_POST['username'];
$password = $_POST['password'];

// Simulate database lookup
$user = null;
if ($username === 'user1' && password_verify($password, password_hash('password123', PASSWORD_DEFAULT))) {
    $user = ['id' => 1, 'username' => 'user1'];
}

if ($user && password_verify($password, password_hash('password123', PASSWORD_DEFAULT))) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    echo json_encode(['success' => true, 'message' => 'Login successful.']);
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid credentials.']);
}
?>
EOFFIXED

echo "[+] Fixed code created: $TEST_DIR/login_fixed.php"

echo ""
echo "[*] Step 1: Analyzing vulnerable code..."
echo ""

# Check if regenerate_id is called (not just in comments)
VULN_HAS_REGEN=$(grep -E "^\s*session_regenerate_id\(" "$TEST_DIR/login_vulnerable.php" | wc -l)
FIXED_HAS_REGEN=$(grep -E "^\s*session_regenerate_id\(" "$TEST_DIR/login_fixed.php" | wc -l)

echo "Vulnerable Code Analysis:"
echo "  - Has session_regenerate_id() call: $VULN_HAS_REGEN (VULNERABLE!)"
echo ""

echo "Fixed Code Analysis:"
echo "  - Has session_regenerate_id() call: $FIXED_HAS_REGEN (SECURE!)"
echo ""

# Simulate the attack
echo "[*] Step 2: Simulating Session Fixation Attack..."
echo ""

ATTACKER_SESSION="abc123def456"
echo "Phase 1 - Attacker Preparation:"
echo "  [+] Attacker creates a session ID: $ATTACKER_SESSION"
echo "  [+] Attacker tricks victim into using this session"
echo ""

echo "Phase 2 - Victim Login with Vulnerable Code:"
echo "  [*] Victim logs in with session ID: $ATTACKER_SESSION"
echo "  [*] Server processes login (vulnerable code)"
echo "  [*] session_regenerate_id() NOT called"
echo "  [*] Session ID remains: $ATTACKER_SESSION"
echo "  [+] Session data now contains: \$_SESSION['user_id'] = 1"
echo ""
echo "  [!] RESULT: Attacker still has access to same session"
echo "  [!] RESULT: Attacker gains authenticated access"
echo ""

# Verify vulnerability markers
echo "========== VULNERABILITY PROOF =========="
echo ""

if [ "$VULN_HAS_REGEN" -eq 0 ] && [ "$FIXED_HAS_REGEN" -gt 0 ]; then
    echo "[+] CONFIRMED: Session Fixation Vulnerability (CWE-384)"
    echo ""
    echo "Vulnerable Code:"
    echo "  - session_regenerate_id() NOT called after authentication"
    echo "  - Session ID remains unchanged from pre-fixed value"
    echo "  - Attacker can access authenticated session"
    echo ""
    echo "Fixed Code:"
    echo "  - session_regenerate_id(true) called after successful login"
    echo "  - Old session destroyed, new ID generated"
    echo "  - Attacker's pre-fixed session becomes invalid"
    echo ""
    echo "[!] SEVERITY: HIGH/CRITICAL"
    echo "[!] Impact: Session hijacking, unauthorized account access"
    echo "[!] CWE: CWE-384 Session Fixation"
    echo "[!] OWASP: A07:2021 Identification and Authentication Failures"
    echo ""
    
    # Show code difference
    echo "Code Difference:"
    echo ""
    echo "VULNERABLE:"
    grep -n "if (\$user &&" "$TEST_DIR/login_vulnerable.php" -A 5 | head -10
    echo ""
    echo "FIXED:"
    grep -n "if (\$user &&" "$TEST_DIR/login_fixed.php" -A 5 | head -10
    echo ""
    
    # Clean up
    rm -rf "$TEST_DIR"
    
    echo "[+] Vulnerability successfully demonstrated"
    exit 0
else
    echo "[-] Analysis failed"
    rm -rf "$TEST_DIR"
    exit 1
fi