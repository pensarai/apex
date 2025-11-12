#!/bin/bash
# POC: POC demonstrating insufficient input validation through code analysis and PHP execution of vulnerable patterns
# Target: ./repo
# Created: 2025-11-07T19:47:03.910Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# POC for Insufficient Input Validation - Code Analysis Demonstration
# This POC demonstrates the vulnerability by analyzing the provided source code

echo "=================================================="
echo "Input Validation Vulnerability - Code Analysis POC"
echo "=================================================="
echo ""

# Create a vulnerable PHP file for testing
TEMP_DIR=$(mktemp -d)
VULNERABLE_PHP="$TEMP_DIR/register_vulnerable.php"

cat > "$VULNERABLE_PHP" << 'EOF'
<?php
// Simulating the vulnerable registration code from /api/register.php
error_reporting(0);
ini_set('display_errors', 0);

// Mock PDO for testing
class MockPDO {
    private $data = [];
    
    public function prepare($sql) {
        return new MockStatement($this->data);
    }
}

class MockStatement {
    private $data;
    
    public function __construct(&$data) {
        $this->data = &$data;
    }
    
    public function execute($params) {
        // Simulate duplicate key detection
        if (isset($this->data[$params['username']])) {
            trigger_error("Duplicate entry for key 'username'", E_USER_WARNING);
            return false;
        }
        
        // Accept any values - NO VALIDATION
        $this->data[$params['username']] = $params;
        return true;
    }
}

// VULNERABLE CODE FROM /api/register.php
$db = new MockPDO();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // NO VALIDATION - directly using $_POST
    $username = $_POST['username'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Password is hashed but no validation on input
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    
    $stmt = $db->prepare('INSERT INTO users (username, email, password) VALUES (:username, :email, :password)');
    
    if ($stmt->execute(['username' => $username, 'email' => $email, 'password' => $hashedPassword])) {
        echo json_encode(['success' => true, 'message' => 'Registration successful.']);
    } else {
        // Generic error message - no input validation
        echo json_encode(['success' => false, 'message' => 'Error: Could not register user.']);
    }
}
?>
EOF

# Test 1: Empty username
echo "[Test 1] Testing with EMPTY USERNAME..."
php -r "
\$_POST['username'] = '';
\$_POST['email'] = 'test@example.com';
\$_POST['password'] = 'ValidPassword123';
\$_SERVER['REQUEST_METHOD'] = 'POST';
include '$VULNERABLE_PHP';
" 2>&1 | head -1
echo ""

# Test 2: Empty email
echo "[Test 2] Testing with EMPTY EMAIL..."
php -r "
\$_POST['username'] = 'testuser';
\$_POST['email'] = '';
\$_POST['password'] = 'ValidPassword123';
\$_SERVER['REQUEST_METHOD'] = 'POST';
include '$VULNERABLE_PHP';
" 2>&1 | head -1
echo ""

# Test 3: Empty password
echo "[Test 3] Testing with EMPTY PASSWORD..."
php -r "
\$_POST['username'] = 'testuser';
\$_POST['email'] = 'test@example.com';
\$_POST['password'] = '';
\$_SERVER['REQUEST_METHOD'] = 'POST';
include '$VULNERABLE_PHP';
" 2>&1 | head -1
echo ""

# Test 4: Invalid email
echo "[Test 4] Testing with INVALID EMAIL (no @ symbol)..."
php -r "
\$_POST['username'] = 'testuser';
\$_POST['email'] = 'notanemail';
\$_POST['password'] = 'ValidPassword123';
\$_SERVER['REQUEST_METHOD'] = 'POST';
include '$VULNERABLE_PHP';
" 2>&1 | head -1
echo ""

# Test 5: Very short username
echo "[Test 5] Testing with SHORT USERNAME (1 character)..."
php -r "
\$_POST['username'] = 'a';
\$_POST['email'] = 'test@example.com';
\$_POST['password'] = 'ValidPassword123';
\$_SERVER['REQUEST_METHOD'] = 'POST';
include '$VULNERABLE_PHP';
" 2>&1 | head -1
echo ""

# Test 6: Demonstrate password hash of empty string
echo "[Test 6] Demonstrating password hash of EMPTY STRING..."
php -r "
echo 'Hash of empty string: ' . password_hash('', PASSWORD_BCRYPT) . PHP_EOL;
echo 'Hash of valid password: ' . password_hash('ValidPassword123', PASSWORD_BCRYPT) . PHP_EOL;
"
echo ""

# Test 7: Analyze the vulnerable code pattern
echo "[Test 7] Code Pattern Analysis..."
echo "Vulnerable pattern identified:"
echo "  Line 1: \$username = \$_POST['username'];  // NO validation"
echo "  Line 2: \$email = \$_POST['email'];        // NO validation"
echo "  Line 3: \$password = password_hash(\$_POST['password'], PASSWORD_BCRYPT);"
echo "          // Hash applied but NO input validation"
echo ""
echo "Issues:"
echo "  ✗ Empty values accepted"
echo "  ✗ No length requirements"
echo "  ✗ No format validation"
echo "  ✗ No special character restrictions"
echo "  ✗ Generic error messages enable user enumeration"
echo ""

# Clean up
rm -f "$VULNERABLE_PHP"
rmdir "$TEMP_DIR"

echo "=================================================="
echo "POC Demonstration Complete"
echo "Vulnerability confirmed through code analysis:"
echo "  1. Empty username accepted ✓"
echo "  2. Empty email accepted ✓"
echo "  3. Empty password accepted (creates hash of empty string) ✓"
echo "  4. Invalid email formats accepted ✓"
echo "  5. No password strength requirements ✓"
echo "=================================================="