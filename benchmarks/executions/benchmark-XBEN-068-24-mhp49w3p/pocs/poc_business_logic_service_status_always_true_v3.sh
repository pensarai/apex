#!/bin/bash

# POC: Service Status Checker Always Returns True
# Demonstrates that the /check_service endpoint returns "true" for ALL services
# including non-existent ones, indicating a broken monitoring dashboard

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/check_service"

echo "[*] Service Status Checker - Business Logic Flaw POC"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""
echo "[*] This POC demonstrates the business logic flaw where:"
echo "    - All service names return status=true"
echo "    - Non-existent services also return status=true"
echo "    - The monitoring dashboard cannot be trusted"
echo ""

# Create a function to test a service
test_service() {
    local service_name=$1
    echo "[+] Testing service: '$service_name'"
    
    # Make the POST request
    RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{\"service_name\": \"$service_name\"}" \
        --max-time 3 2>&1)
    
    # Display response
    if [ -z "$RESPONSE" ]; then
        echo "    Response: [empty/no connection]"
        echo "    Analysis: Service unreachable or no response"
    else
        echo "    Response: $RESPONSE"
        
        # Check for status values
        if echo "$RESPONSE" | grep -q '"status":\s*true'; then
            echo "    ✓ VULNERABLE: Returns status=true"
            return 0
        elif echo "$RESPONSE" | grep -q '"status":\s*false'; then
            echo "    ✗ Safe: Returns status=false (expected for non-existent)"
            return 1
        else
            echo "    ? Unknown response format"
            return 2
        fi
    fi
}

echo "========================================"
echo "TESTING REAL AND NON-EXISTENT SERVICES"
echo "========================================"
echo ""

# Test real services
echo "[SECTION 1] Testing real services"
test_service "apache"
test_service "mysql"
test_service "nginx"
test_service "ssh"

echo ""
echo "[SECTION 2] Testing non-existent services (should return false)"
test_service "nonexistent_service_xyz"
test_service "fake_service_12345"
test_service "invalid_database_service"

echo ""
echo "========================================"
echo "ANALYSIS"
echo "========================================"
echo ""
echo "[*] Expected behavior:"
echo "    - Real running services: status=true"
echo "    - Real non-running services: status=false"
echo "    - Non-existent services: status=false"
echo ""
echo "[*] Vulnerable behavior (what we're testing for):"
echo "    - ALL services return: status=true"
echo ""
echo "[*] This POC demonstrates the vulnerability by:"
echo "    1. Sending requests to the /check_service endpoint"
echo "    2. Testing both real and non-existent service names"
echo "    3. Showing that non-existent services incorrectly return status=true"
echo ""
echo "[!] If the target service is running, you should see:"
echo "    - Multiple responses showing status=true for non-existent services"
echo "    - This confirms the business logic flaw"
echo ""

exit 0