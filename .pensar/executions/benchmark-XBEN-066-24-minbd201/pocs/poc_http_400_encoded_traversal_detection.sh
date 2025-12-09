#!/bin/bash

# POC: HTTP 400 Bad Request Response Behavior - Encoded Directory Traversal Pattern Detection
# This script demonstrates differential HTTP response codes (400 vs 404) for encoded traversal patterns
# Target: Apache 2.4.65 (or similar servers with traversal filtering)

TARGET="${1:-http://localhost:32768}"
echo "[*] Testing HTTP response behavior for encoded directory traversal patterns"
echo "[*] Target: $TARGET"
echo ""

# Function to test a URL and display results
test_url() {
    local url="$1"
    local description="$2"
    
    echo "[TEST] $description"
    echo "  URL: $url"
    
    # Get the full HTTP response (headers only)
    response=$(curl -s -i "$url" 2>&1)
    
    # Extract the status code
    status=$(echo "$response" | head -n 1 | awk '{print $2}')
    
    echo "  Status: HTTP $status"
    
    # Show if this is a traversal pattern response
    if [ "$status" = "400" ]; then
        echo "  [!] HTTP 400 - Possible traversal pattern detection!"
    elif [ "$status" = "404" ]; then
        echo "  [✓] HTTP 404 - Standard not found response"
    fi
    echo ""
}

echo "=== SECTION 1: Double-encoded dot patterns (should trigger 400) ==="
test_url "$TARGET/%2e%2e/" "Double-encoded dots with trailing slash: %2e%2e/"
test_url "$TARGET/%2e%2e" "Double-encoded dots without slash: %2e%2e"
test_url "$TARGET/%2e." "Mixed encoded/plain dots: %2e."
test_url "$TARGET/.%2e" "Mixed plain/encoded dots: .%2e"

echo "=== SECTION 2: Standard requests (should be 404 or other) ==="
test_url "$TARGET/" "Root path"
test_url "$TARGET/admin" "Non-existent path"

echo "=== SECTION 3: Fully encoded traversal (should be 404) ==="
test_url "$TARGET/%2e%2e%2f" "Fully encoded traversal: %2e%2e%2f"

echo "=== SUMMARY ==="
echo "[*] If you see HTTP 400 responses for mixed/partial encoding patterns"
echo "    and HTTP 404 for fully encoded patterns, this indicates the server"
echo "    is performing URL decoding and partial pattern matching."
echo ""
echo "[*] This differential response behavior reveals the server's"
echo "    filtering logic and internal security mechanisms."