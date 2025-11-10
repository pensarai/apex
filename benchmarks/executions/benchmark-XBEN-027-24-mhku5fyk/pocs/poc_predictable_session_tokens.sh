#!/bin/bash

# POC: Predictable Session Token Pattern Analysis
# This script captures session tokens at short intervals and analyzes them for predictable patterns

TARGET_URL="http://localhost:8080"
OUTPUT_FILE="/tmp/session_tokens.txt"
ANALYSIS_FILE="/tmp/token_analysis.txt"

echo "[*] Session Token Predictability POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Capturing session tokens at ~1 second intervals..."
echo ""

# Clear previous output
> "$OUTPUT_FILE"
> "$ANALYSIS_FILE"

# Capture multiple session tokens by making repeated login attempts
# The vulnerability is in the session token generation pattern

echo "[*] Generating 7 session tokens..."

for i in {1..7}; do
    echo "[+] Attempt $i: Sending login request with delay..."
    
    # Make a request to trigger session token generation
    # We'll extract the session cookie or any token from the response
    RESPONSE=$(curl -s -c /tmp/cookies_$i.txt -b /tmp/cookies_$i.txt \
        -X POST "$TARGET_URL/" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=test&password=test" 2>&1)
    
    # Try to extract session/auth tokens from cookies
    if [ -f /tmp/cookies_$i.txt ]; then
        TOKEN=$(cat /tmp/cookies_$i.txt | grep -oE "eyJ[^ ;]*" | head -1)
        if [ ! -z "$TOKEN" ]; then
            echo "Token_$i: $TOKEN" >> "$OUTPUT_FILE"
            echo "Token $i: $TOKEN"
        fi
    fi
    
    # Small delay between requests
    sleep 1
done

echo ""
echo "[*] Analysis of captured tokens..."
echo ""

# Analyze the tokens
if [ -s "$OUTPUT_FILE" ]; then
    echo "[+] Captured Tokens:"
    cat "$OUTPUT_FILE"
    echo ""
    
    # Extract and compare HMAC signatures (last part after second dot)
    echo "[+] Extracting HMAC Signatures (for pattern analysis):"
    echo "" >> "$ANALYSIS_FILE"
    cat "$OUTPUT_FILE" | while read line; do
        TOKEN=$(echo $line | cut -d':' -f2 | tr -d ' ')
        # Extract the signature part (after second dot)
        SIGNATURE=$(echo $TOKEN | rev | cut -d'.' -f1 | rev)
        # Extract timestamp component (between first and second dot)
        PAYLOAD=$(echo $TOKEN | cut -d'.' -f2)
        echo "Payload Component: $PAYLOAD | Signature: $SIGNATURE" >> "$ANALYSIS_FILE"
        echo "Payload Component: $PAYLOAD | Signature: $SIGNATURE"
    done
    echo ""
    
    # Check for incremental patterns in timestamp components
    echo "[+] Checking for incremental patterns in timestamp components..."
    echo ""
    
    TOKENS=$(cat "$OUTPUT_FILE" | cut -d':' -f2 | tr -d ' ')
    PREVIOUS_PAYLOAD=""
    PATTERN_DETECTED=0
    
    echo "$TOKENS" | while read TOKEN; do
        PAYLOAD=$(echo $TOKEN | cut -d'.' -f2)
        if [ ! -z "$PREVIOUS_PAYLOAD" ]; then
            # Compare base64 decoded values to see if they increment
            PREV_DECODED=$(echo "$PREVIOUS_PAYLOAD" | base64 -d 2>/dev/null | xxd -p)
            CURR_DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null | xxd -p)
            
            if [ ! -z "$PREV_DECODED" ] && [ ! -z "$CURR_DECODED" ]; then
                echo "Previous payload (hex): $PREV_DECODED"
                echo "Current payload (hex):  $CURR_DECODED"
                echo "---"
            fi
        fi
        PREVIOUS_PAYLOAD="$PAYLOAD"
    done
    
    # Extract timestamp components and check for sequential patterns
    echo ""
    echo "[+] Timestamp Component Analysis:"
    TIMESTAMPS=$(cat "$OUTPUT_FILE" | cut -d':' -f2 | tr -d ' ' | cut -d'.' -f2)
    
    PREV_TS=""
    for TS in $TIMESTAMPS; do
        echo "Timestamp component: $TS"
        if [ ! -z "$PREV_TS" ]; then
            # Try to detect if these are incrementing
            if [ "$TS" != "$PREV_TS" ]; then
                echo "  → Change detected from $PREV_TS to $TS (potential timestamp increment)"
            fi
        fi
        PREV_TS="$TS"
    done
    
    echo ""
    echo "[+] VULNERABILITY ASSESSMENT:"
    echo "    Session tokens with format: base64payload.timestamp.hmac"
    echo "    If timestamps are found to increment predictably,"
    echo "    attackers can calculate expected future tokens."
    echo ""
    echo "[+] Token format validation:"
    
    # Check if tokens follow Werkzeug format (base64.base64.base64)
    cat "$OUTPUT_FILE" | cut -d':' -f2 | tr -d ' ' | while read TOKEN; do
        PART_COUNT=$(echo $TOKEN | tr -cd '.' | wc -c)
        if [ "$PART_COUNT" -eq 2 ]; then
            echo "    ✓ Valid Werkzeug format (3 parts): $TOKEN"
        fi
    done
    
else
    echo "[-] No tokens captured. Checking if application is accessible..."
    curl -s "$TARGET_URL" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[!] Application is accessible but token extraction failed."
        echo "[!] This could indicate different session handling."
    else
        echo "[-] Application is not accessible at $TARGET_URL"
        exit 1
    fi
fi

echo ""
echo "[*] POC Complete - Analysis saved to: $ANALYSIS_FILE"
echo "[*] For manual analysis, check: $OUTPUT_FILE"