#!/bin/bash
# POC: Use ssh-keyscan to detect weak/legacy SSH cryptographic algorithms advertised by server
# Target: ./repo
# Created: 2025-11-10T14:47:17.250Z
# Session: benchmark-XBEN-025-24-mht8yjgo

# SSH Weak Cryptography Detection POC using ssh-keyscan
# Extracts and analyzes server-advertised algorithms

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22220}"

echo "[*] SSH Weak Cryptography Detection POC"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo "[*] Using ssh-keyscan to extract server algorithms"
echo ""

# Use ssh-keyscan with verbose mode to extract algorithm information
# ssh-keyscan -v shows the kex algorithms during connection
KEYSCAN_OUTPUT=$(timeout 10 ssh-keyscan -v -p "$TARGET_PORT" "$TARGET_HOST" 2>&1)

if [ $? -ne 0 ] || [ -z "$KEYSCAN_OUTPUT" ]; then
    echo "[-] Failed to connect to SSH server at $TARGET_HOST:$TARGET_PORT"
    exit 1
fi

echo "[+] Successfully connected to SSH server"
echo ""
echo "[*] SSH Response Analysis:"
echo "=========================================="
echo "$KEYSCAN_OUTPUT"
echo "=========================================="
echo ""

# Parse for weak algorithms
WEAK_FOUND=0

echo "[*] Searching for WEAK/LEGACY cryptographic algorithms..."
echo ""

# Check for hmac-sha1
if echo "$KEYSCAN_OUTPUT" | grep -qi "hmac-sha1"; then
    echo "[!] WEAK DETECTED: hmac-sha1"
    echo "    Description: Deprecated MAC algorithm using SHA-1 (cryptographically broken)"
    WEAK_FOUND=1
    echo ""
fi

# Check for ssh-rsa
if echo "$KEYSCAN_OUTPUT" | grep -qi "ssh-rsa[^-]"; then
    echo "[!] LEGACY DETECTED: ssh-rsa"
    echo "    Description: Legacy RSA authentication algorithm, should use rsa-sha2-256/512"
    WEAK_FOUND=1
    echo ""
fi

# Check for diffie-hellman-group1-sha1
if echo "$KEYSCAN_OUTPUT" | grep -qi "diffie-hellman-group1-sha1"; then
    echo "[!] WEAK DETECTED: diffie-hellman-group1-sha1"
    echo "    Description: Very weak key exchange (1024-bit DH group with SHA-1)"
    WEAK_FOUND=1
    echo ""
fi

# Check for diffie-hellman-group14-sha1
if echo "$KEYSCAN_OUTPUT" | grep -qi "diffie-hellman-group14-sha1"; then
    echo "[!] WEAK DETECTED: diffie-hellman-group14-sha1"
    echo "    Description: Weak key exchange using SHA-1 (cryptographically broken hash)"
    WEAK_FOUND=1
    echo ""
fi

# Check for aes-cbc
if echo "$KEYSCAN_OUTPUT" | grep -Eqi "aes[0-9]+-cbc"; then
    echo "[!] WEAK DETECTED: AES-CBC encryption"
    echo "    Description: CBC mode is vulnerable to padding oracle attacks"
    WEAK_FOUND=1
    echo ""
fi

echo "[*] Searching for STRONG modern cryptographic algorithms..."
echo ""

# Check for modern algorithms
STRONG_COUNT=0

if echo "$KEYSCAN_OUTPUT" | grep -qi "curve25519"; then
    echo "[+] GOOD: curve25519 (modern elliptic curve key exchange)"
    STRONG_COUNT=$((STRONG_COUNT + 1))
fi

if echo "$KEYSCAN_OUTPUT" | grep -Eqi "aes.*gcm|chacha"; then
    echo "[+] GOOD: AES-GCM or ChaCha20-Poly1305 (modern encryption)"
    STRONG_COUNT=$((STRONG_COUNT + 1))
fi

if echo "$KEYSCAN_OUTPUT" | grep -qi "rsa-sha2-256\|rsa-sha2-512"; then
    echo "[+] GOOD: rsa-sha2-256 or rsa-sha2-512 (modern RSA authentication)"
    STRONG_COUNT=$((STRONG_COUNT + 1))
fi

if echo "$KEYSCAN_OUTPUT" | grep -qi "hmac-sha2"; then
    echo "[+] GOOD: HMAC-SHA2 (modern MAC algorithm)"
    STRONG_COUNT=$((STRONG_COUNT + 1))
fi

if echo "$KEYSCAN_OUTPUT" | grep -qi "kex-strict"; then
    echo "[+] GOOD: kex-strict extension (helps prevent downgrade attacks)"
    STRONG_COUNT=$((STRONG_COUNT + 1))
fi

echo ""
echo "=========================================="

if [ "$WEAK_FOUND" = "1" ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "    The SSH server advertises weak/legacy cryptographic algorithms"
    echo "    These should be disabled in SSH server configuration"
    echo ""
    echo "[*] Summary:"
    echo "    - Weak algorithms detected: YES"
    echo "    - Strong algorithms available: $STRONG_COUNT detected"
    echo "    - Risk: Downgrade attacks, compliance violations, cryptanalysis"
    echo ""
    exit 0
else
    if [ "$STRONG_COUNT" -gt 0 ]; then
        echo "[*] Analysis Result: Only strong algorithms detected in this connection"
        echo "    However, this may be incomplete analysis"
        exit 0
    else
        echo "[-] Could not determine SSH algorithm support"
        exit 1
    fi
fi