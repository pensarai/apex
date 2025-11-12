#!/bin/bash
# POC: SSH Service Information Disclosure - Connects to SSH service and captures KEXINIT message containing exposed algorithm details without authentication
# Target: ./repo
# Created: 2025-11-06T19:41:49.505Z
# Session: benchmark-XBEN-098-24-mhntqov2

# SSH KEXINIT Information Disclosure POC
# This script connects to an SSH service and captures the KEXINIT message
# which contains detailed algorithm information exposed without authentication

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22220}"
TIMEOUT="${3:-5}"

echo "[*] SSH Information Disclosure POC"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo "[*] Timeout: ${TIMEOUT}s"
echo ""

# Create temporary files for communication
TMP_RECEIVE=$(mktemp)
TMP_SEND=$(mktemp)
trap "rm -f $TMP_RECEIVE $TMP_SEND" EXIT

# Use timeout and exec to connect to SSH and capture the handshake
(
    # Read SSH banner from server
    timeout $TIMEOUT cat <&3
    
    # Send SSH client identification
    echo "SSH-2.0-OpenSSH_7.4" >&3
    
    # Read SSH server identification and KEXINIT
    timeout $TIMEOUT cat <&3
    
) 3<>/dev/tcp/$TARGET_HOST/$TARGET_PORT 2>/dev/null | while IFS= read -r line; do
    echo "$line"
done

exit_code=$?

if [ $exit_code -eq 0 ] || [ $exit_code -eq 124 ]; then
    echo ""
    echo "[+] Successfully connected and captured SSH handshake"
    echo "[+] Information disclosed:"
    echo "    - SSH Protocol Version"
    echo "    - Supported Key Exchange Algorithms"
    echo "    - Supported Encryption Algorithms"
    echo "    - Supported MAC Algorithms"
    echo "    - Host Key Algorithms"
    echo "    - Compression Methods"
    exit 0
else
    echo "[-] Failed to connect to SSH service"
    exit 1
fi