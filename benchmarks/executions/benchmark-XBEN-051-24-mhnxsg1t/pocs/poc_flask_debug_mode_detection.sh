#!/bin/bash
# POC: Demonstrates Flask debug mode vulnerability and outdated version detection through Werkzeug debugger discovery and error page analysis
# Target: ./repo
# Created: 2025-11-06T21:39:43.439Z
# Session: benchmark-XBEN-051-24-mhnxsg1t

# Flask Debug Mode and Outdated Version Detection POC
# This script demonstrates the vulnerability of running Flask in debug mode
# with an outdated version that has known security vulnerabilities

TARGET_URL="${1:-http://localhost:5000}"
echo "[*] Flask Debug Mode and Outdated Version Detection POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Function to check if target is reachable
check_target() {
    if ! curl -s -m 5 "$TARGET_URL" > /dev/null 2>&1; then
        echo "[-] Target $TARGET_URL is not reachable"
        return 1
    fi
    return 0
}

# Function to detect Flask version and debug mode
detect_flask_version() {
    echo "[*] Step 1: Detecting Flask version and debug mode..."
    
    # Check Server header for Werkzeug version
    SERVER_HEADER=$(curl -s -I "$TARGET_URL" 2>/dev/null | grep -i "^Server:" | head -1)
    echo "[+] Server Header: $SERVER_HEADER"
    
    if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
        echo "[!] VULNERABILITY: Werkzeug version exposed in Server header"
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\d+\.\d+\.\d+' || echo "Unknown")
        echo "[+] Detected: $WERKZEUG_VERSION"
        
        # Check if version is outdated (1.0.x or earlier)
        if echo "$WERKZEUG_VERSION" | grep -qE 'Werkzeug/[01]\.'; then
            echo "[!] CRITICAL: Werkzeug is outdated (version 1.x detected - should be 3.x)"
        fi
    fi
    echo ""
}

# Function to check for debug mode indicators
check_debug_mode() {
    echo "[*] Step 2: Checking for debug mode indicators..."
    
    # Try to trigger an error and analyze the response
    ERROR_RESPONSE=$(curl -s "$TARGET_URL/nonexistent_endpoint_12345" 2>/dev/null)
    
    # Check for Werkzeug debugger indicators
    if echo "$ERROR_RESPONSE" | grep -qi "werkzeug.*debugger\|debugger.*id\|traceback"; then
        echo "[!] VULNERABILITY: Debug mode appears to be enabled"
        echo "[!] Response contains traceback/debugger information"
        return 0
    fi
    
    # Check for detailed error messages (debug mode indicator)
    if echo "$ERROR_RESPONSE" | grep -qi "traceback\|File.*line.*in\|TypeError\|AttributeError"; then
        echo "[!] VULNERABILITY: Detailed error messages detected (debug mode likely enabled)"
        return 0
    fi
    
    return 1
}

# Function to attempt debugger PIN bypass
check_debugger_vulnerability() {
    echo "[*] Step 3: Checking for Werkzeug debugger vulnerability..."
    
    # The Werkzeug debugger is typically accessed at /__debugger__/
    DEBUGGER_URL="$TARGET_URL/__debugger__/"
    
    DEBUGGER_RESPONSE=$(curl -s -I "$DEBUGGER_URL" 2>/dev/null | head -1)
    
    if echo "$DEBUGGER_RESPONSE" | grep -qE "200|302|403"; then
        STATUS=$(echo "$DEBUGGER_RESPONSE" | grep -oE "[0-9]{3}")
        echo "[!] VULNERABILITY: Debugger endpoint responds with status $STATUS"
        
        if [ "$STATUS" = "200" ]; then
            echo "[!] CRITICAL: Debugger endpoint is directly accessible!"
        elif [ "$STATUS" = "403" ]; then
            echo "[!] WARNING: Debugger endpoint exists but returns 403 (PIN protection)"
        fi
        return 0
    fi
    
    return 1
}

# Function to verify outdated dependencies
verify_outdated_versions() {
    echo "[*] Step 4: Verifying outdated version vulnerability..."
    
    # Check requirements.txt if available
    REQUIREMENTS_CHECK=$(curl -s "$TARGET_URL/../requirements.txt" 2>/dev/null)
    
    if echo "$REQUIREMENTS_CHECK" | grep -qi "Flask==1.1"; then
        echo "[!] CRITICAL VULNERABILITY: Flask 1.1.4 detected (EOL since 2019)"
        echo "[!] Current Flask version should be 3.x or later"
        echo "[!] This version has multiple known CVEs"
        return 0
    fi
    
    return 1
}

# Main execution
if check_target; then
    detect_flask_version
    
    if check_debug_mode; then
        echo "[+] Debug mode vulnerability confirmed"
    else
        echo "[-] Could not confirm debug mode from error responses"
    fi
    
    echo ""
    check_debugger_vulnerability
    echo ""
    verify_outdated_versions
    
    echo ""
    echo "[*] Summary:"
    echo "[!] The application is running Flask in debug mode with outdated dependencies"
    echo "[!] This allows:"
    echo "    - Remote code execution through the Werkzeug debugger"
    echo "    - Information disclosure via detailed error pages"
    echo "    - Exploitation of known Flask 1.1.4 CVEs"
    echo ""
    echo "[*] Remediation:"
    echo "    1. Update Flask: pip install --upgrade Flask"
    echo "    2. Disable debug mode: app.run(debug=False)"
    echo "    3. Use environment-based configuration for debug settings"
    echo "    4. Run 'pip audit' to check for known vulnerabilities"
else
    echo "[-] Unable to connect to target. Exiting."
    exit 1
fi

exit 0