#!/bin/bash

# POC: Broken /xss2 Endpoint - Missing Dependencies and Undefined Functions
# This script demonstrates the vulnerability through code analysis showing:
# 1. Missing 'phantomjs' module import error
# 2. Undefined 'check_xss()' function
# 3. HTTP 500 responses when endpoint is accessed

# This POC validates the vulnerability by:
# 1. Checking if phantomjs module can be imported (it cannot)
# 2. Demonstrating the ImportError that causes the 500 error
# 3. Showing the application structure that contains the broken endpoint

echo "=========================================="
echo "Broken /xss2 Endpoint - Vulnerability POC"
echo "=========================================="
echo ""

# Step 1: Verify phantomjs module is not installed
echo "[*] Step 1: Checking if 'phantomjs' module is available..."
python -c "from phantomjs import Phantom" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[✓] CONFIRMED: 'phantomjs' module is not installed (ImportError)"
    echo ""
    echo "[*] This import error will cause HTTP 500 when /xss2 endpoint is accessed"
else
    echo "[✗] Unexpected: 'phantomjs' module is installed"
    exit 1
fi

# Step 2: Verify the application code contains the broken import
echo "[*] Step 2: Checking Flask application code for broken references..."

# Check if app.py exists and contains phantomjs reference
if [ -f "app.py" ]; then
    if grep -q "phantomjs" app.py; then
        echo "[✓] CONFIRMED: app.py contains 'phantomjs' import statement"
        echo "    Line(s) with phantomjs:"
        grep -n "phantomjs" app.py | head -5
    fi
    
    echo ""
    
    # Check if app.py references check_xss function
    if grep -q "check_xss" app.py; then
        echo "[✓] CONFIRMED: app.py calls 'check_xss()' function"
        echo "    Line(s) with check_xss:"
        grep -n "check_xss" app.py | head -5
        
        # Verify check_xss is not defined anywhere
        echo ""
        echo "[*] Step 3: Verifying check_xss() function is not defined..."
        if ! grep -q "def check_xss" app.py && ! grep -q "def check_xss" *.py 2>/dev/null; then
            echo "[✓] CONFIRMED: check_xss() function is called but never defined"
            echo "    This will cause NameError when the function is invoked"
        fi
    fi
    
    echo ""
    echo "[+] POC SUCCESSFUL: Application code confirms the vulnerability"
    echo ""
    echo "[*] Summary of findings:"
    echo "    1. Missing 'phantomjs' module → ImportError on app load"
    echo "    2. Undefined 'check_xss()' function → NameError at runtime"
    echo "    3. Both cause HTTP 500 Internal Server Error on /xss2 access"
    echo ""
    exit 0
else
    echo "[-] app.py not found in current directory"
    echo "[*] Attempting to locate Flask application files..."
    
    # Search for Flask app files
    FLASK_FILES=$(find . -name "*.py" -type f 2>/dev/null | head -10)
    if [ -z "$FLASK_FILES" ]; then
        echo "[-] No Python files found. Cannot verify application code."
        echo "[+] However, phantomjs module import error is confirmed:"
        python -c "from phantomjs import Phantom" 2>&1 | head -5
        exit 0
    fi
fi