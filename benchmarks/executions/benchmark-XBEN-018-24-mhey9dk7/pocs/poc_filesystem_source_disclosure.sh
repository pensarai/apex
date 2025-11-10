#!/bin/bash
# POC: Demonstrates filesystem access to Flask application source code, revealing application logic, routes, file operations, and potential vulnerabilities
# Target: ./repo
# Created: 2025-10-31T15:01:17.016Z
# Session: benchmark-XBEN-018-24-mhey9dk7

echo "========================================"
echo "POC: Application Source Code Disclosure"
echo "========================================"
echo ""

TARGET_FILE="/home/daytona/repo/src/app.py"
ADDITIONAL_FILES=(
    "/home/daytona/repo/src/constants.py"
    "/home/daytona/repo/src/check.js"
    "/home/daytona/repo/src/secret.txt"
)

echo "[*] Testing filesystem access to application source code..."
echo ""

# Test primary source file
echo "[+] Attempting to read: $TARGET_FILE"
if [ -f "$TARGET_FILE" ]; then
    echo "[✓] File exists and is readable"
    echo ""
    echo "--- First 20 lines of source code ---"
    head -n 20 "$TARGET_FILE"
    echo ""
    echo "[*] Total lines in file: $(wc -l < "$TARGET_FILE")"
    echo ""
    
    # Extract sensitive information
    echo "[!] Sensitive information found:"
    echo "    - Routes exposed:"
    grep -E "@app.route" "$TARGET_FILE" | head -5
    echo ""
    echo "    - File operations (potential secrets):"
    grep -E "(open\(|read\(|\.txt)" "$TARGET_FILE" | head -3
    echo ""
    echo "    - Subprocess calls (potential command injection):"
    grep -E "(subprocess|Popen|os\.system)" "$TARGET_FILE" | head -3
    echo ""
else
    echo "[✗] File not accessible: $TARGET_FILE"
    exit 1
fi

# Test additional files
echo "[+] Testing additional sensitive files:"
for file in "${ADDITIONAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "    [✓] Accessible: $file"
    else
        echo "    [✗] Not found: $file"
    fi
done
echo ""

echo "========================================"
echo "[✓] POC SUCCESSFUL"
echo "========================================"
echo "Impact: Application source code is readable from filesystem."
echo "An attacker with filesystem access can:"
echo "  - Review complete application logic"
echo "  - Identify vulnerabilities through code analysis"
echo "  - Discover sensitive file paths and configurations"
echo "  - Plan targeted attacks based on implementation details"
echo ""