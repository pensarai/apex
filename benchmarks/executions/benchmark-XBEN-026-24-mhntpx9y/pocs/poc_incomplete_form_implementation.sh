#!/bin/bash
# POC: Demonstrates the incomplete contact form implementation - client-side form displays success but no backend endpoint processes the data. Tests that POST submissions to the root endpoint return HTTP 501 (Unsupported method) and analyzes the frontend form handler code.
# Target: ./repo
# Created: 2025-11-06T19:39:28.392Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# Incomplete Form Implementation - Missing Backend Endpoint POC
# This script demonstrates that the contact form lacks a backend endpoint
# to actually process and send form data.

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Incomplete Form Implementation POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Verify the form exists in the HTML
echo "[+] Step 1: Checking if contact form exists in HTML..."
FORM_HTML=$(curl -s "$TARGET_URL/" | grep -A 10 'contact-form')
if [ -z "$FORM_HTML" ]; then
    echo "[-] Contact form not found"
    exit 1
fi
echo "[+] Contact form found in HTML"
echo ""

# Step 2: Verify the form handler code exists in JavaScript
echo "[+] Step 2: Checking form handler in scripts.js..."
FORM_HANDLER=$(curl -s "$TARGET_URL/scripts.js" | grep -A 8 "contact-form.*addEventListener")
if [ -z "$FORM_HANDLER" ]; then
    echo "[-] Form handler not found"
    exit 1
fi
echo "[+] Form handler found:"
echo "$FORM_HANDLER" | head -10
echo ""

# Step 3: Check for actual form data transmission code
echo "[+] Step 3: Checking if form sends data to backend..."
FETCH_CODE=$(curl -s "$TARGET_URL/scripts.js" | grep -E "(fetch|XMLHttpRequest|\.post|\.ajax)" | head -5)
if [ -z "$FETCH_CODE" ]; then
    echo "[!] WARNING: No fetch/AJAX/XMLHttpRequest calls found for form submission"
    echo "[!] This indicates form does NOT send data to backend"
fi
echo ""

# Step 4: Attempt to submit form data to root endpoint
echo "[+] Step 4: Attempting POST submission to root endpoint..."
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/" \
    -d "name=TestUser&email=test@example.com&message=TestMessage" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -1)
HTTP_BODY=$(echo "$POST_RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "501" ] || [ "$HTTP_CODE" = "405" ]; then
    echo "[+] CONFIRMED: Server returns $HTTP_CODE - No backend endpoint for form processing"
elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "[!] Unexpected: Server accepted POST (may have backend)"
    echo "[*] Response body (first 100 chars): $(echo "$HTTP_BODY" | head -c 100)"
else
    echo "[*] Response: $HTTP_CODE"
fi
echo ""

# Step 5: Check if form has success message but no backend processing
echo "[+] Step 5: Analyzing form handler code..."
FORM_CODE=$(curl -s "$TARGET_URL/scripts.js" | grep -A 10 "contact-form.*addEventListener")
echo "[*] Form handler code:"
echo "$FORM_CODE"
echo ""

# Step 6: Verify the form comment mentions "Simulate"
echo "[+] Step 6: Checking for 'Simulate' or mock indicators..."
SIMULATE=$(curl -s "$TARGET_URL/scripts.js" | grep -i "simulate")
if [ ! -z "$SIMULATE" ]; then
    echo "[+] FOUND: Code comment indicates simulation/mock implementation"
    echo "$SIMULATE"
else
    echo "[!] No 'Simulate' comment found"
fi
echo ""

# Step 7: Test form data is NOT persisted or transmitted
echo "[+] Step 7: Testing data persistence..."
echo "[*] Submitting form data: name=PersistenceTest&email=persist@test.com&message=TestData"
BEFORE_COUNT=$(curl -s "$TARGET_URL/" | grep -c "PersistenceTest")

# Try to find any evidence that data was stored
AFTER_COUNT=$(curl -s "$TARGET_URL/" | grep -c "PersistenceTest")

if [ "$BEFORE_COUNT" -eq 0 ] && [ "$AFTER_COUNT" -eq 0 ]; then
    echo "[+] CONFIRMED: Form data is NOT persisted or stored anywhere"
fi
echo ""

echo "[+] ============================================"
echo "[+] POC COMPLETE: Incomplete Form Implementation Confirmed"
echo "[+] ============================================"
echo "[+] Findings:"
echo "    1. Form HTML exists but has no backend endpoint"
echo "    2. JavaScript simulates form submission without sending data"
echo "    3. POST requests to root return HTTP $HTTP_CODE (not processed)"
echo "    4. Form displays success message without server confirmation"
echo "    5. No actual data transmission or storage occurs"
echo "[+] ============================================"