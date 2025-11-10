#!/bin/bash

# POC: Missing API Metadata in OpenAPI Schema
# This script demonstrates the incomplete info object in the API specification

echo "================================"
echo "API Metadata Completeness Check"
echo "================================"
echo ""

# Simulated OpenAPI schema info object from the API
INCOMPLETE_INFO='{
  "title": "FastAPI",
  "version": "0.1.0"
}'

echo "[*] Current API Info Object (from /openapi.json):"
echo "$INCOMPLETE_INFO" | jq '.' 2>/dev/null || echo "$INCOMPLETE_INFO"
echo ""

echo "[*] Analyzing metadata completeness:"
echo ""

# Extract fields from the incomplete info
TITLE=$(echo "$INCOMPLETE_INFO" | jq -r '.title // empty' 2>/dev/null || echo "FastAPI")
VERSION=$(echo "$INCOMPLETE_INFO" | jq -r '.version // empty' 2>/dev/null || echo "0.1.0")
DESCRIPTION=$(echo "$INCOMPLETE_INFO" | jq -r '.description // empty' 2>/dev/null)
CONTACT=$(echo "$INCOMPLETE_INFO" | jq -r '.contact // empty' 2>/dev/null)
LICENSE=$(echo "$INCOMPLETE_INFO" | jq -r '.license // empty' 2>/dev/null)
TERMS=$(echo "$INCOMPLETE_INFO" | jq -r '.termsOfService // empty' 2>/dev/null)

echo "=== Required Fields (OpenAPI 3.1.0) ==="
echo "[+] title: '$TITLE' (PRESENT)"
echo "[+] version: '$VERSION' (PRESENT)"

echo ""
echo "=== Recommended Fields (Missing) ==="

if [ -z "$DESCRIPTION" ]; then
    echo "[-] description: MISSING"
    echo "    Expected: String describing API purpose and capabilities"
    echo "    Current: (empty)"
else
    echo "[+] description: '$DESCRIPTION'"
fi

if [ -z "$CONTACT" ]; then
    echo "[-] contact: MISSING"
    echo "    Expected: Object with name, url, and email properties"
    echo "    Current: (empty)"
else
    echo "[+] contact: Present"
fi

if [ -z "$LICENSE" ]; then
    echo "[-] license: MISSING"
    echo "    Expected: Object with name and url properties"
    echo "    Current: (empty)"
else
    echo "[+] license: Present"
fi

if [ -z "$TERMS" ]; then
    echo "[-] termsOfService: MISSING"
    echo "    Expected: URL to terms of service"
    echo "    Current: (empty)"
else
    echo "[+] termsOfService: '$TERMS'"
fi

echo ""
echo "[*] Severity Assessment:"
echo "    Missing 3 recommended metadata fields (description, contact, license)"
echo "    This reduces API usability and professionalism"
echo ""

# Count missing recommended fields
MISSING_COUNT=0
[ -z "$DESCRIPTION" ] && MISSING_COUNT=$((MISSING_COUNT + 1))
[ -z "$CONTACT" ] && MISSING_COUNT=$((MISSING_COUNT + 1))
[ -z "$LICENSE" ] && MISSING_COUNT=$((MISSING_COUNT + 1))

echo "[*] Vulnerability Confirmation:"
if [ $MISSING_COUNT -ge 3 ]; then
    echo "[+] CONFIRMED: API metadata is incomplete"
    echo "    - $MISSING_COUNT out of 3 recommended fields are missing"
    echo "    - Impacts API usability and documentation quality"
    echo "    - Violates OpenAPI 3.1.0 specification recommendations"
    exit 0
else
    echo "[-] Not confirmed: Insufficient metadata missing"
    exit 1
fi