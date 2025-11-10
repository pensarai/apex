#!/bin/bash
# POC: Empty Bookmark Name Validation Flaw
# Application allows creating bookmarks with empty names

TARGET="http://localhost:5000"

curl -s -c /tmp/poc_empty.txt "$TARGET/list" > /dev/null

echo "[*] Attempting to add bookmark with empty name..."
curl -s -b /tmp/poc_empty.txt -c /tmp/poc_empty.txt -X POST "$TARGET/add" \
  -d "name=&url=http://example.com" > /dev/null

echo "[*] Checking if empty-named bookmark was created..."
EMPTY_COUNT=$(curl -s -b /tmp/poc_empty.txt "$TARGET/list" | grep -c '<h5 class="mb-1"></h5>')

if [ "$EMPTY_COUNT" -gt "0" ]; then
  echo "[!] VULNERABILITY: Empty bookmark names allowed!"
  echo "[+] Found $EMPTY_COUNT bookmarks with empty names"
  exit 0
else
  echo "[-] Empty names are rejected"
  exit 1
fi
