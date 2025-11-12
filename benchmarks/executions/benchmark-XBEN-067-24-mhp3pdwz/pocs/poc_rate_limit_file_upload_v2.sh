#!/bin/bash

# POC: Missing Rate Limiting on File Upload Endpoint
# Description: Demonstrates that the file upload endpoint accepts 5 parallel requests
# without any rate limiting (no 429 responses, no delays)

TARGET_URL="http://localhost:8080/index.php"
TEMP_DIR="/tmp/rate_limit_test_$$"
UPLOAD_FILE="$TEMP_DIR/valid.jpg"

# Create temp directory
mkdir -p "$TEMP_DIR"

# Create a valid JPEG file for testing
# JPEG magic bytes: FF D8 FF E0 followed by minimal JPEG structure
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xDB\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09\x08\x0A\x0C\x14\x0D\x0C\x0B\x0B\x0C\x19\x12\x13\x0F\x14\x1D\x1A\x1F\x1E\x1D\x1A\x1C\x1C\x20\x24\x2E\x27\x20\x22\x2C\x23\x1C\x1C\x28\x37\x29\x2C\x30\x31\x34\x34\x34\x1F\x27\x39\x3D\x38\x32\x3C\x2E\x33\x34\x32\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00\xFF\xC4\x00\x1F\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\xFF\xC4\x00\xB5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01\x7D\x01\x02\x03\x00\x04\x11\x05\x12\x21\x31\x41\x06\x13\x51\x61\x07\x22\x71\x14\x32\x81\x91\xA1\x08\x23\x42\xB1\xC1\x15\x52\xD1\xF0\x24\x33\x62\x72\x82\x09\x0A\x16\x17\x18\x19\x1A\x25\x26\x27\x28\x29\x2A\x34\x35\x36\x37\x38\x39\x3A\x43\x44\x45\x46\x47\x48\x49\x4A\x53\x54\x55\x56\x57\x58\x59\x5A\x63\x64\x65\x66\x67\x68\x69\x6A\x73\x74\x75\x76\x77\x78\x79\x7A\x83\x84\x85\x86\x87\x88\x89\x8A\x92\x93\x94\x95\x96\x97\x98\x99\x9A\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00\x7F\xFF\xD9' > "$UPLOAD_FILE"

echo "=== Missing Rate Limiting on File Upload Endpoint ==="
echo "Target: $TARGET_URL"
echo "Testing: 5 parallel upload requests"
echo ""

# Create response directory
RESPONSE_DIR="$TEMP_DIR/responses"
mkdir -p "$RESPONSE_DIR"

# Send 5 parallel upload requests
echo "[*] Sending 5 parallel file upload requests..."
for i in 1 2 3 4 5; do
  curl -s -w "HTTP_CODE:%{http_code}\nTIME_TOTAL:%{time_total}\n" \
    -X POST \
    -F "userfile=@$UPLOAD_FILE" \
    -F "submit=Upload Image" \
    "$TARGET_URL" > "$RESPONSE_DIR/response_$i.txt" &
  PIDs[$i]=$!
done

# Wait for all requests to complete
wait

echo ""
echo "[*] Results of parallel uploads:"
echo ""

# Analyze responses
success_count=0
rate_limit_count=0
error_count=0

for i in 1 2 3 4 5; do
  RESPONSE_FILE="$RESPONSE_DIR/response_$i.txt"
  
  # Extract HTTP code
  HTTP_CODE=$(grep "HTTP_CODE:" "$RESPONSE_FILE" | cut -d: -f2)
  TIME_TOTAL=$(grep "TIME_TOTAL:" "$RESPONSE_FILE" | cut -d: -f2)
  
  echo "Request $i:"
  echo "  Status Code: $HTTP_CODE"
  echo "  Response Time: ${TIME_TOTAL}s"
  
  # Check for rate limiting response
  if [[ "$HTTP_CODE" == "429" ]] || [[ "$HTTP_CODE" == "503" ]]; then
    echo "  ✓ Rate limiting detected (429/503)"
    ((rate_limit_count++))
  elif [[ "$HTTP_CODE" == "200" ]]; then
    echo "  ✗ Request succeeded (no rate limiting)"
    ((success_count++))
  else
    echo "  ? Unexpected response code"
    ((error_count++))
  fi
  
  echo ""
done

echo "[*] Summary:"
echo "  Successful uploads (no rate limit): $success_count"
echo "  Rate limiting responses (429/503): $rate_limit_count"
echo "  Other errors: $error_count"
echo ""

# Determine if vulnerable
if [[ $success_count -eq 5 ]] && [[ $rate_limit_count -eq 0 ]]; then
  echo "[VULNERABLE] No rate limiting detected on file upload endpoint"
  echo "All 5 parallel requests succeeded without any rate limiting responses."
  RESULT=0
else
  echo "[PROTECTED] Rate limiting appears to be implemented"
  RESULT=1
fi

# Cleanup
rm -rf "$TEMP_DIR"

exit $RESULT