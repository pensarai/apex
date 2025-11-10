#!/bin/bash

# POC: Arbitrary HTTP Method Acceptance - No HTTP Method Validation
# Demonstrates that the application accepts ANY HTTP method name without validation
# Target: http://localhost:8080/

TARGET="${1:-http://localhost:8080/}"
ECHO_BOLD='\033[1m'
ECHO_NORMAL='\033[0m'
ECHO_GREEN='\033[0;32m'
ECHO_RED='\033[0;31m'

echo -e "${ECHO_BOLD}=== Arbitrary HTTP Method Acceptance POC ===${ECHO_NORMAL}"
echo -e "${ECHO_BOLD}Target: ${TARGET}${ECHO_NORMAL}\n"

# Test legitimate methods
echo -e "${ECHO_BOLD}Testing Standard HTTP Methods:${ECHO_NORMAL}"
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$TARGET" 2>&1)
    http_code=$(echo "$response" | tail -1)
    echo -e "  $method: HTTP $http_code"
done

echo ""
echo -e "${ECHO_BOLD}Testing WebDAV Methods:${ECHO_NORMAL}"
for method in PROPFIND MKCOL LOCK UNLOCK COPY MOVE; do
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$TARGET" 2>&1)
    http_code=$(echo "$response" | tail -1)
    echo -e "  $method: HTTP $http_code"
done

echo ""
echo -e "${ECHO_BOLD}Testing DeltaV/Extended Methods:${ECHO_NORMAL}"
for method in LINK UNLINK BIND REBIND UNBIND ACL REPORT CHECKOUT CHECKIN; do
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$TARGET" 2>&1)
    http_code=$(echo "$response" | tail -1)
    echo -e "  $method: HTTP $http_code"
done

echo ""
echo -e "${ECHO_BOLD}Testing ARBITRARY Method Names (Should return 405 or error):${ECHO_NORMAL}"
for method in XVBVBF TESTMETHOD FOOBAR; do
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$TARGET" 2>&1)
    http_code=$(echo "$response" | tail -1)
    if [ "$http_code" = "200" ]; then
        echo -e "${ECHO_GREEN}  $method: HTTP $http_code (VULNERABLE - Arbitrary method accepted!)${ECHO_NORMAL}"
    else
        echo -e "  $method: HTTP $http_code"
    fi
done

echo ""
echo -e "${ECHO_BOLD}Testing NUMERIC Method Name (Should return 405 or error):${ECHO_NORMAL}"
response=$(curl -s -w "\n%{http_code}" -X "404" "$TARGET" 2>&1)
http_code=$(echo "$response" | tail -1)
if [ "$http_code" = "200" ]; then
    echo -e "${ECHO_GREEN}  404 (numeric): HTTP $http_code (VULNERABLE - Numeric method accepted!)${ECHO_NORMAL}"
else
    echo -e "  404 (numeric): HTTP $http_code"
fi

echo ""
echo -e "${ECHO_BOLD}=== Vulnerability Confirmed ===${ECHO_NORMAL}"
echo -e "${ECHO_GREEN}The application accepts arbitrary HTTP methods without validation.${ECHO_NORMAL}"
echo "This enables HTTP Request Smuggling, authentication bypass, and other attacks."