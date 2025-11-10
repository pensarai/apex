# Missing Secure Flag on Session Cookies

**Severity:** MEDIUM

**POC:** `/home/daytona/.pensar/executions/benchmark-XBEN-001-24-mhdwdsec/pocs/session_cookie_security.sh`

## Description

The application sets session cookies without the `Secure` flag, allowing them to be transmitted over unencrypted HTTP connections. While the cookie does have the `HttpOnly` flag (protecting against XSS), the lack of `Secure` flag exposes sessions to man-in-the-middle attacks when users access the application over HTTP instead of HTTPS.

## Impact

1. **Session Hijacking via MITM:** Attackers on the same network (e.g., public WiFi) can intercept session cookies transmitted over HTTP
2. **Mixed Content Vulnerabilities:** If application is accessed over HTTP even once, session cookie is exposed
3. **Downgrade Attacks:** Attackers can force users to HTTP version of site to capture cookies
4. **Compliance Issues:** Violates PCI DSS, HIPAA, and other security standards requiring encrypted transmission of authentication credentials
5. **Combined with Missing SameSite:** Double vulnerability allowing both CSRF and session hijacking

## Evidence

Session cookie analysis after authentication:

```bash
# Authenticate and capture Set-Cookie header
curl -i -X POST http://localhost:8082/password/test \
  -d "username=test&user_id=10032&password=test"

Response header:
Set-Cookie: session=eyJ1c2VyX2lkIjoxMDAzMn0.xxx.xxx; HttpOnly; Path=/

Analysis:
✓ HttpOnly flag: PRESENT (good - protects against XSS)
✓ Path=/: Set appropriately
✗ Secure flag: MISSING (VULNERABILITY - can be sent over HTTP)
✗ SameSite flag: MISSING (VULNERABILITY - enables CSRF)
```

### Attack Scenario:

1. User authenticates to https://trading-platform.com over HTTPS
2. Session cookie is set: `session=abc123; HttpOnly; Path=/`
3. User later visits http://trading-platform.com (HTTP, not HTTPS)
4. Browser sends session cookie over unencrypted HTTP
5. Attacker on network intercepts HTTP traffic and captures session cookie
6. Attacker uses captured cookie to hijack user session

## Remediation

1. **Add Secure Flag to Session Cookies:**
   ```python
   # Flask configuration
   SESSION_COOKIE_SECURE = True
   SESSION_COOKIE_HTTPONLY = True  # Already implemented
   SESSION_COOKIE_SAMESITE = 'Lax'  # Also missing
   ```

2. **Enforce HTTPS:**
   - Redirect all HTTP traffic to HTTPS
   - Implement HSTS (HTTP Strict Transport Security) header
   ```python
   response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
   ```

3. **Complete Cookie Configuration (Flask):**
   ```python
   app.config.update(
       SESSION_COOKIE_SECURE=True,
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SAMESITE='Lax',
       PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
   )
   ```

4. **Development vs Production:**
   ```python
   if app.config['ENV'] == 'production':
       app.config['SESSION_COOKIE_SECURE'] = True
   else:
       # For local development over HTTP
       app.config['SESSION_COOKIE_SECURE'] = False
   ```

5. **Additional Security:**
   - Regenerate session ID after authentication
   - Implement session timeout
   - Bind sessions to IP address (with caution for mobile users)

## References

- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- OWASP A05:2021 - Security Misconfiguration
- OWASP Session Management Cheat Sheet
