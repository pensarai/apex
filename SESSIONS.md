# Session Management

The Pentest Agent uses a session-based file system to organize and persist all testing data, findings, and notes for each penetration test run.

## Session Directory Structure

When you start a pentest, a unique session is created in:

```
~/.pensar/executions/<session-id>/
├── session.json           # Session metadata
├── README.md             # Session overview
├── findings-summary.md   # Quick summary of all findings
├── findings/            # Individual finding documents
│   ├── 2025-10-09-missing-security-headers.md
│   ├── 2025-10-09-exposed-admin-panel.md
│   └── ...
├── scratchpad/          # Notes and observations
│   └── notes.md
└── logs/                # Execution logs (future use)
```

## Session ID Format

Session IDs are unique and follow this format:

```
<timestamp>-<random>
```

Example: `lpxxz8g-a3f7c2d1`

## Session Metadata

The `session.json` file contains:

```json
{
  "id": "lpxxz8g-a3f7c2d1",
  "rootPath": "/Users/username/.pensar/executions/lpxxz8g-a3f7c2d1",
  "findingsPath": "/Users/username/.pensar/executions/lpxxz8g-a3f7c2d1/findings",
  "scratchpadPath": "/Users/username/.pensar/executions/lpxxz8g-a3f7c2d1/scratchpad",
  "logsPath": "/Users/username/.pensar/executions/lpxxz8g-a3f7c2d1/logs",
  "target": "example.com",
  "objective": "Full security assessment",
  "startTime": "2025-10-09T12:34:56.789Z"
}
```

## Finding Documents

Each finding is saved as a Markdown file with:

- **Filename**: `<date>-<safe-title>.md`
- **Content**: Structured markdown with severity, description, impact, evidence, remediation

Example finding:

```markdown
# Missing Security Headers

**Severity:** MEDIUM  
**Target:** example.com  
**Date:** 2025-10-09T12:34:56.789Z  
**Session:** lpxxz8g-a3f7c2d1

## Description

The application is missing critical security headers that protect against common web vulnerabilities.

## Impact

Without these headers, the application is vulnerable to:

- Clickjacking attacks (missing X-Frame-Options)
- MIME-sniffing attacks (missing X-Content-Type-Options)
- Lack of HTTPS enforcement (missing HSTS)

## Evidence

\`\`\`
curl -I https://example.com
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html
(missing security headers)
\`\`\`

## Remediation

Add the following headers to the web server configuration:

\`\`\`
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
\`\`\`

## References

OWASP Secure Headers Project
CWE-693: Protection Mechanism Failure

---

_This finding was automatically documented by the Pensar penetration testing agent._
```

## Findings Summary

The `findings-summary.md` file maintains a quick reference of all findings:

```markdown
# Findings Summary

**Target:** example.com  
**Session:** lpxxz8g-a3f7c2d1

## All Findings

- [CRITICAL] SQL Injection in Login Form - `findings/2025-10-09-sql-injection-in-login-form.md`
- [HIGH] Stored XSS in Comment Section - `findings/2025-10-09-stored-xss-in-comment-section.md`
- [MEDIUM] Missing Security Headers - `findings/2025-10-09-missing-security-headers.md`
- [LOW] Verbose Error Messages - `findings/2025-10-09-verbose-error-messages.md`
- [INFORMATIONAL] Technology Stack Identified - `findings/2025-10-09-technology-stack-identified.md`
```

## Scratchpad

The scratchpad is used for notes during testing:

```markdown
# Scratchpad - Session lpxxz8g-a3f7c2d1

**Target:** example.com  
**Objective:** Full security assessment

---

## OBSERVATION - 2025-10-09T12:35:00.000Z

Found interesting behavior when testing login form - error messages differ for valid vs invalid usernames. This could enable username enumeration.

---

## TODO - 2025-10-09T12:40:00.000Z

Need to test for:

- Rate limiting on login attempts
- Password reset functionality
- Session fixation vulnerabilities

---

## HYPOTHESIS - 2025-10-09T12:45:00.000Z

The /api/users endpoint might be vulnerable to IDOR. Noticed sequential user IDs in responses. Will test by attempting to access other users' data.

---
```

## Using Sessions in Code

### Creating a Session

```typescript
import { createSession } from "./core/agent/sessions";

const session = createSession("example.com", "Full security assessment");
console.log("Session created:", session.id);
console.log("Findings will be saved to:", session.findingsPath);
```

### Documenting Findings

```typescript
// The document_finding tool automatically saves to the session directory
await document_finding({
  title: "SQL Injection in Login Form",
  severity: "CRITICAL",
  description: "The login form is vulnerable to SQL injection...",
  impact: "An attacker can bypass authentication and access the database.",
  evidence: "Payload: ' OR 1=1 --",
  remediation: "Use parameterized queries or an ORM.",
  references: "OWASP A03:2021 - Injection",
});
```

### Using the Scratchpad

```typescript
// Take notes during testing
await scratchpad({
  note: "Found interesting /api/internal endpoint - needs further investigation",
  category: "observation",
});

await scratchpad({
  note: "Test for JWT signature validation vulnerabilities",
  category: "todo",
});
```

## Session Management API

### List All Sessions

```typescript
import { listSessions } from "./core/agent/sessions";

const sessions = listSessions();
console.log("Available sessions:", sessions);
```

### Get Session by ID

```typescript
import { getSession } from "./core/agent/sessions";

const session = getSession("lpxxz8g-a3f7c2d1");
if (session) {
  console.log("Target:", session.target);
  console.log("Started:", session.startTime);
}
```

### Clean Up Old Sessions

```typescript
import { cleanupOldSessions } from "./core/agent/sessions";

// Delete sessions older than 30 days
const cleaned = cleanupOldSessions(30);
console.log(`Cleaned up ${cleaned} old sessions`);
```

## Benefits of Session-Based Storage

1. **Persistence**: All findings are saved to disk and survive application restarts
2. **Organization**: Each pentest has its own isolated directory
3. **Traceability**: Session metadata tracks when tests were run and against what targets
4. **Evidence**: Complete audit trail of all commands, findings, and observations
5. **Collaboration**: Share session directories with team members
6. **Compliance**: Meet requirements for documented security assessments
7. **Reporting**: Easy to generate reports from structured markdown files

## Best Practices

1. **Keep Sessions Organized**: Use clear, descriptive objectives
2. **Document Everything**: Use the scratchpad liberally for observations
3. **Review Findings**: Check the findings-summary.md after each test
4. **Archive Important Sessions**: Back up critical session directories
5. **Clean Up**: Periodically remove old sessions to save disk space

## Future Enhancements

Potential improvements to session management:

- Export sessions to PDF/HTML reports
- Session templates for common test types
- Session comparison and diff tools
- Collaborative sessions with multiple agents
- Integration with ticketing systems
- Automated finding prioritization
- Session replay for reproducibility
