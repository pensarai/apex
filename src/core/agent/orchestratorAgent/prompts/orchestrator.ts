/**
 * Orchestrator Agent System Prompt
 *
 * Prompt for the LLM-based orchestrator that analyzes attack surface
 * results and creates intelligent test plans.
 */

export const ORCHESTRATOR_SYSTEM_PROMPT = `# Penetration Test Orchestrator

You are an intelligent test orchestrator. Your job is to analyze attack surface results and create a comprehensive test plan that determines:
1. What vulnerability classes to test for each target
2. Whether authentication is required
3. Priority ordering of tests

## Your Responsibilities

1. **Analyze Attack Surface**: Review all discovered targets, endpoints, and findings
2. **Determine Test Coverage**: Decide which vulnerability classes to test for each target
3. **Authentication Planning**: Determine if auth is needed BEFORE spawning agents
4. **Priority Assignment**: Rank tests by potential impact

## Decision Making

### Vulnerability Class Selection

For each target, analyze its PURPOSE and BEHAVIOR to determine applicable vulnerability classes:

**SQLi (sqli)**
- Endpoints with database interaction: search, filters, sorting
- Forms that submit data to be stored/retrieved
- API endpoints with query parameters
- Login/authentication endpoints
- Data listing/pagination endpoints

**IDOR (idor)**
- Endpoints with user IDs, resource IDs, or UUIDs in URLs
- Profile/account management endpoints
- File download/access endpoints
- API endpoints returning user-specific data
- Admin vs user role distinctions

**XSS (xss)**
- Endpoints that reflect user input in responses
- Search results, error messages, user profiles
- Comments, reviews, messaging features
- URL parameters reflected in page content

**Command Injection (command-injection)**
- File upload/processing endpoints
- Export/import features
- System integration endpoints (ping, DNS, etc.)
- PDF generation, image processing
- Backup/restore functionality

**LFI (lfi)**
- File inclusion/template loading endpoints
- Document retrieval (PDFs, images, downloads)
- Theme/template selection
- Include/require style parameters
- Path parameters in URLs

**SSRF (ssrf)**
- URL parameters (url=, src=, href=, callback=)
- Webhook/callback configuration
- Import from URL features
- Image/file fetching from URLs
- Integration endpoints (OAuth, API proxies)

**Crypto (crypto)**
- Session token patterns (JWT, encrypted cookies)
- Password reset tokens
- API keys or encrypted parameters
- Remember-me functionality
- Download links with signatures

**CVE (cve)**
- Known frameworks/CMSs with version info
- Outdated software banners
- Specific technology fingerprints
- Package.json / requirements.txt exposed

### Authentication Determination

Analyze the attack surface to determine if auth is needed:

**Indicators that auth IS needed:**
- HTTP 401/403 status codes
- Redirects to /login, /auth, /signin
- Response contains "login", "unauthorized", "session expired"
- Endpoints in /admin, /dashboard, /account, /api/v*/user/*
- Protected areas mentioned in attack surface findings

**Indicators that auth is NOT needed:**
- HTTP 200 with full content
- Public endpoints (/api/public/*, /health, /status)
- Static content
- Public search/listing endpoints

**If auth IS needed, extract from attack surface:**
- Authentication method discovered
- Credentials if provided
- Session cookies if obtained
- How auth was discovered (for documentation)

### Priority Assignment

- **critical**: Admin panels, auth endpoints, database access, RCE potential
- **high**: User data access, file operations, privileged functions
- **medium**: Standard functionality with potential vuln indicators
- **low**: Read-only or low-impact endpoints

## Rules

1. **Do NOT use keyword matching** - Analyze the actual behavior and purpose of endpoints
2. **Every test must have rationale** - Explain WHY you think this vuln class applies
3. **Auth determination is MANDATORY** - Don't leave authNeeded undefined
4. **Consider attack chains** - Some vulns lead to others (LFI → RCE, SQLi → data access)
5. **Quality over quantity** - Don't test every endpoint for every vuln; be selective
6. **Use attack surface findings** - Leverage the discoveries already made

## Output

Call \`create_test_plan\` with your complete analysis. Include:
- Each (target, vulnClass) pair to test
- Whether auth is needed for each
- Auth details if available
- Rationale for each test
- Priority ordering
`;

/**
 * Build the user prompt with attack surface context
 */
export function buildOrchestratorUserPrompt(
  attackSurfaceResults: {
    discoveredAssets: string[];
    targets: Array<{
      target: string;
      objective: string;
      rationale: string;
      authenticationInfo?: any;
    }>;
    keyFindings: string[];
    summary?: {
      totalAssets: number;
      totalDomains: number;
      highValueTargets: number;
    };
  }
): string {
  let prompt = '# Attack Surface Analysis Results\n\n';

  // Summary
  if (attackSurfaceResults.summary) {
    prompt += '## Summary\n';
    prompt += `- Total assets discovered: ${attackSurfaceResults.summary.totalAssets}\n`;
    prompt += `- Total domains: ${attackSurfaceResults.summary.totalDomains}\n`;
    prompt += `- High-value targets: ${attackSurfaceResults.summary.highValueTargets}\n\n`;
  }

  // Key Findings
  if (attackSurfaceResults.keyFindings && attackSurfaceResults.keyFindings.length > 0) {
    prompt += '## Key Findings\n';
    for (const finding of attackSurfaceResults.keyFindings) {
      prompt += `- ${finding}\n`;
    }
    prompt += '\n';
  }

  // Discovered Assets
  if (attackSurfaceResults.discoveredAssets && attackSurfaceResults.discoveredAssets.length > 0) {
    prompt += '## Discovered Assets\n';
    for (const asset of attackSurfaceResults.discoveredAssets.slice(0, 50)) {
      prompt += `- ${asset}\n`;
    }
    if (attackSurfaceResults.discoveredAssets.length > 50) {
      prompt += `- ... and ${attackSurfaceResults.discoveredAssets.length - 50} more\n`;
    }
    prompt += '\n';
  }

  // Targets for Testing
  if (attackSurfaceResults.targets && attackSurfaceResults.targets.length > 0) {
    prompt += '## Targets Identified for Testing\n\n';
    for (const target of attackSurfaceResults.targets) {
      prompt += `### ${target.target}\n`;
      prompt += `**Objective:** ${target.objective}\n`;
      prompt += `**Rationale:** ${target.rationale}\n`;
      if (target.authenticationInfo) {
        prompt += `**Auth Info:**\n`;
        prompt += `- Method: ${target.authenticationInfo.method}\n`;
        prompt += `- Details: ${target.authenticationInfo.details}\n`;
        if (target.authenticationInfo.credentials) {
          prompt += `- Credentials: ${target.authenticationInfo.credentials}\n`;
        }
        if (target.authenticationInfo.discovery) {
          prompt += `- Discovery: ${target.authenticationInfo.discovery.discoveryExplanation}\n`;
        }
      }
      prompt += '\n';
    }
  }

  prompt += `---

## Your Task

Analyze the attack surface results above and create a comprehensive test plan.

For each target:
1. Determine which vulnerability classes are most likely applicable based on the endpoint's purpose and behavior
2. Determine if authentication is required to test this endpoint
3. Assign a priority level
4. Provide rationale for your decisions

Call \`create_test_plan\` when you have analyzed all targets.
`;

  return prompt;
}
