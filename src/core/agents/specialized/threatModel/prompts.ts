import { join } from "path";
import type { DeploymentContext } from "./types";

// ---------------------------------------------------------------------------
// System Prompts
// ---------------------------------------------------------------------------

export const WHITEBOX_CODE_AGENT_SYSTEM_PROMPT = `You are an expert source-code analyst with direct filesystem access. You will be given a specific objective — focus exclusively on completing it.

Your focus is on **deployed applications and services** — APIs, web apps, microservices — that listen on a port and serve traffic. Ignore libraries, shared packages, SDKs, CLI tools, build scripts, and test suites unless they are part of a deployable service.

# Tool Usage Guide

## read_file
Read the contents of any file. You can read the whole file or a specific line range.
- When a file is large, read it in chunks using startLine / endLine to stay focused.
- Follow imports and references — when you see an interesting function call, read its source.

## list_files
List files and directories. Use this to orient yourself in the codebase.
- Start by listing the project root or relevant subdirectory to understand the structure.
- Use recursive=true sparingly on targeted subdirectories to avoid flooding context.

## grep
Search file contents by pattern. This is your most powerful navigation tool.
- Use it to find route definitions, middleware, controllers, endpoint registrations, etc.
- Use -i for case-insensitive searches.
- Use --include="*.ext" to narrow to relevant file types.
- Use -C 3 or -C 5 to get context around matches.
- Use -rn (default for directories) for recursive search with line numbers.
- Use -l to get just file paths when you need a broad overview of where something appears.

## execute_command
Run shell commands when needed.
- Use for build tools, git operations, package managers, linters, etc.

## document_asset
**Use this to document every significant asset you discover.** Each call persists a JSON record to the session's assets directory.

## response
When your objective includes structured output, call \`response\` with your final results once you are done. This ends your run — make sure all data is included.

# Working Approach
1. **Orient first** — list files and read key entry points to understand the structure.
2. **Ignore submodules** — check for a \`.gitmodules\` file or run \`git submodule status\`. Any directories that are git submodules are external dependencies and must be **completely excluded** from your analysis.
3. **Search, then read** — use grep to locate what you need, then read the relevant files.
4. **Document as you go** — call document_asset for every significant asset you discover.
5. **Follow the trail** — trace through imports, function calls, and references to build full understanding.
6. **Be thorough** — don't stop at the first match. Cover everything relevant to the objective.
`;

export const DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT = `You are an expert security analyst synthesizing structured analysis data into threat model artifacts. You are NOT exploring source code — you are reading structured JSON analysis files that were produced by earlier phases.

# Tool Usage Guide

## read_file
Read JSON data files from the session directory. These files contain structured analysis results — read them in full to understand the data.

## grep
Use grep to cross-reference data across files when needed — e.g. searching for a specific endpoint or component name across multiple JSON files.

## response
When your objective is complete, call \`response\` with your final structured results. This ends your run — make sure all data is included.

# Working Approach
1. **Read the data files** specified in your objective — these contain all the information you need.
2. **Cross-reference** data across files to build a complete picture.
3. **Focus on deployed endpoints** (paths, methods, parameters) — not source file paths.
4. **Be thorough** — ensure your output covers all relevant data from the input files.
`;

// ---------------------------------------------------------------------------
// Phase 0: Application Context Discovery
// ---------------------------------------------------------------------------

export function buildApplicationContextObjective(
  codebasePath: string,
  applicationIdentity?: string,
): string {
  const identityHint = applicationIdentity
    ? `\n## Application Identity Hint\nThe user describes this application as: "${applicationIdentity}"\nUse this as a starting point but verify and expand upon it through code analysis.\n`
    : "";

  return `# Discover Application Context

## Codebase
- **Path:** ${codebasePath}
${identityHint}
## Task
Analyze the codebase to understand what this application IS — its nature, domain, capabilities, and security-relevant characteristics. This context will drive threat identification, so focus on what makes this application unique from a security perspective.

### What to Determine

1. **Application Identity** — Determine:
   - **Type:** Is this a library, framework, service, platform, CLI tool, or something else?
   - **Domain:** What domain does it operate in? (e.g. browser automation, e-commerce, fintech, CI/CD, AI/ML)
   - **Description:** One clear paragraph explaining what it does
   - **Users:** Who uses this? (developers integrating it, end users, operators, other services)
   - **Core Capabilities:** What are the key things it can DO that have security implications? (e.g. "executes arbitrary browser actions", "processes credit card payments", "manages infrastructure")

2. **Features & Capabilities** — For each security-relevant feature, determine:
   - What the feature does
   - Why it matters for security (what could go wrong)
   - What privileged operations it can perform (file access, network requests, code execution, data access)
   - What sensitive data it handles (credentials, PII, tokens, secrets)

3. **Application-Specific Trust Boundaries** — Identify where untrusted data enters and what sensitive context it reaches:
   - These should be specific to this application, NOT generic zones like "DMZ" or "internal network"
   - Example for a browser automation framework: "web page content → agent instruction parser" is a trust boundary because malicious page content could influence agent behavior
   - Example for an API gateway: "upstream request headers → routing logic" is a trust boundary
   - For each boundary: what are the input sources, and what sensitive context does the input cross into?

4. **Attacker Profiles** — Define realistic attacker profiles specific to this application:
   - Who would attack this application and why?
   - What do they control? (e.g. a website's HTML content, an npm package, API inputs)
   - What are their goals? (data exfiltration, code execution, denial of service, privilege escalation)
   - What skill level is required?
   - Do NOT include generic attacker profiles — each should be grounded in how this specific application could be abused

### Approach
1. Read the project README, package.json, and main entry points to understand what the application does
2. Explore the source code to identify core features and capabilities
3. Look for where external/untrusted data enters the system
4. Trace how that data flows through to privileged operations
5. Think about who would want to attack this and what they'd gain

### Output
Call the \`response\` tool with the structured application context when done.`;
}

// ---------------------------------------------------------------------------
// Phase 1b: Deployment Context Discovery
// ---------------------------------------------------------------------------

export function buildDeploymentContextObjective(codebasePath: string): string {
  return `# Extract Deployment and Infrastructure Context

## Codebase
- **Path:** ${codebasePath}

## Task
Analyze the repository to extract deployment and infrastructure context. This information will be used to build a threat model, so be thorough and precise.

### What to Find

1. **Cloud Provider & Services** — Look for:
   - AWS SDK imports, \`aws-cdk\`, \`@aws-sdk/*\`, boto3, Azure SDK, GCP client libraries
   - Cloud-specific config files (samconfig.toml, cdk.json, app.yaml)
   - Environment variables referencing cloud services (AWS_REGION, GOOGLE_CLOUD_PROJECT)

2. **Containers & Orchestration** — Look for:
   - Dockerfiles, docker-compose.yml/yaml
   - Kubernetes manifests (deployments, services, ingress) in k8s/, kubernetes/, deploy/ directories
   - Helm charts (Chart.yaml)
   - ECS task definitions

3. **Infrastructure as Code** — Look for:
   - Terraform (.tf files), CDK (cdk.json + lib/), Pulumi (Pulumi.yaml), CloudFormation templates
   - Record the tool name and config file path

4. **CI/CD** — Look for:
   - .github/workflows/*.yml (GitHub Actions)
   - .gitlab-ci.yml (GitLab CI)
   - Jenkinsfile, .circleci/config.yml, bitbucket-pipelines.yml
   - buildspec.yml (AWS CodeBuild)

5. **Databases** — Look for:
   - ORM configurations (Prisma schema, TypeORM config, Sequelize, SQLAlchemy, Django settings)
   - Database connection strings in config files or environment variables
   - Database client imports (pg, mysql2, mongodb, redis, ioredis)
   - Determine the database type and version if possible

6. **Message Queues** — Look for:
   - RabbitMQ, SQS, Kafka, Bull/BullMQ, Redis pub/sub imports and configuration

7. **Reverse Proxy** — Look for:
   - nginx.conf, Caddyfile, traefik.yml
   - Reverse proxy configuration in docker-compose or k8s ingress

8. **Environment Files** — Look for:
   - .env, .env.example, .env.local, .env.production
   - Do NOT read the actual values — just record the file paths

### Output
Call the \`response\` tool with the structured deployment context when done.`;
}

// ---------------------------------------------------------------------------
// Phase 1c: Security Controls Discovery
// ---------------------------------------------------------------------------

export function buildSecurityControlsObjective(
  codebasePath: string,
  deploymentContext: DeploymentContext,
  sessionRootPath: string,
): string {
  const dbTypes =
    deploymentContext.databases?.map((d) => d.type).join(", ") ?? "unknown";
  const attackSurfacePath = join(
    sessionRootPath,
    "attack-surface-results.json",
  );

  return `# Extract Security Controls and Middleware

## Codebase
- **Path:** ${codebasePath}
- **Databases:** ${dbTypes}

## Attack Surface Data
The attack surface analysis (apps, endpoints, frameworks) is available at:
- **File:** ${attackSurfacePath}

Read this file to understand the application structure, frameworks in use, and known apps/endpoints. Use this context to guide your security controls discovery.

## Task
Analyze the codebase to find ALL security controls, authentication mechanisms, and authorization models. For each control, assess its effectiveness and identify gaps.

### What to Find

1. **Authentication Middleware** — Look for:
   - JWT verification (jsonwebtoken, jose, passport-jwt)
   - Session middleware (express-session, cookie-session)
   - OAuth/OIDC (passport, openid-client, next-auth)
   - API key validation
   - Where it's applied (all routes, specific route groups, individual routes)

2. **Authorization / Access Control** — Look for:
   - Role-based checks (RBAC middleware, role decorators)
   - Attribute-based access control (ABAC)
   - Permission checks, guards, policies
   - Owner-only checks (comparing user ID to resource owner)

3. **Input Validation** — Look for:
   - Validation libraries (zod, joi, yup, class-validator, express-validator)
   - Manual input sanitization or validation
   - Schema validation on request bodies
   - Parameterized queries vs raw SQL

4. **Output Encoding** — Look for:
   - Template engine auto-escaping settings
   - React JSX (auto-escapes by default)
   - dangerouslySetInnerHTML or equivalent unsafe patterns
   - Manual HTML encoding

5. **Security Headers** — Look for:
   - helmet.js or manual security header configuration
   - Content-Security-Policy (CSP) configuration
   - CORS configuration (cors npm package, manual headers)
   - X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security

6. **Rate Limiting** — Look for:
   - express-rate-limit, rate-limiter-flexible, or similar
   - Where rate limiting is applied (all routes, auth routes only, etc.)
   - Rate limit values and configuration

7. **CSRF Protection** — Look for:
   - csurf, csrf-csrf, or similar CSRF middleware
   - SameSite cookie attributes
   - Custom CSRF token implementation

8. **Encryption** — Look for:
   - TLS/SSL configuration
   - Data encryption at rest (field-level encryption, encrypted columns)
   - Password hashing (bcrypt, argon2, scrypt)

9. **Logging & Monitoring** — Look for:
   - Security event logging (failed auth attempts, authorization failures)
   - Audit logging
   - Error logging that might leak sensitive data

10. **Secrets Management** — Look for:
    - Hardcoded secrets, API keys in source code
    - Environment variable usage for secrets
    - Secrets manager integration (AWS Secrets Manager, Vault, etc.)

### For Each Control, Determine:
- **type**: The control type (auth_middleware, cors, csp, rate_limiter, etc.)
- **name**: A descriptive name
- **implementation**: How it's implemented (library, custom code)
- **scope**: What it applies to (all routes, specific routes, etc.)
- **effectiveness**: strong (well-implemented, comprehensive), moderate (covers most cases but has gaps), weak (easily bypassed or incomplete), unknown
- **gaps**: Any weaknesses or missing coverage

### Output
Call the \`response\` tool with the structured security controls when done.`;
}

// ---------------------------------------------------------------------------
// Phase 2: Architecture Synthesis
// ---------------------------------------------------------------------------

export function buildArchitectureSynthesisObjective(
  sessionRootPath: string,
): string {
  const attackSurfacePath = join(
    sessionRootPath,
    "attack-surface-results.json",
  );
  const deploymentContextPath = join(
    sessionRootPath,
    "deployment-context.json",
  );

  return `# Model System Architecture

## Data Files
Read these files to understand the system:
- **Attack Surface:** ${attackSurfacePath}
- **Deployment Context:** ${deploymentContextPath}

## Instructions

1. **Read both data files** in full to understand the application structure and deployment context.

2. **Define system components** — based on the deployment context and attack surface, model all components (apps, databases, caches, proxies, CDNs, etc.):
   - Assign a unique ID (comp-1, comp-2, ...) and a trust boundary
   - Include the technology stack for each component

3. **Define trust boundaries** — group components into trust boundaries:
   - external (internet), dmz (edge/proxy), internal (app tier), data (databases/caches)
   - Each component belongs to exactly one boundary
   - Assign unique IDs (tb-external, tb-dmz, etc.)

4. **Define data flows** — model how data moves between components:
   - Include protocol, data classification, and whether the flow is authenticated/encrypted
   - Assign unique IDs (df-1, df-2, ...)

## Output
Call the \`response\` tool with the structured system architecture when done.`;
}

// ---------------------------------------------------------------------------
// Phase 3: Attack Path Synthesis (application-centric)
// ---------------------------------------------------------------------------

export function buildAttackPathSynthesisObjective(
  sessionRootPath: string,
): string {
  const applicationContextPath = join(
    sessionRootPath,
    "application-context.json",
  );
  const attackSurfacePath = join(
    sessionRootPath,
    "attack-surface-results.json",
  );
  const deploymentContextPath = join(
    sessionRootPath,
    "deployment-context.json",
  );
  const securityControlsPath = join(sessionRootPath, "security-controls.json");
  const systemArchitecturePath = join(
    sessionRootPath,
    "system-architecture.json",
  );

  return `# Identify Application-Specific Attack Paths

## Data Files
Read ALL of these files before generating attack paths:
- **Application Context:** ${applicationContextPath} — Start here. This describes what the application IS, its features, trust boundaries, and attacker profiles.
- **Attack Surface:** ${attackSurfacePath}
- **Deployment Context:** ${deploymentContextPath}
- **Security Controls:** ${securityControlsPath}
- **System Architecture:** ${systemArchitecturePath}

## Approach

You are generating attack paths that are SPECIFIC to this application. Do NOT use STRIDE categories as your generative framework. Instead:

1. **Start from the application context** — read it first to understand what the application does, who would attack it, and what the application-specific trust boundaries are.
2. **For each attacker profile**, consider what attacks they could mount given what they control and what their goals are.
3. **For each application-specific trust boundary**, consider how untrusted input could cross into sensitive context.
4. **Cross-reference with the attack surface** to ground each attack path in real endpoints, features, and parameters.
5. **Check security controls** to determine what defenses exist and where gaps remain.
6. **Include deployment context** to make attack paths technology-specific.

## Signal vs. Noise

SKIP generic threats that are not specific to what this application does. For example:
- If this is NOT a web application with cookie-based sessions, skip CSRF threats
- If this is a library/framework (not a deployed service), skip server configuration threats
- If this application doesn't serve HTML pages, skip XSS/clickjacking
- Focus on threats that arise FROM the application's unique capabilities and trust boundaries

PRIORITIZE threats that are unique to this application's domain. For example:
- For a browser automation framework: prompt injection via web page content, data exfiltration through agent actions
- For a payment processor: transaction manipulation, race conditions in balance updates
- For an AI service: model manipulation, training data poisoning, inference-time attacks

## Attack Path Structure

Each attack path must trace a concrete path through the system:
- **Entry Point:** Where the attack starts (a specific feature, input, endpoint)
- **Mechanism:** Step-by-step how the attack flows through the system (array of steps)
- **Impact:** What happens if the attack succeeds
- **Attacker Profile:** Which attacker profile would execute this (must reference a profile from the application context)
- **Affected Features:** Which features are impacted

## Quality Standards

- **Every attack path must be grounded in the application context** — reference specific features, trust boundaries, and attacker profiles
- **Mechanisms must be concrete** — not "attacker exploits vulnerability" but "attacker embeds malicious instruction in page title → agent reads page title as context → agent executes attacker-controlled action"
- **Preconditions must be specific** — conditions tied to this application's behavior, not generic statements
- **Control gaps must identify what's missing** — not just "no mitigation" but what specific control would prevent this
- **Pentest guidance must be actionable** — specific techniques a pentester could use to test this attack path

Assign unique IDs: AP-001, AP-002, etc. Use severity levels: critical, high, medium, low.

## Output
Call the \`response\` tool with the structured attack paths when done.`;
}
