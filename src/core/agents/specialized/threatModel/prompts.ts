import type { DeploymentContext, SecurityControlsResult } from "./types";
import type { WhiteboxAttackSurfaceResult } from "../whiteboxAttackSurface/types";

// ---------------------------------------------------------------------------
// Phase 1: Deployment Context Discovery
// ---------------------------------------------------------------------------

export function buildDeploymentContextObjective(
  codebasePath: string,
): string {
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
// Phase 2: Security Controls Discovery
// ---------------------------------------------------------------------------

export function buildSecurityControlsObjective(
  codebasePath: string,
  deploymentContext: DeploymentContext,
  attackSurface: WhiteboxAttackSurfaceResult,
): string {
  const dbTypes =
    deploymentContext.databases?.map((d) => d.type).join(", ") ?? "unknown";
  const frameworks = attackSurface.apps.map((a) => a.framework).join(", ");

  return `# Extract Security Controls and Middleware

## Codebase
- **Path:** ${codebasePath}
- **Frameworks:** ${frameworks}
- **Databases:** ${dbTypes}

## Known Apps
${attackSurface.apps.map((a) => `- **${a.name}** (${a.framework}) at ${a.location}`).join("\n")}

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
- **file** and **line**: Where it's defined
- **effectiveness**: strong (well-implemented, comprehensive), moderate (covers most cases but has gaps), weak (easily bypassed or incomplete), unknown
- **gaps**: Any weaknesses or missing coverage

### Output
Call the \`response\` tool with the structured security controls when done.`;
}

// ---------------------------------------------------------------------------
// Phase 3: Threat Model Synthesis
// ---------------------------------------------------------------------------

export const THREAT_MODEL_SYNTHESIS_SYSTEM_PROMPT = `You are an expert threat modeler using the STRIDE methodology. You will receive structured data about a codebase's deployment context, security controls, and attack surface. Your job is to synthesize a comprehensive STRIDE threat model.

# STRIDE Categories

- **Spoofing**: Can an attacker pretend to be another user or system? (fake credentials, token theft, session hijacking)
- **Tampering**: Can an attacker modify data they shouldn't? (SQL injection, parameter manipulation, request forgery)
- **Repudiation**: Can an attacker deny performing an action? (missing audit logs, unsigned transactions)
- **Information Disclosure**: Can an attacker access data they shouldn't? (IDOR, directory traversal, verbose errors, data leaks)
- **Denial of Service**: Can an attacker degrade or halt the service? (resource exhaustion, algorithmic complexity, missing rate limits)
- **Elevation of Privilege**: Can an attacker gain unauthorized access levels? (IDOR to admin, role bypass, privilege escalation)

# Modeling Rules

## Components
- Model each distinct system component (web app, API, database, cache, CDN, proxy, etc.)
- Assign a unique ID (comp-1, comp-2, ...) and a trust boundary

## Trust Boundaries
- Define boundaries: external (internet), dmz (edge/proxy), internal (app tier), data (databases/caches)
- Each component belongs to exactly one boundary

## Data Flows
- Model significant data flows between components
- Include protocol, data classification, and whether the flow is authenticated/encrypted

## Threats
Quality standards for each threat:
- **Every threat must reference a real endpoint** from the attack surface data — do not fabricate endpoints
- **Preconditions must be specific** — not generic statements like "if the app is vulnerable" but specific conditions like "the search parameter is concatenated into raw SQL without parameterization"
- **Mitigations must reference actual controls** — cite the specific security controls from the input data, with notes on whether they apply to this threat
- **Attack vectors must include real endpoints** with method, parameter, and specific technique
- **Pentest guidance must be actionable** — specific objectives a pentester can execute, with deployment-specific considerations (e.g. "PostgreSQL — use pg_sleep for time-based blind SQLi")
- **Residual risk** should account for existing mitigations — if strong mitigations exist, risk is lower

## Summary
- Count totals accurately
- Categorize threats by STRIDE category and residual risk level`;

export function buildThreatModelSynthesisPrompt(
  deploymentContext: DeploymentContext,
  securityControls: SecurityControlsResult,
  attackSurface: WhiteboxAttackSurfaceResult,
): string {
  return `# Synthesize STRIDE Threat Model

You have the following structured data about the target application. Analyze it and produce a complete STRIDE threat model.

## Deployment Context
\`\`\`json
${JSON.stringify(deploymentContext, null, 2)}
\`\`\`

## Security Controls
\`\`\`json
${JSON.stringify(securityControls, null, 2)}
\`\`\`

## Attack Surface
\`\`\`json
${JSON.stringify(attackSurface, null, 2)}
\`\`\`

## Instructions

1. **Define system components** — based on the deployment context and attack surface, model all components (apps, databases, caches, proxies, CDNs, etc.)

2. **Define trust boundaries** — group components into trust boundaries (external, dmz, internal, data)

3. **Define data flows** — model how data moves between components, noting protocol, classification, and security properties

4. **Identify threats** — for each STRIDE category, analyze the attack surface and security controls to find threats:
   - Cross-reference endpoints from the attack surface with security controls to find gaps
   - Consider deployment-specific attack vectors (e.g. PostgreSQL-specific SQL injection, Node.js prototype pollution)
   - Assess which controls mitigate which threats, and note the residual risk
   - Generate actionable pentest guidance with deployment-specific considerations

5. **Calculate summary** — accurate counts of components, data flows, and threats by category and risk

Focus on threats that are plausible given the deployment context and security controls. Don't generate generic threats — every threat should be grounded in specific endpoints, parameters, and deployment details from the input data.`;
}
