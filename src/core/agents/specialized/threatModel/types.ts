import { z } from "zod";

// ---------------------------------------------------------------------------
// Deployment Context
// ---------------------------------------------------------------------------

export const DeploymentContextSchema = z.object({
  cloud: z
    .object({
      provider: z
        .string()
        .optional()
        .describe("Cloud provider (e.g. AWS, GCP, Azure, DigitalOcean)"),
      region: z.string().optional().describe("Deployment region"),
      services: z
        .array(z.string())
        .optional()
        .describe("Cloud services in use (e.g. ECS, RDS, S3, CloudFront)"),
    })
    .optional()
    .describe("Cloud deployment details, if applicable"),
  containers: z
    .object({
      runtime: z
        .string()
        .optional()
        .describe("Container runtime (e.g. Docker, Podman)"),
      orchestration: z
        .string()
        .optional()
        .describe(
          "Orchestration platform (e.g. Kubernetes, ECS, Docker Compose)",
        ),
      hasDockerfile: z
        .boolean()
        .optional()
        .describe("Whether a Dockerfile was found"),
      hasDockerCompose: z
        .boolean()
        .optional()
        .describe("Whether a Docker Compose file was found"),
      hasKubernetes: z
        .boolean()
        .optional()
        .describe("Whether Kubernetes manifests were found"),
    })
    .optional()
    .describe("Container configuration details, if applicable"),
  iac: z
    .array(
      z.object({
        tool: z
          .string()
          .describe(
            "IaC tool (e.g. Terraform, CDK, Pulumi, CloudFormation)",
          ),
        configPath: z
          .string()
          .describe("Path to the IaC configuration"),
      }),
    )
    .describe(
      "Infrastructure as Code tools detected (empty array if none)",
    ),
  cicd: z
    .array(z.string())
    .describe(
      "CI/CD platforms detected (e.g. GitHub Actions, GitLab CI, Jenkins). Empty array if none",
    ),
  databases: z
    .array(
      z.object({
        type: z
          .string()
          .describe(
            "Database type (e.g. PostgreSQL, MySQL, MongoDB, Redis)",
          ),
        version: z
          .string()
          .optional()
          .describe("Version if determinable"),
      }),
    )
    .describe("Databases discovered (empty array if none)"),
  messageQueues: z
    .array(z.string())
    .describe(
      "Message queues/brokers (e.g. RabbitMQ, SQS, Kafka). Empty array if none",
    ),
  reverseProxy: z
    .string()
    .describe(
      "Reverse proxy (e.g. nginx, Caddy, Traefik). Empty string if none",
    ),
  environmentFiles: z
    .array(z.string())
    .describe(
      "Environment file paths discovered (e.g. .env, .env.example). Empty array if none",
    ),
});

export type DeploymentContext = z.infer<typeof DeploymentContextSchema>;

// ---------------------------------------------------------------------------
// Security Controls
// ---------------------------------------------------------------------------

export const SecurityControlSchema = z.object({
  type: z
    .enum([
      "waf",
      "cdn",
      "cors",
      "csp",
      "rate_limiter",
      "auth_middleware",
      "authorization",
      "input_validation",
      "output_encoding",
      "csrf_protection",
      "encryption",
      "logging",
      "secrets_management",
      "security_headers",
      "other",
    ])
    .describe("Type of security control"),
  name: z.string().describe("Descriptive name for this control"),
  implementation: z
    .string()
    .describe(
      "How the control is implemented (library, custom code, etc.)",
    ),
  scope: z
    .string()
    .describe(
      "What the control applies to (e.g. all routes, /api/* only)",
    ),
  effectiveness: z
    .enum(["strong", "moderate", "weak", "unknown"])
    .describe("Assessed effectiveness of the control"),
  gaps: z
    .string()
    .describe(
      "Known gaps or weaknesses in the control. Empty string if none identified",
    ),
});

export type SecurityControl = z.infer<typeof SecurityControlSchema>;

export const SecurityControlsResultSchema = z.object({
  controls: z
    .array(SecurityControlSchema)
    .describe("All security controls discovered in the codebase"),
  authenticationMechanism: z
    .object({
      type: z
        .string()
        .describe(
          "Auth type (e.g. JWT Bearer, Session Cookie, OAuth2, API Key)",
        ),
      implementation: z
        .string()
        .describe("Library or approach used"),
      sessionStorage: z
        .string()
        .describe(
          "How sessions are stored (stateless, Redis, DB, etc.)",
        ),
      mfa: z
        .string()
        .optional()
        .describe("MFA support status"),
    })
    .optional()
    .describe("Primary authentication mechanism"),
  authorizationModel: z
    .object({
      type: z
        .string()
        .describe(
          "Authorization model (e.g. RBAC, ABAC, ACL, custom)",
        ),
      implementation: z
        .string()
        .describe("How authorization is enforced"),
      roles: z
        .array(z.string())
        .optional()
        .describe("Defined roles if RBAC"),
    })
    .optional()
    .describe("Authorization model"),
});

export type SecurityControlsResult = z.infer<
  typeof SecurityControlsResultSchema
>;

// ---------------------------------------------------------------------------
// System Architecture: Components, Trust Boundaries, Data Flows
// ---------------------------------------------------------------------------

export const ComponentSchema = z.object({
  id: z.string().describe("Unique component ID (e.g. comp-1)"),
  name: z.string().describe("Component name (e.g. user-api)"),
  type: z
    .enum([
      "web_app",
      "api_service",
      "database",
      "cache",
      "queue",
      "cdn",
      "gateway",
      "reverse_proxy",
      "storage",
      "identity_provider",
      "other",
    ])
    .describe("Component type"),
  technology: z
    .string()
    .describe(
      "Technology stack (e.g. Express.js on Node 20, PostgreSQL 15)",
    ),
  trustBoundary: z
    .string()
    .describe(
      "Name of the trust boundary this component belongs to",
    ),
});

export type Component = z.infer<typeof ComponentSchema>;

export const TrustBoundarySchema = z.object({
  id: z
    .string()
    .describe("Unique boundary ID (e.g. tb-external)"),
  name: z
    .string()
    .describe("Human-readable boundary name"),
  level: z
    .enum(["external", "dmz", "internal", "data"])
    .describe("Trust level of this boundary"),
  componentIds: z
    .array(z.string())
    .describe("IDs of components within this boundary"),
});

export type TrustBoundary = z.infer<typeof TrustBoundarySchema>;

export const DataFlowSchema = z.object({
  id: z.string().describe("Unique data flow ID (e.g. df-1)"),
  from: z.string().describe("Source component name"),
  to: z.string().describe("Destination component name"),
  protocol: z
    .string()
    .describe(
      "Protocol used (e.g. HTTPS, SQL/TLS, Redis, gRPC)",
    ),
  dataClassification: z
    .enum(["public", "internal", "confidential", "restricted"])
    .describe("Data sensitivity classification"),
  authenticated: z
    .boolean()
    .describe("Whether the flow requires authentication"),
  encrypted: z
    .boolean()
    .describe("Whether the flow is encrypted in transit"),
});

export type DataFlow = z.infer<typeof DataFlowSchema>;

export const SystemArchitectureSchema = z.object({
  components: z
    .array(ComponentSchema)
    .describe("System components identified in the codebase"),
  trustBoundaries: z
    .array(TrustBoundarySchema)
    .describe("Trust boundaries grouping components by trust level"),
  dataFlows: z
    .array(DataFlowSchema)
    .describe("Data flows between components"),
});

export type SystemArchitecture = z.infer<typeof SystemArchitectureSchema>;

// ---------------------------------------------------------------------------
// Application Context
// ---------------------------------------------------------------------------

export const ApplicationIdentitySchema = z.object({
  type: z
    .enum([
      "library",
      "framework",
      "service",
      "platform",
      "cli",
      "other",
    ])
    .describe("What kind of software this is"),
  description: z
    .string()
    .describe(
      "One-paragraph summary of what the application does, its key value proposition, and how users interact with it",
    ),
  domain: z
    .string()
    .describe(
      "Application domain (e.g. browser automation, e-commerce, fintech, CI/CD)",
    ),
  users: z
    .array(z.string())
    .describe(
      "Who uses this application (e.g. developers, end users, operators)",
    ),
  coreCapabilities: z
    .array(z.string())
    .describe(
      "Key capabilities with security implications (e.g. executes browser actions, processes payments, runs arbitrary code)",
    ),
});

export type ApplicationIdentity = z.infer<typeof ApplicationIdentitySchema>;

export const ApplicationFeatureSchema = z.object({
  name: z
    .string()
    .describe(
      "Feature name with brief clarifier (e.g. 'act() - Single Action Execution')",
    ),
  description: z
    .string()
    .describe("What the feature does — 2-3 sentences"),
  securityRelevance: z
    .string()
    .describe(
      "Why this feature matters for security — what could go wrong and what makes it a target",
    ),
  privilegedOperations: z
    .array(z.string())
    .describe(
      "Privileged operations this feature can perform (e.g. file system access, shell command execution, network requests to arbitrary hosts)",
    ),
  dataHandled: z
    .array(z.string())
    .describe(
      "Sensitive data this feature handles (e.g. user credentials, API keys, page content, PII)",
    ),
});

export type ApplicationFeature = z.infer<typeof ApplicationFeatureSchema>;

export const ApplicationTrustBoundarySchema = z.object({
  name: z
    .string()
    .describe(
      "Boundary name describing the crossing (e.g. 'API Request -> Instruction Parser', 'Page Content -> LLM Service')",
    ),
  description: z
    .string()
    .describe(
      "What crosses this boundary and why it matters — how untrusted data reaches sensitive context",
    ),
  inputSources: z
    .array(z.string())
    .describe(
      "Specific sources of untrusted input (e.g. 'HTTP request body', 'page DOM elements', 'LLM API response tool_calls')",
    ),
  crossesTo: z
    .string()
    .describe(
      "What sensitive context the input reaches and what it can influence (e.g. 'Browser action execution engine — instructions are parsed and executed directly on the controlled browser')",
    ),
});

export type ApplicationTrustBoundary = z.infer<
  typeof ApplicationTrustBoundarySchema
>;

export const AttackerProfileSchema = z.object({
  name: z
    .string()
    .describe(
      "Profile name (e.g. 'Malicious Web Page Operator', 'Compromised Dependency Author')",
    ),
  description: z
    .string()
    .describe(
      "Who this attacker is and their motivation — 2-3 sentences",
    ),
  skillLevel: z
    .enum(["low", "medium", "high", "expert"])
    .describe("Expected attacker skill level"),
  controls: z
    .array(z.string())
    .describe(
      "What the attacker controls (e.g. 'page HTML/CSS/JS content', 'npm package source code', 'LLM API responses')",
    ),
  goals: z
    .array(z.string())
    .describe(
      "What the attacker wants to achieve (e.g. 'exfiltrate credentials', 'execute arbitrary code', 'hijack agent execution')",
    ),
});

export type AttackerProfile = z.infer<typeof AttackerProfileSchema>;

export const ApplicationContextSchema = z.object({
  identity: ApplicationIdentitySchema.describe(
    "What the application is",
  ),
  features: z
    .array(ApplicationFeatureSchema)
    .describe("Security-relevant features and capabilities"),
  trustBoundaries: z
    .array(ApplicationTrustBoundarySchema)
    .describe(
      "Application-specific trust boundaries where untrusted data enters sensitive context",
    ),
  attackerProfiles: z
    .array(AttackerProfileSchema)
    .describe(
      "Realistic attacker profiles based on the application's nature and domain",
    ),
});

export type ApplicationContext = z.infer<typeof ApplicationContextSchema>;

// ---------------------------------------------------------------------------
// Attack Paths
// ---------------------------------------------------------------------------

export const AttackPathSchema = z.object({
  id: z
    .string()
    .describe("Unique attack path ID (e.g. AP-001)"),
  title: z
    .string()
    .describe(
      "Descriptive title including entry point and impact (e.g. 'Prompt Injection via Malicious Page Content -> LLM Instruction Hijacking')",
    ),
  severity: z
    .enum(["critical", "high", "medium", "low"])
    .describe(
      "Severity factoring in both impact and exploitability given existing controls",
    ),
  attackerProfile: z
    .string()
    .describe(
      "Name of the attacker profile that would execute this attack (must match a profile from ApplicationContext)",
    ),
  entryPoint: z
    .string()
    .describe(
      "Specific feature, input, or endpoint where the attack begins (e.g. 'POST /v1/sessions/{id}/act with malicious selector')",
    ),
  affectedFeatures: z
    .array(z.string())
    .describe(
      "Features affected by this attack path (must match feature names from ApplicationContext)",
    ),
  mechanism: z
    .array(z.string())
    .describe(
      "Step-by-step array showing how the attack flows through the system, from initial action to final impact. Each step should be a concrete, numbered action.",
    ),
  impact: z
    .string()
    .describe(
      "What happens if the attack succeeds — concrete consequences, not generic risk statements",
    ),
  preconditions: z
    .array(z.string())
    .describe(
      "Conditions that must be true for this attack to work (e.g. 'attacker has network access to API server')",
    ),
  existingControls: z
    .array(z.string())
    .describe(
      "Existing controls that partially or fully mitigate this attack (reference SecurityControl names where applicable)",
    ),
  controlGaps: z
    .array(z.string())
    .describe(
      "Missing or insufficient controls that make this attack viable",
    ),
  pentestGuidance: z
    .object({
      objectives: z
        .array(z.string())
        .describe(
          "Specific pentest objectives for validating this attack path",
        ),
      techniques: z
        .array(z.string())
        .describe(
          "Recommended testing techniques, tools, and example payloads/commands",
        ),
      deploymentConsiderations: z
        .array(z.string())
        .describe(
          "Deployment-specific details that affect testing. Empty array if none",
        ),
      prerequisites: z
        .array(z.string())
        .describe(
          "Prerequisites before testing (e.g. authenticated session, network access). Empty array if none",
        ),
    })
    .describe("Guidance for penetration testing this attack path"),
});

export type AttackPath = z.infer<typeof AttackPathSchema>;

// ---------------------------------------------------------------------------
// Top-level Threat Model Result
// ---------------------------------------------------------------------------

/**
 * Schema for what the threat model agent produces via structured output.
 * Contains only analytical output — no computed metadata or summaries.
 */
export const ThreatModelResultSchema = z.object({
  applicationContext: ApplicationContextSchema.describe(
    "Application identity, features, trust boundaries, and attacker profiles",
  ),
  deployment: DeploymentContextSchema.describe(
    "Deployment infrastructure context",
  ),
  architecture: SystemArchitectureSchema.describe(
    "System architecture — components, trust boundaries, and data flows",
  ),
  securityControls: SecurityControlsResultSchema.describe(
    "Security controls discovered in the codebase",
  ),
  attackPaths: z
    .array(AttackPathSchema)
    .describe("Attack paths identified through threat modeling"),
});

/** What the agent produces (Zod-inferred) */
export type ThreatModelAgentResult = z.infer<
  typeof ThreatModelResultSchema
>;

/** What the API returns — adds computed metadata and summary fields */
export interface ThreatModelResult {
  metadata: {
    mode: "whitebox";
    target: string;
    generatedAt: string;
    modelUsed: string;
    schemaVersion: string;
    repoType?: string;
    packageManager?: string;
  };
  applicationContext: ApplicationContext;
  deployment: DeploymentContext;
  architecture: SystemArchitecture;
  securityControls: SecurityControlsResult;
  attackPaths: AttackPath[];
  summary: {
    totalComponents: number;
    totalDataFlows: number;
    totalAttackPaths: number;
    bySeverity: Record<"critical" | "high" | "medium" | "low", number>;
    topRisks: string[];
  };
  files: {
    markdownPath: string;
    jsonPath: string;
  };
}
