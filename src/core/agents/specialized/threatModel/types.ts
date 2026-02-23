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
    .optional(),
  containers: z
    .object({
      runtime: z
        .string()
        .optional()
        .describe("Container runtime (e.g. Docker, Podman)"),
      orchestration: z
        .string()
        .optional()
        .describe("Orchestration platform (e.g. Kubernetes, ECS, Docker Compose)"),
      hasDockerfile: z.boolean().optional(),
      hasDockerCompose: z.boolean().optional(),
      hasKubernetes: z.boolean().optional(),
    })
    .optional(),
  iac: z
    .array(
      z.object({
        tool: z
          .string()
          .describe("IaC tool (e.g. Terraform, CDK, Pulumi, CloudFormation)"),
        configPath: z.string().describe("Path to the IaC configuration"),
      }),
    )
    .optional()
    .describe("Infrastructure as Code tools detected"),
  cicd: z
    .array(z.string())
    .optional()
    .describe("CI/CD platforms detected (e.g. GitHub Actions, GitLab CI, Jenkins)"),
  databases: z
    .array(
      z.object({
        type: z
          .string()
          .describe("Database type (e.g. PostgreSQL, MySQL, MongoDB, Redis)"),
        version: z.string().optional().describe("Version if determinable"),
      }),
    )
    .optional(),
  messageQueues: z
    .array(z.string())
    .optional()
    .describe("Message queues/brokers (e.g. RabbitMQ, SQS, Kafka)"),
  reverseProxy: z
    .string()
    .optional()
    .describe("Reverse proxy (e.g. nginx, Caddy, Traefik)"),
  environmentFiles: z
    .array(z.string())
    .optional()
    .describe("Environment file paths discovered (e.g. .env, .env.example)"),
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
    .describe("How the control is implemented (library, custom code, etc.)"),
  scope: z
    .string()
    .describe("What the control applies to (e.g. all routes, /api/* only)"),
  file: z.string().optional().describe("Source file where the control is defined"),
  line: z.number().optional().describe("Line number in the source file"),
  effectiveness: z
    .enum(["strong", "moderate", "weak", "unknown"])
    .describe("Assessed effectiveness of the control"),
  gaps: z
    .string()
    .optional()
    .describe("Known gaps or weaknesses in the control"),
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
        .describe("Auth type (e.g. JWT Bearer, Session Cookie, OAuth2, API Key)"),
      implementation: z.string().describe("Library or approach used"),
      sessionStorage: z
        .string()
        .describe("How sessions are stored (stateless, Redis, DB, etc.)"),
      mfa: z.string().optional().describe("MFA support status"),
    })
    .optional()
    .describe("Primary authentication mechanism"),
  authorizationModel: z
    .object({
      type: z
        .string()
        .describe("Authorization model (e.g. RBAC, ABAC, ACL, custom)"),
      implementation: z.string().describe("How authorization is enforced"),
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
    .describe("Technology stack (e.g. Express.js on Node 20, PostgreSQL 15)"),
  trustBoundary: z
    .string()
    .describe("Name of the trust boundary this component belongs to"),
});

export type Component = z.infer<typeof ComponentSchema>;

export const TrustBoundarySchema = z.object({
  id: z.string().describe("Unique boundary ID (e.g. tb-external)"),
  name: z.string().describe("Human-readable boundary name"),
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
    .describe("Protocol used (e.g. HTTPS, SQL/TLS, Redis, gRPC)"),
  dataClassification: z
    .enum(["public", "internal", "confidential", "restricted"])
    .describe("Data sensitivity classification"),
  authenticated: z.boolean().describe("Whether the flow requires authentication"),
  encrypted: z.boolean().describe("Whether the flow is encrypted in transit"),
});

export type DataFlow = z.infer<typeof DataFlowSchema>;

// ---------------------------------------------------------------------------
// STRIDE Threats
// ---------------------------------------------------------------------------

export const AttackVectorSchema = z.object({
  endpoint: z.string().describe("Target endpoint path"),
  method: z
    .string()
    .describe("HTTP method or access method (e.g. GET, POST, PAGE)"),
  parameter: z
    .string()
    .optional()
    .describe("Target parameter (query param, body field, header, etc.)"),
  technique: z.string().describe("Attack technique description"),
  toolSuggestions: z
    .array(z.string())
    .optional()
    .describe("Suggested tools (e.g. sqlmap, burpsuite, curl)"),
});

export type AttackVector = z.infer<typeof AttackVectorSchema>;

export const ThreatSchema = z.object({
  id: z.string().describe("Unique threat ID (e.g. T-001)"),
  category: z
    .enum([
      "spoofing",
      "tampering",
      "repudiation",
      "information_disclosure",
      "denial_of_service",
      "elevation_of_privilege",
    ])
    .describe("STRIDE threat category"),
  title: z.string().describe("Short descriptive title"),
  description: z.string().describe("Detailed threat description"),
  targetComponent: z.string().describe("Primary target component ID"),
  affectedDataFlow: z
    .string()
    .optional()
    .describe("Affected data flow ID, if applicable"),
  residualRisk: z
    .enum(["critical", "high", "medium", "low", "negligible"])
    .describe("Residual risk after existing mitigations"),
  preconditions: z
    .array(z.string())
    .describe("Conditions that must be true for this threat to be exploitable"),
  attackVectors: z
    .array(AttackVectorSchema)
    .describe("Specific attack vectors with endpoints and techniques"),
  existingMitigations: z
    .array(z.string())
    .describe(
      "Existing mitigations from security controls, with effectiveness notes",
    ),
  pentestGuidance: z.object({
    objectives: z
      .array(z.string())
      .describe("Specific pentest objectives for this threat"),
    suggestedTools: z
      .array(z.string())
      .optional()
      .describe("Tools to use for testing"),
    deploymentConsiderations: z
      .array(z.string())
      .optional()
      .describe(
        "Deployment-specific details that affect testing (DB type, framework, etc.)",
      ),
    prerequisites: z
      .array(z.string())
      .optional()
      .describe("Prerequisites before testing (e.g. authenticated session)"),
  }),
});

export type Threat = z.infer<typeof ThreatSchema>;

// ---------------------------------------------------------------------------
// Top-level STRIDE Threat Model
// ---------------------------------------------------------------------------

export const STRIDEThreatModelSchema = z.object({
  metadata: z.object({
    generatedAt: z.string().describe("ISO 8601 timestamp"),
    codebasePath: z.string().describe("Path to the analyzed codebase"),
    repoType: z.string().describe("Repository type (monorepo, single-app, etc.)"),
    packageManager: z.string().describe("Package manager in use"),
  }),
  deployment: DeploymentContextSchema,
  components: z.array(ComponentSchema).describe("System components"),
  trustBoundaries: z
    .array(TrustBoundarySchema)
    .describe("Trust boundaries"),
  dataFlows: z.array(DataFlowSchema).describe("Data flows between components"),
  securityControls: SecurityControlsResultSchema,
  threats: z.array(ThreatSchema).describe("STRIDE threats identified"),
  summary: z.object({
    totalComponents: z.number(),
    totalDataFlows: z.number(),
    totalThreats: z.number(),
    threatsByCategory: z.object({
      spoofing: z.number(),
      tampering: z.number(),
      repudiation: z.number(),
      information_disclosure: z.number(),
      denial_of_service: z.number(),
      elevation_of_privilege: z.number(),
    }),
    threatsByRisk: z.object({
      critical: z.number(),
      high: z.number(),
      medium: z.number(),
      low: z.number(),
      negligible: z.number(),
    }),
  }),
});

export type STRIDEThreatModel = z.infer<typeof STRIDEThreatModelSchema>;
