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
        .describe(
          "Orchestration platform (e.g. Kubernetes, ECS, Docker Compose)",
        ),
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
          .describe(
            "IaC tool (e.g. Terraform, CDK, Pulumi, CloudFormation)",
          ),
        configPath: z.string().describe("Path to the IaC configuration"),
      }),
    )
    .describe("Infrastructure as Code tools detected (empty array if none)"),
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
        version: z.string().optional().describe("Version if determinable"),
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
      implementation: z.string().describe("Library or approach used"),
      sessionStorage: z
        .string()
        .describe(
          "How sessions are stored (stateless, Redis, DB, etc.)",
        ),
      mfa: z.string().optional().describe("MFA support status"),
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

/** System architecture: components, trust boundaries, and data flows */
export const SystemArchitectureSchema = z.object({
  components: z.array(ComponentSchema).describe("System components"),
  trustBoundaries: z
    .array(TrustBoundarySchema)
    .describe("Trust boundaries"),
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
    .describe("One-paragraph summary of what the application does"),
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
      "Key capabilities with security implications (e.g. executes browser actions, processes payments)",
    ),
});

export type ApplicationIdentity = z.infer<typeof ApplicationIdentitySchema>;

export const ApplicationFeatureSchema = z.object({
  name: z
    .string()
    .describe("Feature name (e.g. page navigation, form fill)"),
  description: z.string().describe("What the feature does"),
  securityRelevance: z
    .string()
    .describe("Why this feature matters for security"),
  privilegedOperations: z
    .array(z.string())
    .describe(
      "Privileged operations this feature can perform (e.g. file system access, network requests)",
    ),
  dataHandled: z
    .array(z.string())
    .describe(
      "Sensitive data this feature handles (e.g. user credentials, page content, cookies)",
    ),
});

export type ApplicationFeature = z.infer<typeof ApplicationFeatureSchema>;

export const ApplicationTrustBoundarySchema = z.object({
  name: z
    .string()
    .describe(
      "Boundary name (e.g. web page -> agent, user prompt -> browser action)",
    ),
  description: z
    .string()
    .describe("What crosses this boundary and why it matters"),
  inputSources: z
    .array(z.string())
    .describe("Where untrusted input comes from"),
  crossesTo: z
    .string()
    .describe("What sensitive context the input reaches"),
});

export type ApplicationTrustBoundary = z.infer<
  typeof ApplicationTrustBoundarySchema
>;

export const AttackerProfileSchema = z.object({
  name: z
    .string()
    .describe(
      "Profile name (e.g. malicious website operator, compromised dependency author)",
    ),
  description: z
    .string()
    .describe("Who this attacker is and their motivation"),
  controls: z
    .array(z.string())
    .describe(
      "What the attacker controls (e.g. web page content, npm package)",
    ),
  goals: z
    .array(z.string())
    .describe(
      "What the attacker wants to achieve (e.g. exfiltrate data, execute arbitrary code)",
    ),
  skillLevel: z
    .enum(["low", "medium", "high", "expert"])
    .describe("Expected attacker skill level"),
});

export type AttackerProfile = z.infer<typeof AttackerProfileSchema>;

export const ApplicationContextSchema = z.object({
  identity: ApplicationIdentitySchema.describe("What the application is"),
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
      "Realistic attacker profiles based on the application's nature",
    ),
});

export type ApplicationContext = z.infer<typeof ApplicationContextSchema>;

// ---------------------------------------------------------------------------
// Attack Paths
// ---------------------------------------------------------------------------

export const AttackPathSchema = z.object({
  id: z.string().describe("Unique attack path ID (e.g. AP-001)"),
  title: z.string().describe("Short descriptive title"),
  severity: z
    .enum(["critical", "high", "medium", "low"])
    .describe("Severity of the attack path"),
  attackerProfile: z
    .string()
    .describe(
      "Name of the attacker profile that would execute this attack",
    ),
  entryPoint: z
    .string()
    .describe(
      "Specific feature, input, or endpoint where the attack begins",
    ),
  mechanism: z
    .array(z.string())
    .describe(
      "Step-by-step array showing how the attack flows through the system",
    ),
  impact: z
    .string()
    .describe("What happens if the attack succeeds"),
  affectedFeatures: z
    .array(z.string())
    .describe("Features affected by this attack path"),
  preconditions: z
    .array(z.string())
    .describe(
      "Conditions that must be true for this attack to work",
    ),
  existingControls: z
    .array(z.string())
    .describe(
      "Existing controls that partially or fully mitigate this attack",
    ),
  controlGaps: z
    .array(z.string())
    .describe(
      "Missing or insufficient controls that make this attack viable",
    ),
  pentestGuidance: z.object({
    objectives: z
      .array(z.string())
      .describe("Specific pentest objectives for this attack path"),
    techniques: z
      .array(z.string())
      .describe("Recommended testing techniques and tools"),
    deploymentConsiderations: z
      .array(z.string())
      .describe(
        "Deployment-specific details that affect testing. Empty array if none",
      ),
    prerequisites: z
      .array(z.string())
      .describe(
        "Prerequisites before testing (e.g. authenticated session). Empty array if none",
      ),
  }),
});

export type AttackPath = z.infer<typeof AttackPathSchema>;

export const AttackPathsResultSchema = z.object({
  attackPaths: z
    .array(AttackPathSchema)
    .describe("Attack paths identified"),
});

export type AttackPathsResult = z.infer<typeof AttackPathsResultSchema>;

// ---------------------------------------------------------------------------
// Top-level Threat Model Result (returned from the threat model command)
// ---------------------------------------------------------------------------

export interface ThreatModelResult {
  metadata: {
    mode: "whitebox";
    target: string;
    generatedAt: string;
    modelUsed: string;
    schemaVersion: string;
    repoType: string;
    packageManager: string;
  };
  applicationContext: ApplicationContext;
  deployment: DeploymentContext;
  architecture: SystemArchitecture;
  securityControls: SecurityControlsResult;
  attackPaths: AttackPath[];
  summary: {
    totalAttackPaths: number;
    bySeverity: Record<"critical" | "high" | "medium" | "low", number>;
    topRisks: string[];
  };
  files: {
    markdownPath: string;
    jsonPath: string;
  };
}

// ---------------------------------------------------------------------------
// Threat Model (for serialization, without file paths)
// ---------------------------------------------------------------------------

export interface ThreatModel {
  metadata: {
    generatedAt: string;
    codebasePath: string;
    repoType: string;
    packageManager: string;
  };
  applicationContext: ApplicationContext;
  deployment: DeploymentContext;
  components: Component[];
  trustBoundaries: TrustBoundary[];
  dataFlows: DataFlow[];
  securityControls: SecurityControlsResult;
  attackPaths: AttackPath[];
  summary: {
    totalComponents: number;
    totalDataFlows: number;
    totalAttackPaths: number;
    attackPathsBySeverity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}
