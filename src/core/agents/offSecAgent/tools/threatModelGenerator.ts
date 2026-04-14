import { z } from "zod";
import type { ToolContext } from "./types";
import type { RiskScore } from "../../specialized/whiteboxAttackSurface/types";
import { AgentEventBus, type AgentEventMap } from "../../../eventBus";

const ThreatModelResultSchema = z.object({
  threatModel: z
    .string()
    .describe(
      "A focused threat model for this specific endpoint. Include: " +
        "attacker profiles relevant to this endpoint, attack vectors those " +
        "attackers could exploit, data sensitivity assessment, " +
        "authentication/authorization risks, input validation concerns, " +
        "business logic risks, and prioritized testing recommendations.",
    ),
  exposure: z
    .number()
    .min(0)
    .max(3)
    .describe(
      "Exposure Level (0-3): 3=Public endpoint no auth, 2=Requires standard user login, 1=Requires privileged/admin access, 0=Private/internal-only",
    ),
  exposureReasoning: z
    .string()
    .describe("Brief explanation for the exposure score"),
  dataSensitivity: z
    .number()
    .min(0)
    .max(3)
    .describe(
      "Data Sensitivity (0-3): 3=PII/PHI/financial/passwords/tokens, 2=Business operations/configs, 1=Low-value user data, 0=No meaningful data",
    ),
  dataSensitivityReasoning: z
    .string()
    .describe("Brief explanation for the data sensitivity score"),
  functionCriticality: z
    .number()
    .min(0)
    .max(2)
    .describe(
      "Function Criticality (0-2): 2=Auth flows/password resets/payments/state-changing mutations, 1=Core product functionality, 0=Non-critical content",
    ),
  functionCriticalityReasoning: z
    .string()
    .describe("Brief explanation for the function criticality score"),
  securityIndicators: z
    .number()
    .min(0)
    .max(2)
    .describe(
      "Security Indicators (0-2): 2=Critical vulnerability patterns found (SQL injection, command injection, hardcoded secrets, path traversal), 1=Moderate security concerns (missing input validation, weak error handling), 0=No obvious security issues",
    ),
  securityIndicatorsReasoning: z
    .string()
    .describe(
      "Brief explanation for the security indicators score, including specific vulnerability patterns observed if any",
    ),
  riskScoreJustification: z
    .string()
    .describe(
      "Overall justification summarizing why this endpoint received this risk score",
    ),
});

type ThreatModelResult = z.infer<typeof ThreatModelResultSchema>;

const THREAT_MODEL_SYSTEM_PROMPT = `You are an Endpoint Threat Modeling & Risk Scoring Agent. Your task is to analyze a specific API endpoint or web page, produce a focused threat model, and assign a quantitative risk score (0-10).

Read the source code at the specified location. Analyze the endpoint's:
- Input handling and validation
- Authentication and authorization requirements
- Data access patterns and sensitivity
- Business logic and state transitions
- Error handling and information disclosure
- Dependencies and trust boundaries

Think in terms of concrete attackers — not abstract threat categories. For this endpoint, identify the realistic attacker profiles that would actually target it, then ground every attack vector and testing priority in what a specific attacker would do. Attacker profiles should reflect the application's domain, the endpoint's exposure, and the data it handles.

Produce a concise, actionable threat model that a penetration tester can use to prioritize their testing approach for this endpoint, along with a structured risk score breakdown.`;

export interface GenerateThreatModelInput {
  appName: string;
  endpointName: string;
  routePath?: string;
  method?: string | string[];
  file?: string;
  line?: number;
  handler?: string;
  authRequired?: boolean;
  description: string;
  pentestObjectives: string[];
}

export interface ThreatModelOutput {
  threatModel: string;
  riskScore: RiskScore;
}

/**
 * Spawn a dedicated CodeAgent to produce a focused threat model and
 * quantitative risk score for a single endpoint. Both outputs come from one
 * agent pass — the agent reads the source code once and returns the threat
 * model text alongside a structured 4-dimension risk score breakdown.
 */
export async function generateThreatModelForEndpoint(
  ctx: ToolContext,
  input: GenerateThreatModelInput,
): Promise<ThreatModelOutput | null> {
  if (!ctx.model) return null;

  const { CodeAgent } = await import("../../specialized/codeAgent/agent");

  const subagentId = `threat-model-${sanitize(input.appName)}-${sanitize(input.endpointName)}`;

  ctx.eventBus?.emit("subagent-spawn", {
    subagentId,
    name: `Threat Model: ${input.endpointName}`,
    input: { app: input.appName, endpoint: input.endpointName },
  });

  const localBus = new AgentEventBus();
  attachChildEventBus(localBus, ctx.eventBus);

  const prompt = buildThreatModelPrompt(input, ctx.projectThreatModel);

  const agent = new CodeAgent<ThreatModelResult>({
    codebasePath: ctx.agentCwd,
    objective: prompt,
    system: THREAT_MODEL_SYSTEM_PROMPT,
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: localBus,
    subagentId,
    responseSchema: ThreatModelResultSchema,
    excludeTools: ["document_endpoint", "document_app"],
  });

  try {
    const result = await agent.consume();
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "completed",
    });

    if (!result) return null;

    const totalScore =
      result.exposure +
      result.dataSensitivity +
      result.functionCriticality +
      result.securityIndicators;

    return {
      threatModel: result.threatModel,
      riskScore: {
        score: totalScore,
        explanation: result.riskScoreJustification,
        breakdown: {
          exposure: result.exposure,
          dataSensitivity: result.dataSensitivity,
          functionCriticality: result.functionCriticality,
          securityIndicators: result.securityIndicators,
        },
      },
    };
  } catch (error) {
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
    });
    console.error(
      `Threat model generation failed for ${input.endpointName}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
}

function buildThreatModelPrompt(
  input: GenerateThreatModelInput,
  projectThreatModel?: string,
): string {
  const lineRange = input.line ? `around line ${input.line}` : "";
  const authInfo = input.authRequired
    ? "Authentication required"
    : "No authentication required";
  const methodStr = Array.isArray(input.method)
    ? input.method.join(", ")
    : (input.method ?? "unknown");

  let prompt = `# Endpoint Threat Model & Risk Score Assessment

## Target Endpoint
- **Application**: ${input.appName}
- **Method**: ${methodStr}
- **Path**: ${input.routePath ?? input.endpointName}
- **File**: ${input.file ?? "unknown"}${input.line ? `:${input.line}` : ""}
- **Handler**: ${input.handler ?? "unknown"}
- **Auth**: ${authInfo}
- **Description**: ${input.description}
- **Existing Objectives**: ${input.pentestObjectives.join(", ") || "none"}

## Instructions
1. Read the source file at \`${input.file ?? "(unknown)"}\` ${lineRange ? `(${lineRange})` : ""} to understand the implementation.
2. If helpful, briefly explore surrounding files (auth middleware, shared handlers, type definitions) to ground your analysis — but stay focused on this endpoint.
3. Analyze the endpoint implementation thoroughly.

## Part 1: Threat Model

Produce a threat model covering:
   - **Attacker Profiles**: 2-4 realistic attackers who would target THIS endpoint. For each profile include:
     - A descriptive name and 1-2 sentence motivation grounded in the application's domain and what this endpoint does
     - Skill level (Low / Medium / High / Expert)
     - What the attacker controls (network position, accounts, API keys, authenticated session, insider access, etc.)
     - What the attacker wants to achieve *via this endpoint specifically* (data theft, privilege escalation, account takeover, service disruption, etc.)
     Include a mix — e.g. an opportunistic external attacker, an authenticated user abusing legitimate access, and at least one more sophisticated or insider profile when relevant. Skip profiles that are not realistic for this endpoint (e.g. don't invent an "insider threat" if the endpoint is unauthenticated and has no insider access surface).
   - **Attack Vectors**: Specific attacks relevant to this endpoint (e.g., injection, auth bypass, IDOR, business logic flaws). Be concrete — reference actual parameters, data flows, and code patterns you observe. Tie each vector back to one of the attacker profiles you defined above ("A [Profile Name] could ...").
   - **Data Sensitivity**: What data does this endpoint handle? PII, credentials, financial data, etc.
   - **Trust Boundaries**: Where does external input enter? What internal services does it call?
   - **Risk Assessment**: What's the worst-case impact of a successful attack on this endpoint?
   - **Testing Priorities**: Ordered list of what a pentester should test first and why. Reference the attacker profile each test is simulating.

Keep the threat model concise (400-800 words). Focus on what's specific to THIS endpoint — not generic web security advice. Every attacker profile and attack vector must be grounded in code you actually read.

## Part 2: Risk Score

Score each dimension based on what you observed in the code:

### 1. Exposure Level (0-3)
| Score | Description |
|-------|-------------|
| 3 | Public endpoint, no authentication required |
| 2 | Requires standard user login |
| 1 | Requires privileged/admin access |
| 0 | Private, IP-restricted, or internal-only |

### 2. Data Sensitivity (0-3)
| Score | Example Data |
|-------|-------------|
| 3 | PII, PHI, financial data, passwords, tokens, secrets |
| 2 | Business operations data, configs, settings |
| 1 | Low-value or non-sensitive user data |
| 0 | No meaningful data (static content, health checks) |

### 3. Function Criticality (0-2)
| Score | Examples |
|-------|---------|
| 2 | Auth flows, password resets, payments, permission changes |
| 1 | Core product functionality (CRUD on user data) |
| 0 | Non-critical content or utility endpoints |

### 4. Security Indicators (0-2)
| Score | Indicators |
|-------|-----------|
| 2 | Critical vuln patterns: SQL injection, command injection, hardcoded secrets, path traversal, unsafe deserialization |
| 1 | Moderate concerns: missing input validation, weak error handling, missing output encoding, overly permissive CORS |
| 0 | No obvious security issues — code follows best practices |

**Final Score = Exposure + DataSensitivity + FunctionCriticality + SecurityIndicators (0-10)**`;

  if (projectThreatModel) {
    prompt += `

## Additional Context (Project-Level Threat Model)
The repository owner has provided a project-level threat model. Use it to inform your assessment — it may contain deployment details, compliance requirements, or known concerns relevant to this endpoint:

<project-threat-model>
${projectThreatModel}
</project-threat-model>`;
  }

  prompt += `

Call the \`response\` tool with your threat model and risk score assessment.`;

  return prompt;
}

function sanitize(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

const CHILD_BUS_EVENT_KEYS = [
  "text-delta",
  "tool-call-start",
  "tool-call-delta",
  "tool-call-complete",
  "tool-result",
  "subagent-spawn",
  "subagent-complete",
  "command-output",
  "error",
  "step-finish",
] as const satisfies readonly (keyof AgentEventMap)[];

function attachChildEventBus(
  local: AgentEventBus,
  parent: AgentEventBus | undefined,
): void {
  for (const key of CHILD_BUS_EVENT_KEYS) {
    local.on(key, (payload: AgentEventMap[typeof key]) => {
      parent?.emit(key, payload);
    });
  }
}
