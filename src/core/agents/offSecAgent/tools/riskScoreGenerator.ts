import { z } from "zod";
import type { ToolContext } from "./types";
import type { RiskScore } from "../../specialized/whiteboxAttackSurface/types";
import { AgentEventBus, type AgentEventMap } from "../../../eventBus";

const RiskScoreResultSchema = z.object({
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
  justification: z
    .string()
    .describe(
      "Overall justification summarizing why this endpoint received this risk score",
    ),
});

const RISK_SCORE_SYSTEM_PROMPT = `You are an Endpoint Risk Scoring Agent. Your task is to evaluate an API or webpage endpoint and assign a Risk Score (0-10) that reflects how important it is to test this endpoint during a penetration test.

Read the source code at the specified location, analyze it, and provide a structured risk assessment. Be thorough but efficient — read only the relevant code.`;

export interface GenerateRiskScoreInput {
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

/**
 * Spawn a dedicated CodeAgent to produce an LLM-based risk score for a single
 * endpoint. Called from inside the `document_endpoint` tool's execute function
 * so that each documented endpoint gets its own scoring pass instead of
 * running a large batch scoring step at the end of the recon workflow.
 */
export async function generateRiskScoreForEndpoint(
  ctx: ToolContext,
  input: GenerateRiskScoreInput,
): Promise<RiskScore | null> {
  if (!ctx.model) return null;
  if (!input.file) return null;

  const { CodeAgent } = await import("../../specialized/codeAgent/agent");

  const subagentId = `risk-score-${sanitize(input.appName)}-${sanitize(input.endpointName)}`;

  ctx.eventBus?.emit("subagent-spawn", {
    subagentId,
    name: `Risk Score: ${input.endpointName}`,
    input: { app: input.appName, endpoint: input.endpointName },
  });

  const localBus = new AgentEventBus();
  attachChildEventBus(localBus, ctx.eventBus);

  const prompt = buildRiskScorePrompt(input);

  const agent = new CodeAgent<z.infer<typeof RiskScoreResultSchema>>({
    codebasePath: ctx.agentCwd,
    objective: prompt,
    system: RISK_SCORE_SYSTEM_PROMPT,
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: localBus,
    subagentId,
    responseSchema: RiskScoreResultSchema,
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
      score: totalScore,
      explanation: result.justification,
      breakdown: {
        exposure: result.exposure,
        dataSensitivity: result.dataSensitivity,
        functionCriticality: result.functionCriticality,
        securityIndicators: result.securityIndicators,
      },
    };
  } catch (error) {
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
    });
    console.error(
      `Risk score generation failed for ${input.endpointName}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
}

function buildRiskScorePrompt(input: GenerateRiskScoreInput): string {
  const lineRange = input.line ? `around line ${input.line}` : "";
  const authInfo = input.authRequired
    ? "Authentication required"
    : "No authentication required";
  const methodStr = Array.isArray(input.method)
    ? input.method.join(", ")
    : (input.method ?? "unknown");

  return `# Endpoint Risk Score Assessment

## Endpoint
- **Application**: ${input.appName}
- **Method**: ${methodStr}
- **Path**: ${input.routePath ?? input.endpointName}
- **File**: ${input.file ?? "unknown"}${input.line ? `:${input.line}` : ""}
- **Handler**: ${input.handler ?? "unknown"}
- **Auth**: ${authInfo}
- **Description**: ${input.description}

## Task
1. Read the source file at \`${input.file ?? "(unknown)"}\` ${lineRange ? `(${lineRange})` : ""} to understand the implementation
2. Analyze authentication requirements, data handling, business logic, and security patterns
3. Score each dimension and provide your assessment via the \`response\` tool

## Scoring Model

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

**Final Score = Exposure + DataSensitivity + FunctionCriticality + SecurityIndicators (0-10)**

Begin by reading the source code, then call \`response\` with your assessment.`;
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
