import { z } from "zod";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import {
  type RiskScore,
  type Endpoint,
} from "../agents/specialized/whiteboxAttackSurface/types";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";
import { runWithBoundedConcurrency } from "../utils/concurrency";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CONCURRENCY = 5;

// ---------------------------------------------------------------------------
// Structured output schema for the risk scoring agent
// ---------------------------------------------------------------------------

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

type RiskScoreResult = z.infer<typeof RiskScoreResultSchema>;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const RISK_SCORE_SYSTEM_PROMPT = `You are an Endpoint Risk Scoring Agent. Your task is to evaluate an API or webpage endpoint and assign a Risk Score (0-10) that reflects how important it is to test this endpoint during a penetration test.

Read the source code at the specified location, analyze it, and provide a structured risk assessment. Be thorough but efficient — read only the relevant code.`;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface RiskScoringInput {
  codebasePath: string;
  endpoints: Array<Endpoint & { appName: string }>;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
  concurrency?: number;
}

/**
 * Calculate risk scores for a batch of endpoints using parallel CodeAgent instances.
 *
 * Each agent reads the endpoint's source code and scores it on four dimensions:
 *   - Exposure (0-3): How reachable is it for an attacker?
 *   - Data Sensitivity (0-3): How sensitive is the data it handles?
 *   - Function Criticality (0-2): How critical is the business logic?
 *   - Security Indicators (0-2): Are there obvious vuln patterns?
 *
 * Total risk score = sum of all four (0-10).
 */
export async function scoreEndpoints(
  input: RiskScoringInput,
): Promise<Map<string, RiskScore>> {
  const {
    codebasePath,
    endpoints,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    concurrency = DEFAULT_CONCURRENCY,
  } = input;

  const results = new Map<string, RiskScore>();

  const scored = await runWithBoundedConcurrency(
    endpoints,
    concurrency,
    async (ep) => {
      const key = `${ep.method}:${ep.file}:${ep.path}`;
      const subagentId = `risk-score-${ep.appName}-${ep.method}-${ep.path}`;

      callbacks?.subagentCallbacks?.onSubagentSpawn?.({
        subagentId,
        input: { app: ep.appName, path: ep.path },
        status: "pending",
      });

      try {
        const score = await scoreEndpoint({
          codebasePath,
          endpoint: ep,
          model,
          session,
          authConfig,
          abortSignal,
          callbacks,
        });

        callbacks?.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { app: ep.appName, path: ep.path },
          status: "completed",
        });

        return { key, score };
      } catch (error) {
        console.error(
          `Risk scoring failed for ${ep.path}: ${error instanceof Error ? error.message : String(error)}`,
        );
        callbacks?.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { app: ep.appName, path: ep.path },
          status: "failed",
        });
        return null;
      }
    },
  );

  for (const r of scored) {
    if (r) results.set(r.key, r.score);
  }

  return results;
}

// ---------------------------------------------------------------------------
// Single endpoint scoring
// ---------------------------------------------------------------------------

async function scoreEndpoint(opts: {
  codebasePath: string;
  endpoint: Endpoint;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
}): Promise<RiskScore> {
  const {
    codebasePath,
    endpoint: ep,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
  } = opts;

  const lineRange = ep.line ? `around line ${ep.line}` : "";
  const authInfo = ep.authRequired
    ? "Authentication required"
    : "No authentication required";

  const objective = `# Endpoint Risk Score Assessment

## Endpoint
- **Method**: ${ep.method}
- **Path**: ${ep.path}
- **File**: ${ep.file} ${lineRange}
- **Handler**: ${ep.handler ?? "unknown"}
- **Auth**: ${authInfo}
- **Description**: ${ep.description ?? "N/A"}

## Task
1. Read the source file at \`${ep.file}\` ${lineRange ? `(${lineRange})` : ""} to understand the implementation
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

  const agent = new CodeAgent<RiskScoreResult>({
    codebasePath,
    objective,
    system: RISK_SCORE_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    responseSchema: RiskScoreResultSchema,
  });

  const result = await agent.consume({
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  if (!result) {
    return {
      score: 0,
      explanation: "Risk scoring agent did not return a result",
      breakdown: {
        exposure: 0,
        dataSensitivity: 0,
        functionCriticality: 0,
        securityIndicators: 0,
      },
    };
  }

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
}
