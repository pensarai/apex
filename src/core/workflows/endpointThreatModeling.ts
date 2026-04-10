import { z } from "zod";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import type { Endpoint } from "../agents/specialized/whiteboxAttackSurface/types";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { AgentEventBus } from "../eventBus";
import { runWithBoundedConcurrency } from "../utils/concurrency";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CONCURRENCY = 5;

// ---------------------------------------------------------------------------
// Structured output schema
// ---------------------------------------------------------------------------

const ThreatModelResultSchema = z.object({
  threatModel: z
    .string()
    .describe(
      "A focused threat model for this specific endpoint. Include: " +
        "attack vectors relevant to this endpoint, data sensitivity assessment, " +
        "authentication/authorization risks, input validation concerns, " +
        "business logic risks, and prioritized testing recommendations.",
    ),
});

type ThreatModelResult = z.infer<typeof ThreatModelResultSchema>;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const THREAT_MODEL_SYSTEM_PROMPT = `You are an Endpoint Threat Modeling Agent. Your task is to analyze a specific API endpoint or web page and produce a focused threat model that describes the security risks, attack vectors, and testing priorities for that exact endpoint.

Read the source code at the specified location. Analyze the endpoint's:
- Input handling and validation
- Authentication and authorization requirements
- Data access patterns and sensitivity
- Business logic and state transitions
- Error handling and information disclosure
- Dependencies and trust boundaries

Produce a concise, actionable threat model that a penetration tester can use to prioritize their testing approach for this endpoint.`;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface EndpointThreatModelingInput {
  codebasePath: string;
  endpoints: Array<Endpoint & { appName: string }>;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  concurrency?: number;
  userThreatModel?: string;
}

/**
 * Generate threat models for a batch of endpoints using parallel CodeAgent
 * instances. Each agent reads the endpoint's source code and produces a
 * focused threat model (300–600 words).
 */
export async function generateEndpointThreatModels(
  input: EndpointThreatModelingInput,
): Promise<Map<string, string>> {
  const {
    codebasePath,
    endpoints,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    concurrency = DEFAULT_CONCURRENCY,
    userThreatModel,
  } = input;

  const results = new Map<string, string>();

  const generated = await runWithBoundedConcurrency(
    endpoints,
    concurrency,
    async (ep) => {
      const key = `${ep.method}:${ep.file}:${ep.path}`;
      const subagentId = `threat-model-${ep.appName}-${ep.method}-${ep.path}`;

      eventBus?.emit("subagent-spawn", {
        subagentId,
        name: ep.appName,
        input: { app: ep.appName, path: ep.path },
      });

      try {
        const threatModel = await generateSingleThreatModel({
          codebasePath,
          endpoint: ep,
          model,
          session,
          authConfig,
          abortSignal,
          eventBus,
          subagentId,
          userThreatModel,
        });

        eventBus?.emit("subagent-complete", {
          subagentId,
          status: "completed",
        });

        return { key, threatModel };
      } catch (error) {
        console.error(
          `Threat model generation failed for ${ep.path}: ${error instanceof Error ? error.message : String(error)}`,
        );
        eventBus?.emit("subagent-complete", {
          subagentId,
          status: "failed",
        });
        return null;
      }
    },
  );

  for (const r of generated) {
    if (r) results.set(r.key, r.threatModel);
  }

  return results;
}

// ---------------------------------------------------------------------------
// Single endpoint threat model generation
// ---------------------------------------------------------------------------

async function generateSingleThreatModel(opts: {
  codebasePath: string;
  endpoint: Endpoint & { appName: string };
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  subagentId: string;
  userThreatModel?: string;
}): Promise<string> {
  const {
    codebasePath,
    endpoint: ep,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    subagentId,
    userThreatModel,
  } = opts;

  const objective = buildThreatModelObjective(ep, userThreatModel);

  const agent = new CodeAgent<ThreatModelResult>({
    codebasePath,
    objective,
    system: THREAT_MODEL_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    subagentId,
    responseSchema: ThreatModelResultSchema,
  });

  const result = await agent.consume();

  if (!result) {
    return "Threat model generation did not return a result.";
  }

  return result.threatModel;
}

// ---------------------------------------------------------------------------
// Objective builder
// ---------------------------------------------------------------------------

function buildThreatModelObjective(
  endpoint: Endpoint & { appName: string },
  userThreatModel?: string,
): string {
  const lineRange = endpoint.line ? `around line ${endpoint.line}` : "";
  const authInfo = endpoint.authRequired
    ? "Authentication required"
    : "No authentication required";

  let objective = `# Endpoint Threat Model Assessment

## Target Endpoint
- **Application**: ${endpoint.appName}
- **Method**: ${endpoint.method}
- **Path**: ${endpoint.path}
- **File**: ${endpoint.file}${endpoint.line ? `:${endpoint.line}` : ""}
- **Handler**: ${endpoint.handler ?? "unknown"}
- **Auth**: ${authInfo}
- **Description**: ${endpoint.description ?? "none"}
- **Existing Objectives**: ${endpoint.pentestObjectives?.join(", ") || "none"}

## Instructions
1. Read the source file at \`${endpoint.file}\` ${lineRange ? `(${lineRange})` : ""} to understand the implementation.
2. Analyze the endpoint implementation thoroughly.
3. Produce a threat model covering:
   - **Attack Vectors**: Specific attacks relevant to this endpoint (e.g., injection, auth bypass, IDOR, business logic flaws). Be concrete — reference actual parameters, data flows, and code patterns you observe.
   - **Data Sensitivity**: What data does this endpoint handle? PII, credentials, financial data, etc.
   - **Trust Boundaries**: Where does external input enter? What internal services does it call?
   - **Risk Assessment**: What's the worst-case impact of a successful attack on this endpoint?
   - **Testing Priorities**: Ordered list of what a pentester should test first and why.

Keep the threat model concise (300-600 words). Focus on what's specific to THIS endpoint — not generic web security advice.`;

  if (userThreatModel) {
    objective += `

## Additional Context (User-Provided Threat Model)
The repository owner has provided the following threat model context. Use it to inform your assessment — it may contain deployment details, compliance requirements, or known concerns relevant to this endpoint:

<user-threat-model>
${userThreatModel}
</user-threat-model>`;
  }

  objective += `

Call the \`response\` tool with your threat model.`;

  return objective;
}
