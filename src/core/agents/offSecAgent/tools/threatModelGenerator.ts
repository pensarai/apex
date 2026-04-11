import { z } from "zod";
import type { ToolContext } from "./types";
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
});

const THREAT_MODEL_SYSTEM_PROMPT = `You are an Endpoint Threat Modeling Agent. Your task is to analyze a specific API endpoint or web page and produce a focused threat model that describes the relevant attackers, security risks, attack vectors, and testing priorities for that exact endpoint.

Read the source code at the specified location. Analyze the endpoint's:
- Input handling and validation
- Authentication and authorization requirements
- Data access patterns and sensitivity
- Business logic and state transitions
- Error handling and information disclosure
- Dependencies and trust boundaries

Think in terms of concrete attackers — not abstract threat categories. For this endpoint, identify the realistic attacker profiles that would actually target it, then ground every attack vector and testing priority in what a specific attacker would do. Attacker profiles should reflect the application's domain, the endpoint's exposure, and the data it handles.

Produce a concise, actionable threat model that a penetration tester can use to prioritize their testing approach for this endpoint.`;

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

/**
 * Spawn a dedicated CodeAgent to produce a focused threat model for a single
 * endpoint. Called from inside the `document_endpoint` tool's execute function
 * so that each documented endpoint gets its own analysis pass instead of
 * relying on the parent discovery agent to write the threat model inline.
 */
export async function generateThreatModelForEndpoint(
  ctx: ToolContext,
  input: GenerateThreatModelInput,
): Promise<string | null> {
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

  const agent = new CodeAgent<{ threatModel: string }>({
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
    return result?.threatModel ?? null;
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

  let prompt = `# Endpoint Threat Model Assessment

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
4. Produce a threat model covering:
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

Keep the threat model concise (400-800 words). Focus on what's specific to THIS endpoint — not generic web security advice. Every attacker profile and attack vector must be grounded in code you actually read.`;

  if (projectThreatModel) {
    prompt += `

## Additional Context (Project-Level Threat Model)
The repository owner has provided a project-level threat model. Use it to inform your assessment — it may contain deployment details, compliance requirements, or known concerns relevant to this endpoint:

<project-threat-model>
${projectThreatModel}
</project-threat-model>`;
  }

  prompt += `

Call the \`response\` tool with your threat model.`;

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
