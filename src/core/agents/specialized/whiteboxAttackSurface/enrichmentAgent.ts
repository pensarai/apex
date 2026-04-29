import type { z } from "zod";
import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { CodeAgent } from "../codeAgent/agent";
import {
  AppInfoSchema,
  DiscoverySummarySchema,
  WHITEBOX_ENRICHMENT_SYSTEM_PROMPT,
  type DiscoverySummary,
} from "../../../workflows/whiteboxAttackSurface";
import type {
  ConsolidatedEndpoint,
  FrameworkId,
} from "../../../integrations/surface/types";
import type { AIModel, CacheMetrics } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { SessionInfo } from "../../../session";
import type { AgentEventBus } from "../../../eventBus";
import type { AttackSurfaceRegistry } from "../../../findings/attackSurfaceRegistry";
import { runWithBoundedConcurrency } from "../../../utils/concurrency";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Per-app fan-out concurrency. Each app's enrichment runs N endpoint agents
 * in parallel up to this cap. Workflow-level concurrency (across apps) is
 * separately bounded by `DEFAULT_CONCURRENCY` in
 * `runWhiteboxAttackSurfaceWorkflow` Phase 2.
 */
const ENRICHMENT_CONCURRENCY = 5;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AppInfo = z.infer<typeof AppInfoSchema>;

interface SharedAgentOptions {
  codebasePath: string;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  attackSurfaceRegistry?: AttackSurfaceRegistry;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onCacheMetrics?: (metrics: CacheMetrics) => void;
  projectThreatModel?: string;
}

export interface EndpointEnrichmentInput extends SharedAgentOptions {
  app: AppInfo;
  endpoint: ConsolidatedEndpoint;
  frameworks: FrameworkId[];
}

export interface AppEnrichmentInput extends SharedAgentOptions {
  app: AppInfo;
  endpoints: ConsolidatedEndpoint[];
  frameworks: FrameworkId[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function slug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_|_$/g, "");
}

export function buildEnrichmentObjective(opts: {
  app: AppInfo;
  codebasePath: string;
  endpoint: ConsolidatedEndpoint;
  frameworks: FrameworkId[];
}): string {
  const { app, codebasePath, endpoint, frameworks } = opts;

  const frameworkLabel =
    frameworks.length > 0 ? frameworks.join(", ") : "unknown";
  const method = endpoint.method.join(",");
  const auth = endpoint.auth.length > 0 ? endpoint.auth.join(", ") : "none";
  const authPrefill = endpoint.auth.length > 0;
  const endpointType =
    endpoint.kind === "page" ? "web-endpoint" : "api-endpoint";

  return `# Enrich Endpoint: ${method} ${endpoint.path}

## Codebase
- **Repository root:** ${codebasePath}
- **App:** ${app.name}
- **App location:** ${app.location}
- **Framework(s):** ${frameworkLabel}

## Endpoint (deterministically extracted by surface)

- **method**: ${method}
- **routePath**: ${endpoint.path}
- **file**: ${endpoint.file}:${endpoint.line}
- **handler**: ${endpoint.handler}
- **endpointType**: ${endpointType}
- **auth signals**: ${auth}
- **prefilled authRequired**: ${authPrefill}

## Task

Document this **single endpoint** by calling \`document_endpoint\` exactly once with these flat fields:

- **appName**: \`"${app.name}"\`
- **routePath**: \`"${endpoint.path}"\` (the HTTP route — NOT a source-file path).
- **method**: \`${JSON.stringify(endpoint.method.length === 1 ? endpoint.method[0] : endpoint.method)}\` (use the value above as-is).
- **endpointType**: \`"${endpointType}"\`.
- **file**: \`"${endpoint.file}"\` (do not modify).
- **line**: \`${endpoint.line}\` (do not modify).
- **handler**: \`"${endpoint.handler}"\` (do not modify).
- **authRequired**: start from the prefilled value above. Override only after reading the middleware chain at the indicated file when the signals are genuinely ambiguous.
- **description**: 1–2 sentences explaining what this endpoint does in plain English. Read the handler at \`${endpoint.file}:${endpoint.line}\` to ground it.
- **riskLevel**: one of \`CRITICAL\`, \`HIGH\`, \`MEDIUM\`, or \`LOW\`. CRITICAL for auth/payment/admin or unauthenticated state-changing routes; HIGH for authenticated user-data mutations; MEDIUM for general; LOW for static/public reads.
- **toolCallDescription**: one short line, e.g. \`"Documenting ${method} ${endpoint.path}"\`.

You do NOT pass \`pentestObjectives\` — \`document_endpoint\` generates them automatically.

## Scope

This agent is responsible for **exactly one** endpoint. Do not document other endpoints. Do not enumerate routes. Your tool registry blocks \`list_files\`, \`grep\`, and \`document_app\` so this is enforced at the tool layer too.

## Workflow

1. \`read_file\` the handler at \`${endpoint.file}:${endpoint.line}\` (use a small line range — you don't need the whole file).
2. Optionally read the middleware referenced by auth signals if you need to refine \`authRequired\`.
3. Call \`document_endpoint\` once with the fields above.
4. Call \`response\` with \`{ endpointsDocumented: 1, summary: "<one-line summary>" }\`.
`;
}

// ---------------------------------------------------------------------------
// Per-endpoint agent runner
// ---------------------------------------------------------------------------

export async function runEnrichmentAgent(
  opts: EndpointEnrichmentInput,
): Promise<void> {
  const {
    codebasePath,
    app,
    endpoint,
    frameworks,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    attackSurfaceRegistry,
    onStepFinish,
    onCacheMetrics,
    projectThreatModel,
  } = opts;

  const subagentId = `enrich-${slug(app.name)}-${slug(endpoint.path)}`;
  const displayName = `${app.name}: ${endpoint.method.join(",")} ${endpoint.path}`;

  eventBus?.emit("subagent-spawn", {
    subagentId,
    name: displayName,
    input: {
      app: app.name,
      type: "enrichment",
      method: endpoint.method,
      path: endpoint.path,
    },
  });

  const objective = buildEnrichmentObjective({
    app,
    codebasePath,
    endpoint,
    frameworks,
  });

  const agent = new CodeAgent<DiscoverySummary>({
    codebasePath,
    objective,
    system: WHITEBOX_ENRICHMENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    attackSurfaceRegistry,
    eventBus,
    subagentId,
    onStepFinish: (event) => onStepFinish?.(event),
    onCacheMetrics,
    responseSchema: DiscoverySummarySchema,
    // Hard-exclude tools an enrichment agent must never use:
    // - document_app: Phase 1 owns app discovery.
    // - list_files / grep: route enumeration is surface's job; without this,
    //   soft prompt guidance gets overridden by the model's discovery instinct
    //   and the agent orients-first, looking like a discovery pass.
    excludeTools: ["document_app", "list_files", "grep"],
    projectThreatModel,
  });

  try {
    await agent.consume();
    eventBus?.emit("subagent-complete", {
      subagentId,
      status: "completed",
    });
  } catch (error) {
    console.error(
      `[enrichment-agent] "${subagentId}" FAILED:`,
      error instanceof Error ? error.message : String(error),
    );
    eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
    });
  }
}

// ---------------------------------------------------------------------------
// App-level fan-out
// ---------------------------------------------------------------------------

export async function runAppEnrichment(
  opts: AppEnrichmentInput,
): Promise<void> {
  const { endpoints, ...shared } = opts;
  if (endpoints.length === 0) return;

  await runWithBoundedConcurrency(
    endpoints,
    ENRICHMENT_CONCURRENCY,
    async (endpoint) => {
      await runEnrichmentAgent({ ...shared, endpoint });
    },
  );
}
