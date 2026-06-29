import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import type { AIModel, CacheMetrics, OpenAIReasoningEffort } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { AgentEventBus } from "../../../eventBus";
import type { AttackSurfaceRegistry } from "../../../findings/attackSurfaceRegistry";
import type {
  ConsolidatedEndpoint,
  FrameworkId,
} from "../../../integrations/surface/types";
import { createLogger } from "../../../logger/structured";
import type { SessionInfo } from "../../../session";
import { scopedLogger } from "../../../util/lazyLogger";
import { runWithBoundedConcurrency } from "../../../utils/concurrency";
import { CodeAgent } from "../codeAgent/agent";
import { WHITEBOX_ENDPOINT_DOCUMENTATION_SYSTEM_PROMPT } from "./prompts";
import {
  type AppInfo,
  type DiscoverySummary,
  DiscoverySummarySchema,
} from "./types";

const log = scopedLogger(() => createLogger("endpoint-documentation-agent"));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Per-app fan-out concurrency — the maximum number of endpoint agents a single
 * app may *schedule* at once. The number that actually *run* concurrently is
 * additionally bounded across ALL apps by the workflow-level `agentLimiter`
 * (see {@link SharedAgentOptions.agentLimiter}); without that shared gate this
 * per-app cap multiplied by the app-level concurrency, so a repo with many apps
 * could run ~50 endpoint agents at once.
 */
const ENDPOINT_DOCUMENTATION_CONCURRENCY = 10;

/**
 * A shared concurrency gate (e.g. a `p-limit` instance). When provided, every
 * endpoint/discovery CodeAgent run is funneled through it so the TOTAL number of
 * concurrently-running agents across all apps stays bounded regardless of how
 * many apps/endpoints the repo has.
 */
export type AgentConcurrencyLimiter = <T>(fn: () => Promise<T>) => Promise<T>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  enableThinking?: boolean;
  projectThreatModel?: string;
  /** Parent subagent id for hierarchy tracking on emitted lifecycle events. */
  parentSubagentId?: string;
  /**
   * Optional shared gate bounding total concurrent agents across the whole
   * workflow. When omitted, agents run ungated (per-app cap only).
   */
  agentLimiter?: AgentConcurrencyLimiter;
}

interface EndpointDocumentationInput extends SharedAgentOptions {
  app: AppInfo;
  endpoint: ConsolidatedEndpoint;
  frameworks: FrameworkId[];
}

export interface AppEndpointDocumentationInput extends SharedAgentOptions {
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

function getDocumentMethod(endpoint: ConsolidatedEndpoint): string[] {
  return endpoint.kind === "page" ? ["PAGE"] : endpoint.method;
}

export function buildEndpointDocumentationObjective(opts: {
  app: AppInfo;
  codebasePath: string;
  endpoint: ConsolidatedEndpoint;
  frameworks: FrameworkId[];
}): string {
  const { app, codebasePath, endpoint, frameworks } = opts;

  const frameworkLabel =
    frameworks.length > 0 ? frameworks.join(", ") : "unknown";

  // Apex's downstream storage convention is method="PAGE" for renderable
  // pages. Surface emits the raw HTTP method (e.g. "GET") with kind="page";
  // we translate at this write boundary so the surface integration layer
  // stays a pure pass-through.
  const documentMethod = getDocumentMethod(endpoint);
  const methodDisplay = documentMethod.join(",");
  const methodValue = JSON.stringify(
    documentMethod.length === 1 ? documentMethod[0] : documentMethod,
  );
  const endpointType =
    endpoint.kind === "page" ? "web-endpoint" : "api-endpoint";

  const auth = endpoint.auth.length > 0 ? endpoint.auth.join(", ") : "none";
  const authPrefill = endpoint.auth.length > 0;

  return `# Document Endpoint: ${methodDisplay} ${endpoint.path}

## Codebase
- **Repository root:** ${codebasePath}
- **App:** ${app.name}
- **App location:** ${app.location}
- **Framework(s):** ${frameworkLabel}

## Endpoint (deterministically extracted by surface)

- **method**: ${methodDisplay}
- **routePath**: ${endpoint.path}
- **file**: ${endpoint.file}:${endpoint.line}
- **handler**: ${endpoint.handler}
- **endpointType**: ${endpointType}
- **auth signals**: ${auth}
- **prefilled authRequired**: ${authPrefill}

## Task

Document this **single endpoint** by calling \`document_endpoint\` exactly once. Use the deterministic fields above as-is for \`appName\` (\`"${app.name}"\`), \`routePath\`, \`method\` (\`${methodValue}\`), \`endpointType\` (\`"${endpointType}"\`), \`file\`, \`line\`, and \`handler\`. The remaining fields you must produce yourself:

- **authRequired**: start from the prefilled value above. Override only after reading the middleware chain at the indicated file when the signals are genuinely ambiguous.
- **description**: 1–2 sentences explaining what this endpoint does in plain English. Read the handler at \`${endpoint.file}:${endpoint.line}\` to ground it.
- **riskLevel**: \`CRITICAL\` for auth/payment/admin or unauthenticated state-changing routes; \`HIGH\` for authenticated user-data mutations; \`MEDIUM\` for general; \`LOW\` for static/public reads.

Do NOT pass \`pentestObjectives\` — \`document_endpoint\` generates them automatically.

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

async function runEndpointDocumentationAgent(
  opts: EndpointDocumentationInput,
): Promise<boolean> {
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
    openAIReasoningEffort,
    enableThinking,
    projectThreatModel,
    parentSubagentId,
    agentLimiter,
  } = opts;

  const subagentId = `endpoint-doc-${slug(app.name)}-${slug(endpoint.path)}`;
  const displayMethod = getDocumentMethod(endpoint);
  const displayName = `${app.name}: ${displayMethod.join(",")} ${endpoint.path}`;

  eventBus?.emit("subagent-spawn", {
    subagentId,
    name: displayName,
    input: {
      app: app.name,
      type: "endpointDocumentation",
      method: displayMethod,
      path: endpoint.path,
    },
    parentSubagentId,
  });

  const objective = buildEndpointDocumentationObjective({
    app,
    codebasePath,
    endpoint,
    frameworks,
  });

  const agent = new CodeAgent<DiscoverySummary>({
    codebasePath,
    objective,
    system: WHITEBOX_ENDPOINT_DOCUMENTATION_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    attackSurfaceRegistry,
    eventBus,
    subagentId,
    onStepFinish: (event) => onStepFinish?.(event),
    onCacheMetrics,
    openAIReasoningEffort,
    enableThinking,
    responseSchema: DiscoverySummarySchema,
    // Hard-exclude tools an endpoint documentation agent must never use:
    // - document_app: Phase 1 owns app discovery.
    // - list_files / grep: route enumeration is surface's job; without this,
    //   soft prompt guidance gets overridden by the model's discovery instinct
    //   and the agent orients-first, looking like a discovery pass.
    excludeTools: ["document_app", "list_files", "grep"],
    projectThreatModel,
  });

  try {
    await (agentLimiter
      ? agentLimiter(() => agent.consume())
      : agent.consume());
    eventBus?.emit("subagent-complete", {
      subagentId,
      status: "completed",
      parentSubagentId,
    });
    return true;
  } catch (error) {
    log.error(
      `"${subagentId}" FAILED`,
      error instanceof Error ? error : undefined,
      { error: String(error) },
    );
    eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
      parentSubagentId,
    });
    return false;
  }
}

// ---------------------------------------------------------------------------
// App-level fan-out
// ---------------------------------------------------------------------------

export async function runAppEndpointDocumentation(
  opts: AppEndpointDocumentationInput,
): Promise<void> {
  const { endpoints, ...shared } = opts;
  if (endpoints.length === 0) return;

  let anyFailed = false;
  await runWithBoundedConcurrency(
    endpoints,
    ENDPOINT_DOCUMENTATION_CONCURRENCY,
    async (endpoint) => {
      const ok = await runEndpointDocumentationAgent({ ...shared, endpoint });
      if (!ok) anyFailed = true;
    },
  );

  // Surface per-endpoint failure to the workflow so per-app status reflects
  // it. Each endpoint already emits its own subagent-complete (failed); this
  // throw lets the workflow's outer catch set appAnyTaskFailed, matching the
  // legacy spawnDiscoveryAgent path's failure propagation.
  if (anyFailed) {
    throw new Error(
      `One or more endpoint documentation agents failed for app ${opts.app.name}`,
    );
  }
}
