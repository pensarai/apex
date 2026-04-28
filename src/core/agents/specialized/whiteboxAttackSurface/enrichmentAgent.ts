import type { z } from "zod";
import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { CodeAgent } from "../codeAgent/agent";
import {
  AppInfoSchema,
  DiscoverySummarySchema,
  WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
  type DiscoverySummary,
} from "../../../workflows/whiteboxAttackSurface";
import type {
  ConsolidatedEndpoint,
  FrameworkId,
} from "../../../integrations/surface/types";
import type { ClassifiedEndpoint } from "../../../integrations/surface/classifier";
import type { AIModel, CacheMetrics } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { SessionInfo } from "../../../session";
import type { AgentEventBus } from "../../../eventBus";
import type { AttackSurfaceRegistry } from "../../../findings/attackSurfaceRegistry";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Apex-side `App` info — mirrors Phase 1's `AppInfoSchema`. */
export type AppInfo = z.infer<typeof AppInfoSchema>;

/**
 * A consolidated endpoint plus its page-vs-API classification — the unit
 * the enrichment agent reasons over. Structural fields are deterministic
 * (from surface); `classifiedMethod` carries the apex-shape method array
 * (e.g. `["PAGE"]` for renderable pages).
 */
export interface EnrichmentEndpoint extends ConsolidatedEndpoint {
  classifiedMethod: ClassifiedEndpoint["method"];
  isPage: boolean;
}

/**
 * Input for {@link runEnrichmentAgent}. Mirrors the per-task `CodeAgent`
 * spawn shape from `runWhiteboxAttackSurfaceWorkflow` Phase 2, specialized
 * for "endpoint list arrives pre-built; enrich rather than enumerate."
 */
export interface EnrichmentAgentInput {
  codebasePath: string;
  app: AppInfo;
  endpoints: EnrichmentEndpoint[];
  frameworks: FrameworkId[];
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

// ---------------------------------------------------------------------------
// Objective builder
// ---------------------------------------------------------------------------

interface BuildObjectiveOpts {
  app: AppInfo;
  codebasePath: string;
  endpoints: EnrichmentEndpoint[];
  frameworks: FrameworkId[];
}

/**
 * Build the per-app enrichment prompt described in design doc section 1.2:
 * deterministic endpoint list, per-endpoint `document_asset` asks, the
 * non-discovery directive, and existing-asset preservation (Phase 2.1).
 */
export function buildEnrichmentObjective(opts: BuildObjectiveOpts): string {
  const { app, codebasePath, endpoints, frameworks } = opts;

  const frameworkLabel =
    frameworks.length > 0 ? frameworks.join(", ") : "unknown";

  const endpointList = endpoints
    .map((ep, i) => {
      const method = ep.classifiedMethod.join(",");
      const auth = ep.auth.length > 0 ? ep.auth.join(", ") : "none";
      const authPrefill = ep.auth.length > 0;
      return `${i + 1}. **${method} ${ep.path}**
    - file: ${ep.file}:${ep.line}
    - handler: ${ep.handler}
    - auth signals: ${auth}
    - prefilled authRequired: ${authPrefill}`;
    })
    .join("\n\n");

  return `# Enrich Endpoints for ${app.name}

## Codebase
- **Repository root:** ${codebasePath}
- **App location:** ${app.location}
- **Framework(s):** ${frameworkLabel}

## Endpoints (deterministically extracted by surface)

${endpointList}

## Task

For each endpoint above, call \`document_asset\` exactly once with:
- **appName**: \`"${app.name}"\`
- **details**: \`{ url, method, file, line, handler, authRequired }\`
  - \`url\`: the route path (e.g. \`/api/users/:id\`)
  - \`method\`: the method array shown above (e.g. \`["GET","POST"]\`, or \`["PAGE"]\` for renderable pages)
  - \`file\`, \`line\`, \`handler\`: as listed above (do not change them)
  - \`authRequired\`: start from the prefilled value (\`true\` when auth signals are non-empty, \`false\` otherwise). Only override after reading the middleware chain at the indicated file when the signals are ambiguous.
- **description**: 1-2 sentences explaining what this endpoint does in plain English.
- **pentestObjectives**: 2-5 specific testing goals (e.g. "Test for IDOR by enumerating user IDs", "Test for SQL injection in the search parameter"). Use cross-endpoint context — shared auth model, ORM, middleware — when crafting them.
- **riskLevel**: one of \`CRITICAL\`, \`HIGH\`, \`MEDIUM\`, or \`LOW\`. CRITICAL for auth/payment/admin or unauthenticated state-changing routes; HIGH for authenticated user-data mutations; MEDIUM for general; LOW for static/public reads.

**Do NOT re-discover routes — the list above is complete.** Do not grep, list, or otherwise enumerate routes. Surface already enumerated them deterministically and any drift here defeats the determinism gain. You may read the handler files at the indicated lines to ground your description and objectives, but never to look for routes the list omits.

## Existing-asset preservation

If an \`asset_*.json\` already exists for the same \`(file, path)\`, the apex session has pre-populated the attack-surface registry with the prior \`description\` and \`pentestObjectives\` for that endpoint — \`document_asset\` will surface them. You MAY keep those existing values unchanged when the structural fields surface re-confirmed (file, path, handler, line) match what was previously documented. Re-write the description and objectives only when the file has changed in a way that affects the endpoint's behavior, or when the endpoint is new (no prior asset). Preserving prior annotations protects manual edits the operator may have made between runs.

When finished, call \`response\` with a summary of how many endpoints you documented.`;
}

// ---------------------------------------------------------------------------
// Agent runner
// ---------------------------------------------------------------------------

/**
 * Spawn a single per-app enrichment {@link CodeAgent} and consume its stream.
 * Mirrors the per-task spawn pattern from `runWhiteboxAttackSurfaceWorkflow`
 * Phase 2: `enrich-${app.name}` subagent id, `document_app` excluded (Phase 1
 * owns apps), same eventBus emit + try/catch shape. Concurrency is the
 * caller's responsibility (`runWithBoundedConcurrency`, `DEFAULT_CONCURRENCY = 5`).
 */
export async function runEnrichmentAgent(
  opts: EnrichmentAgentInput,
): Promise<void> {
  const {
    codebasePath,
    app,
    endpoints,
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

  const subagentId = `enrich-${app.name}`;

  eventBus?.emit("subagent-spawn", {
    subagentId,
    name: app.name,
    input: {
      app: app.name,
      type: "enrichment",
      endpointCount: endpoints.length,
    },
  });

  const objective = buildEnrichmentObjective({
    app,
    codebasePath,
    endpoints,
    frameworks,
  });

  const agent = new CodeAgent<DiscoverySummary>({
    codebasePath,
    objective,
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
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
    excludeTools: ["document_app"],
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
