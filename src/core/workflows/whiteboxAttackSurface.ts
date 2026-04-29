import { z } from "zod";
import {
  writeFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  existsSync,
  statSync,
} from "fs";
import { join } from "path";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import {
  EndpointSchema,
  type WhiteboxAttackSurfaceResult,
  type Endpoint,
  type App,
} from "../agents/specialized/whiteboxAttackSurface/types";
import type { DocumentedEndpointRecord } from "../agents/specialized/attackSurface/schemas";
import type { AIModel, CacheMetrics } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { AgentEventBus } from "../eventBus";
import { runWithBoundedConcurrency } from "../utils/concurrency";
import { execFileSync } from "child_process";
import { createHash } from "crypto";
import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { mapAppWithSurface } from "../integrations/surface";
import { runAppEnrichment } from "../agents/specialized/whiteboxAttackSurface/enrichmentAgent";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CONCURRENCY = 5;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

// ---------------------------------------------------------------------------
// System prompt for whitebox workflow coding agents
// ---------------------------------------------------------------------------

/**
 * Apps-only system prompt for Phase 1 (apps discovery).
 *
 * This is intentionally a stripped variant of {@link WHITEBOX_CODE_AGENT_SYSTEM_PROMPT}
 * with all references to per-route/endpoint documentation removed. Phase 1's
 * job is to identify deployable applications and cloud resources; endpoint
 * enumeration is handled by Phase 2 (surface-driven enrichment or LLM
 * fallback). Mentioning the endpoint tool here causes the Phase 1 agent to
 * over-reach — it improvises by abusing `document_app` for individual routes
 * even when the `document_endpoint` tool is excluded from its registry.
 */
export const WHITEBOX_APPS_DISCOVERY_SYSTEM_PROMPT = `You are an expert source-code analyst with direct filesystem access. You will be given a specific objective — focus exclusively on completing it.

Your focus is on identifying **deployed applications and services** — APIs, web apps, microservices — that listen on a port and serve traffic, as well as **owned cloud resources** (S3 buckets, cloud storage, CDN origins, etc.) that are part of the attack surface. Ignore libraries, shared packages, SDKs, CLI tools, build scripts, and test suites unless they are part of a deployable service.

# Tool Usage Guide

## read_file
Read the contents of any file. You can read the whole file or a specific line range.
- When a file is large, read it in chunks using startLine / endLine to stay focused.
- Follow imports and references — when you see an interesting function call, read its source.

## list_files
List files and directories. Use this to orient yourself in the codebase.
- Start by listing the project root or relevant subdirectory to understand the structure.
- Use recursive=true sparingly on targeted subdirectories to avoid flooding context.

## grep
Search file contents by pattern. This is your most powerful navigation tool.
- Use it to find application entry points, server bootstraps, infrastructure-as-code resource definitions, and configuration files.
- Use -i for case-insensitive searches.
- Use --include="*.ext" to narrow to relevant file types.
- Use -C 3 or -C 5 to get context around matches.
- Use -rn (default for directories) for recursive search with line numbers.
- Use -l to get just file paths when you need a broad overview of where something appears.

## execute_command
Run shell commands when needed.
- Use for build tools, git operations, package managers, linters, etc.

## document_app
**This is your primary output tool.** Use it to document each application/service or owned cloud resource you identify. Persists a JSON record to the session's apps directory.

**CRITICAL — application documentation rules:**
- **One \`document_app\` call per deployable application or cloud resource.** Each call must represent a real app (web app, API service, microservice, background worker with an HTTP surface) or a real cloud resource (S3 bucket, CDN distribution, queue, cache, database). Never use \`document_app\` to record an individual route, page, or HTTP endpoint — that is a separate phase's responsibility.
- **Always set \`name\`** to the application or service name.
- **Always set \`type\`** to the correct enum value (web_application, api, full_stack, database, cloud_resource, storage, etc.).
- **Always set \`framework\`** to the web framework or cloud service.
- **Always set \`location\`** to the path relative to the repository root for code, or the resource identifier for cloud resources.

## response
When your objective includes structured output, call \`response\` with your final results once you are done. This ends your run.

# Working Approach
1. **Orient first** — list files and read key entry points to understand the structure.
2. **Ignore submodules** — check for a \`.gitmodules\` file or run \`git submodule status\`. Any directories that are git submodules are external dependencies and must be **completely excluded** from your analysis.
3. **Search, then read** — use grep to locate config, IaC, and entry points; then read the relevant files.
4. **Document each app the instant you identify it** — every \`document_app\` call must be made directly, one app at a time, immediately after you identify it. Never collect apps into a manifest, JSON file, or batch script. If you find yourself thinking "let me list all of these and then document them," stop — that pattern silently drops items when output tokens run out.
5. **Stay scoped** — your job ends at app discovery. Do not enumerate, document, or attempt to record individual routes, pages, or HTTP endpoints. A separate phase handles that after you finish.
6. **Be thorough on apps** — don't stop at the first one. Cover every deployable application, service, and owned cloud resource. Repetitive \`document_app\` calls (one per real app) are expected.
`;

/**
 * Enrichment-only system prompt for the per-app enrichment agent that runs
 * on the surface-driven path of Phase 2.
 *
 * The agent receives a complete, deterministic list of endpoints (extracted
 * by `@pensar/surface`) and its only job is to enrich each one with a
 * description, refined auth assessment, and risk level — then call
 * `document_endpoint` once per entry. It must NOT re-enumerate routes,
 * grep for new ones, or list directories looking for handlers.
 *
 * The shared {@link WHITEBOX_CODE_AGENT_SYSTEM_PROMPT} contains heavy
 * "orient first / list files / search-then-read / be thorough" framing that
 * an enrichment agent reads as discovery instructions, causing it to ignore
 * the deterministic list and start over from scratch. This variant strips
 * that framing.
 */
export const WHITEBOX_ENRICHMENT_SYSTEM_PROMPT = `You are an expert security analyst. Your job is to enrich a complete, deterministic list of endpoints that has already been extracted from the source code by a separate phase. You will be given the full list in your objective; do not re-enumerate routes.

# Tool Usage Guide

## read_file
Read the handler file at the indicated \`file:line\` for each endpoint when you need context to write its description, pentest framing, or refined auth assessment. Use \`startLine\` / \`endLine\` ranges — there is no need to read whole files.

## list_files
Generally NOT needed. Your endpoint list already includes the file path for every handler. Use this only for narrow, targeted disambiguation (e.g. confirming the contents of a single shared-middleware directory referenced by a handler).

## grep
Generally NOT needed. The endpoint list is final and complete. Use this only when an endpoint's auth signal is ambiguous and you must locate a middleware definition referenced from the handler. **Do NOT use \`grep\` to look for additional routes** — route discovery is a previous phase's job and your list will not be changed.

## execute_command
Run shell commands when needed (rare for enrichment).

## document_endpoint
**This is your primary output tool.** Call it exactly once per endpoint in your input list. Each call persists a JSON record to the session's assets directory.

**CRITICAL — endpoint enrichment rules:**
- **One \`document_endpoint\` call per entry in your input list.** The number of calls you make must equal the number of endpoints provided. Do not skip entries. Do not add new entries.
- **Use the structural fields from your input as-is:** \`routePath\`, \`method\`, \`file\`, \`line\`, \`handler\`. Don't "verify" them by re-discovering — they are deterministic.
- **Always set \`appName\`** to the application name provided in your objective.
- **Always set \`endpointType\`**: \`"web-endpoint"\` for renderable pages (\`method = "PAGE"\`), \`"api-endpoint"\` for HTTP APIs, \`"asset"\` for cloud-resource access patterns.
- **Always set \`description\`** to a 1-2 sentence summary of what this endpoint does in plain English.
- **Always set \`riskLevel\`** to \`CRITICAL\`, \`HIGH\`, \`MEDIUM\`, or \`LOW\`. CRITICAL for auth/payment/admin or unauthenticated state-changing routes; HIGH for authenticated user-data mutations; MEDIUM for general; LOW for static/public reads.
- **Set \`authRequired\`** — start from the prefilled value in your input (true when auth signals are non-empty, false otherwise). Override only after reading the middleware chain at the indicated file when the signals are genuinely ambiguous.
- Pentest objectives are generated automatically by \`document_endpoint\` — you do not pass them. Just provide the structural and descriptive fields above.

## response
When you have called \`document_endpoint\` for every endpoint in your input list, call \`response\` with a summary count.

# Working Approach
1. **Read your input list first.** The objective contains every endpoint with its file, line, handler, method, and prefilled auth signals already located. This is the entire scope of your work.
2. **Per endpoint, read just enough handler code** at the indicated \`file:line\` to write a meaningful description and assess risk. Don't read whole files — use line ranges.
3. **Document immediately.** Call \`document_endpoint\` directly per endpoint, the moment you have enough context. Do not collect entries in a buffer to "process later."
4. **Stay scoped.** Your job is enrichment, not discovery. Do not call \`list_files\` or \`grep\` to look for additional routes — the list is final.
`;

export const WHITEBOX_CODE_AGENT_SYSTEM_PROMPT = `You are an expert source-code analyst with direct filesystem access. You will be given a specific objective — focus exclusively on completing it.

Your focus is on **deployed applications and services** — APIs, web apps, microservices — that listen on a port and serve traffic, as well as **owned cloud resources** (S3 buckets, cloud storage, CDN origins, etc.) that are part of the attack surface. Ignore libraries, shared packages, SDKs, CLI tools, build scripts, and test suites unless they are part of a deployable service.

# Tool Usage Guide

## read_file
Read the contents of any file. You can read the whole file or a specific line range.
- When a file is large, read it in chunks using startLine / endLine to stay focused.
- Follow imports and references — when you see an interesting function call, read its source.

## list_files
List files and directories. Use this to orient yourself in the codebase.
- Start by listing the project root or relevant subdirectory to understand the structure.
- Use recursive=true sparingly on targeted subdirectories to avoid flooding context.

## grep
Search file contents by pattern. This is your most powerful navigation tool.
- Use it to find route definitions, middleware, controllers, endpoint registrations, etc.
- Use -i for case-insensitive searches.
- Use --include="*.ext" to narrow to relevant file types.
- Use -C 3 or -C 5 to get context around matches.
- Use -rn (default for directories) for recursive search with line numbers.
- Use -l to get just file paths when you need a broad overview of where something appears.

## execute_command
Run shell commands when needed.
- Use for build tools, git operations, package managers, linters, etc.

## document_app
Use this to document each application/service you identify. Persists a JSON record to the session's apps directory.

## document_endpoint
**This is your primary output tool for endpoints.** Use it to document every endpoint you discover. Each call persists a JSON record to the session's endpoints directory, organized by app.

**HARD RULE — call this tool DIRECTLY, one route at a time.** The moment you have enough information about a route to document it, your very next tool call must be \`document_endpoint\` for that route. Do not defer. Do not batch. Do not collect routes into a list to "process later."

**You MUST NOT, under any circumstances:**
- Build a manifest, JSON file, list, or array of routes to document later (e.g. \`cat > /tmp/pages.json << EOF [...] EOF\`).
- Write a shell, Python, or any other script whose purpose is to generate \`document_endpoint\` tool calls.
- Use a single message to "summarize all the routes I'll document" before documenting them.
- Stop documentation early because you "have enough" or it's "getting repetitive." If you discovered N routes, you must produce N \`document_endpoint\` calls.

These patterns silently truncate at output-token limits and routes get dropped. The only correct workflow is: discover a route → call \`document_endpoint\` for it → discover the next route → call \`document_endpoint\` for it → ... until every route is documented. Repetition is expected and required.

**CRITICAL — endpoint documentation rules:**
- **One entry per unique route path.** Do NOT create separate entries for different HTTP methods on the same path. If \`/api/users\` supports GET, POST, and DELETE, that is ONE entry with \`method: ["GET", "POST", "DELETE"]\`.
- **Use \`method: "PAGE"\`** for web pages and views (non-API routes).
- **Always set \`appName\`** to the application name provided in your objective.
- **Always set \`routePath\`** to the HTTP route this endpoint serves (e.g., \`/api/users/:id\`, \`/dashboard\`). This is the URL path a client requests — NOT a source-file path.
- **Always set \`file\`** to the source-code file where the route is defined (e.g., \`src/routes/users.ts\`). This is NOT the HTTP route.
- **Set \`line\`** to the line number when determinable.
- **Set \`handler\`** to the handler function or component name.
- **Set \`authRequired\`** to true/false based on middleware, guards, or decorators.


## response
When your objective includes structured output, call \`response\` with your final results once you are done. This ends your run.

# Working Approach
1. **Orient first** — list files and read key entry points to understand the structure.
2. **Ignore submodules** — check for a \`.gitmodules\` file or run \`git submodule status\`. Any directories that are git submodules are external dependencies and must be **completely excluded** from your analysis.
3. **Search, then read** — use grep to locate what you need, then read the relevant files.
4. **Document each item the instant you discover it** — every \`document_app\` / \`document_endpoint\` call must be made directly, one item per call, immediately after you identify it. Never collect items into a manifest, JSON file, or batch script. If you find yourself thinking "let me list all of these and then document them," stop — that pattern silently drops items when output tokens run out.
5. **Follow the trail** — trace through imports, function calls, and references to build full understanding.
6. **Be thorough** — don't stop at the first match. Cover everything relevant to the objective. Repetitive \`document_endpoint\` calls are expected; do not summarize, deduplicate, or shortcut them.
`;

// ---------------------------------------------------------------------------
// Intermediate schemas (structured output for each workflow step)
// ---------------------------------------------------------------------------

export const AppInfoSchema = z.object({
  name: z.string().describe("Application or service name"),
  framework: z
    .string()
    .describe(
      "Framework or cloud service (e.g. Express, Next.js, Django, FastAPI, Rails, AWS S3, CloudFront)",
    ),
  description: z.string().describe("Brief description of what this app does"),
  location: z
    .string()
    .describe(
      "Path to the app root relative to the repository root, or resource identifier for cloud resources",
    ),
  type: z
    .enum([
      "web_application",
      "api",
      "full_stack",
      "domain",
      "subdomain",
      "database",
      "cloud_resource",
      "storage",
    ])
    .default("web_application")
    .describe(
      "Application type — web_application for frontend apps, api for backend services, " +
        "full_stack for frameworks like Next.js/Remix that serve both, " +
        "database for databases, cloud_resource for owned cloud infra, storage for S3/GCS/blob storage",
    ),
});

const AppsDiscoveryResultSchema = z.object({
  repoType: z.string().describe("e.g. monorepo, single-app, multi-package"),
  packageManager: z
    .string()
    .describe("e.g. npm, yarn, pnpm, pip, cargo, go modules"),
  apps: z
    .array(AppInfoSchema)
    .describe("All applications/services discovered in the repository"),
});

type AppsDiscoveryResult = z.infer<typeof AppsDiscoveryResultSchema>;

export const DiscoverySummarySchema = z.object({
  endpointsDocumented: z
    .number()
    .describe("Number of endpoints documented via document_endpoint"),
  summary: z.string().describe("Brief summary of what was found"),
});

export type DiscoverySummary = z.infer<typeof DiscoverySummarySchema>;

// ---------------------------------------------------------------------------
// Input type
// ---------------------------------------------------------------------------

export interface WhiteboxAttackSurfaceWorkflowInput {
  codebasePath: string;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  attackSurfaceRegistry?: import("../findings/attackSurfaceRegistry").AttackSurfaceRegistry;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onCacheMetrics?: (metrics: CacheMetrics) => void;
  /** Known domains associated with the project — agents can map discovered apps to these. */
  domains?: string[];
  /** Project-level threat model content (e.g. from .pensar/threat_model.md), if found */
  projectThreatModel?: string;
  /** Deployment environment names (e.g. ["production", "staging"]) from project settings. */
  environments?: string[];
}

// ---------------------------------------------------------------------------
// Incremental input type
// ---------------------------------------------------------------------------

export interface IncrementalWhiteboxInput extends WhiteboxAttackSurfaceWorkflowInput {
  previousCommitSha: string;
  currentCommitSha: string;
  existingResult: WhiteboxAttackSurfaceResult;
}

// ---------------------------------------------------------------------------
// App metadata schema (written to app.json in each app folder)
// ---------------------------------------------------------------------------

interface AppMetadata {
  name: string;
  type: string;
  framework: string;
  description: string;
  location: string;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * Deterministic whitebox attack surface workflow.
 *
 * Phase 1: Spawn a single CodeAgent to identify all apps in the repo.
 * Phase 1.5: Create app folders with app.json metadata.
 * Phase 2: For each app, spawn two CodeAgents in parallel — one for
 *           pages, one for API endpoints — using document_endpoint.
 *           Threat models and risk scores are generated inline during
 *           this phase (inside document_endpoint).
 * Phase 3: Read the assets directory to build endpoint data.
 * Phase 4: Final assembly.
 */
export async function runWhiteboxAttackSurfaceWorkflow(
  input: WhiteboxAttackSurfaceWorkflowInput,
): Promise<WhiteboxAttackSurfaceResult> {
  const {
    codebasePath,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    attackSurfaceRegistry,
    onStepFinish,
    onCacheMetrics,
    domains,
    projectThreatModel,
    environments,
  } = input;

  // =========================================================================
  // Phase 1: Identify all apps in the repository
  // =========================================================================

  const appsAgent = new CodeAgent<AppsDiscoveryResult>({
    codebasePath,
    objective: buildAppsDiscoveryObjective(codebasePath, domains, environments),
    // Phase 1 uses an apps-only system prompt (no document_endpoint guidance)
    // paired with `excludeTools: ["document_endpoint"]`. The shared
    // WHITEBOX_CODE_AGENT_SYSTEM_PROMPT instructs every agent to call
    // document_endpoint per route — strong enough that Phase 1 would
    // improvise by abusing document_app for individual routes if the prompt
    // mentioned the tool at all. The variant below removes those mentions.
    system: WHITEBOX_APPS_DISCOVERY_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    attackSurfaceRegistry,
    eventBus,
    subagentId: "whitebox-apps-discovery",
    onStepFinish: (event) => onStepFinish?.(event),
    onCacheMetrics,
    responseSchema: AppsDiscoveryResultSchema,
    projectThreatModel,
    // Tool-level guard symmetric to Phase 2's `excludeTools: ["document_app"]`
    // (in spawnDiscoveryAgent + enrichmentAgent).
    excludeTools: ["document_endpoint"],
  });

  console.log(
    `[whitebox-workflow] Phase 1: discovering apps in ${codebasePath}${domains?.length ? ` (${domains.length} known domains)` : ""}`,
  );

  eventBus?.emit("subagent-spawn", {
    subagentId: "whitebox-apps-discovery",
    name: "Whitebox Apps Discovery",
    input: { codebasePath },
  });

  const appsResult = await appsAgent.consume();

  eventBus?.emit("subagent-complete", {
    subagentId: "whitebox-apps-discovery",
    status: "completed",
  });

  console.log(
    `[whitebox-workflow] Phase 1 complete: ${appsResult?.apps.length ?? 0} apps discovered` +
      (appsResult
        ? ` (repoType=${appsResult.repoType}, packageManager=${appsResult.packageManager})`
        : " (no result returned)"),
  );

  if (appsResult?.apps.length) {
    for (const app of appsResult.apps) {
      console.log(
        `[whitebox-workflow]   app: "${app.name}" type=${app.type} framework="${app.framework}" location="${app.location}"`,
      );
    }
  }

  if (!appsResult || appsResult.apps.length === 0) {
    return {
      repoType: appsResult?.repoType ?? "unknown",
      packageManager: appsResult?.packageManager ?? "unknown",
      apps: [],
      summary: {
        totalApps: 0,
        totalPages: 0,
        totalApiEndpoints: 0,
        totalPentestObjectives: 0,
      },
    };
  }

  // =========================================================================
  // Phase 1.5: Create app folders with app.json metadata
  // =========================================================================

  const assetsPath = join(session.rootPath, "assets");
  mkdirSync(assetsPath, { recursive: true });

  for (const app of appsResult.apps) {
    const appDir = join(assetsPath, sanitizeName(app.name));
    mkdirSync(appDir, { recursive: true });
    const metadata: AppMetadata = {
      name: app.name,
      type: app.type,
      framework: app.framework,
      description: app.description,
      location: app.location,
    };
    writeFileSync(
      join(appDir, "app.json"),
      JSON.stringify(metadata, null, 2),
      "utf-8",
    );
  }

  // =========================================================================
  // Phase 2: Per-app dispatch — surface-driven enrichment vs. fallback agents.
  //          Service apps try `mapAppWithSurface`; on `surface` mode run a
  //          per-endpoint enrichment CodeAgent against the deterministic list,
  //          on `fallback` run the legacy pages+apiEndpoints CodeAgent pair.
  //          Cloud resources always take the specialized objective — surface
  //          is HTTP-route-focused and doesn't enumerate cloud assets.
  // =========================================================================

  const NON_SERVICE_TYPES = ["cloud_resource", "storage", "database"];
  const serviceApps = appsResult.apps.filter(
    (app) => !NON_SERVICE_TYPES.includes(app.type),
  );
  const cloudApps = appsResult.apps.filter((app) =>
    NON_SERVICE_TYPES.includes(app.type),
  );

  console.log(
    `[whitebox-workflow] Phase 2: ${serviceApps.length} service apps (surface or fallback per app), ${cloudApps.length} cloud resources → ${appsResult.apps.length} total apps`,
  );

  const totalApps = appsResult.apps.length;
  let completedAppCount = 0;

  eventBus?.emit("app-analysis-progress", {
    totalApps,
    completedApps: 0,
  });

  type AppInfo = z.infer<typeof AppInfoSchema>;

  const spawnDiscoveryAgent = async (
    app: AppInfo,
    type: "pages" | "apiEndpoints" | "cloudResourceEndpoints",
    objective: string,
  ): Promise<void> => {
    const subagentId = `${type}-${app.name}`;

    console.log(
      `[whitebox-workflow] Phase 2: spawning agent "${subagentId}" (app="${app.name}", type=${type}, appType=${app.type})`,
    );

    eventBus?.emit("subagent-spawn", {
      subagentId,
      name: app.name,
      input: { app: app.name, type },
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

      console.log(
        `[whitebox-workflow] Phase 2: agent "${subagentId}" completed`,
      );

      eventBus?.emit("subagent-complete", {
        subagentId,
        status: "completed",
      });
    } catch (error) {
      console.error(
        `[whitebox-workflow] Phase 2: agent "${subagentId}" FAILED:`,
        error instanceof Error ? error.message : String(error),
      );

      eventBus?.emit("subagent-complete", {
        subagentId,
        status: "failed",
      });
    }
  };

  const spawnPagesAgent = (app: AppInfo): Promise<void> =>
    spawnDiscoveryAgent(
      app,
      "pages",
      buildPagesDiscoveryObjective(codebasePath, app),
    );

  const spawnApiEndpointsAgent = (app: AppInfo): Promise<void> =>
    spawnDiscoveryAgent(
      app,
      "apiEndpoints",
      buildApiEndpointsDiscoveryObjective(codebasePath, app),
    );

  const spawnCloudResourceAgent = (app: AppInfo): Promise<void> =>
    spawnDiscoveryAgent(
      app,
      "cloudResourceEndpoints",
      buildCloudResourceEndpointsObjective(codebasePath, app, environments),
    );

  await runWithBoundedConcurrency(
    appsResult.apps,
    DEFAULT_CONCURRENCY,
    async (app) => {
      try {
        if (NON_SERVICE_TYPES.includes(app.type)) {
          // Cloud resources: surface doesn't enumerate these — always fallback.
          await spawnCloudResourceAgent(app);
        } else {
          const surfaceResult = await mapAppWithSurface(
            join(codebasePath, app.location),
            codebasePath,
          );
          if (surfaceResult.mode === "surface") {
            console.log(
              `[whitebox] ${app.name}: surface-driven (${surfaceResult.endpoints.length} endpoints, frameworks=${surfaceResult.frameworks.join(",")})`,
            );

            await runAppEnrichment({
              codebasePath,
              app,
              endpoints: surfaceResult.endpoints,
              frameworks: surfaceResult.frameworks,
              model,
              session,
              authConfig,
              abortSignal,
              eventBus,
              attackSurfaceRegistry,
              onStepFinish,
              onCacheMetrics,
              projectThreatModel,
            });
          } else {
            console.log(
              `[whitebox] ${app.name}: fallback (${surfaceResult.reason})`,
            );
            await Promise.all([
              spawnPagesAgent(app),
              spawnApiEndpointsAgent(app),
            ]);
          }
        }
      } finally {
        completedAppCount++;
        eventBus?.emit("app-analysis-progress", {
          totalApps,
          completedApps: completedAppCount,
          appName: app.name,
        });
      }
    },
  );

  // =========================================================================
  // Phase 3: Read assets directory to build endpoint data
  // =========================================================================

  console.log(`[whitebox-workflow] Phase 3: reading assets from ${assetsPath}`);

  const {
    apps: parsedApps,
    repoType,
    packageManager,
  } = readAppsFromAssetsDirectory(assetsPath, appsResult);

  for (const app of parsedApps) {
    console.log(
      `[whitebox-workflow] Phase 3: "${app.name}" → ${app.pages.length} pages, ${app.apiEndpoints.length} API endpoints`,
    );
  }

  // =========================================================================
  // Phase 4: Final assembly (risk scores are already attached inline
  //          by document_endpoint during Phase 2)
  // =========================================================================

  const apps: App[] = parsedApps;

  const totalPages = apps.reduce((sum, a) => sum + a.pages.length, 0);
  const totalApiEndpoints = apps.reduce(
    (sum, a) => sum + a.apiEndpoints.length,
    0,
  );
  const totalPentestObjectives = apps.reduce(
    (sum, a) =>
      sum +
      [...a.pages, ...a.apiEndpoints].reduce(
        (s, ep) => s + ep.pentestObjectives.length,
        0,
      ),
    0,
  );

  return {
    repoType,
    packageManager,
    apps,
    summary: {
      totalApps: apps.length,
      totalPages,
      totalApiEndpoints,
      totalPentestObjectives,
    },
  };
}

// ---------------------------------------------------------------------------
// Assets directory reader
// ---------------------------------------------------------------------------

/**
 * Read app folders and their asset files from the assets directory.
 *
 * Expected structure:
 *   assets/
 *     <app-name>/
 *       app.json          — app metadata (name, framework, description, location)
 *       asset_*.json      — endpoint assets written by document_endpoint
 *
 * Each asset file is a {@link DocumentedEndpointRecord}. Endpoints are classified
 * as pages (method contains "PAGE") or API endpoints (everything else).
 */
function readAppsFromAssetsDirectory(
  assetsPath: string,
  appsDiscovery?: AppsDiscoveryResult,
): {
  apps: App[];
  repoType: string;
  packageManager: string;
} {
  const repoType = appsDiscovery?.repoType ?? "unknown";
  const packageManager = appsDiscovery?.packageManager ?? "unknown";

  if (!existsSync(assetsPath)) {
    console.log(`[readAssets] Assets directory does not exist: ${assetsPath}`);
    return { apps: [], repoType, packageManager };
  }

  const entries = readdirSync(assetsPath);
  console.log(
    `[readAssets] Found ${entries.length} entries in ${assetsPath}: [${entries.join(", ")}]`,
  );
  const apps: App[] = [];

  for (const entry of entries) {
    const entryPath = join(assetsPath, entry);
    if (!statSync(entryPath).isDirectory()) {
      console.log(`[readAssets] Skipping non-directory: ${entry}`);
      continue;
    }

    const appJsonPath = join(entryPath, "app.json");
    let metadata: AppMetadata;

    if (existsSync(appJsonPath)) {
      try {
        metadata = JSON.parse(
          readFileSync(appJsonPath, "utf-8"),
        ) as AppMetadata;
      } catch {
        console.warn(
          `[readAssets] Skipping app folder with unreadable app.json: ${entry}`,
        );
        continue;
      }
    } else {
      console.log(`[readAssets] Skipping folder without app.json: ${entry}`);
      continue;
    }

    const pages: Endpoint[] = [];
    const apiEndpoints: Endpoint[] = [];

    const assetFiles = readdirSync(entryPath).filter(
      (f) => f.endsWith(".json") && f !== "app.json",
    );

    console.log(
      `[readAssets] App "${metadata.name}" (${entry}): ${assetFiles.length} asset files`,
    );

    let parseFailed = 0;
    for (const file of assetFiles) {
      try {
        const raw = readFileSync(join(entryPath, file), "utf-8");
        const data = JSON.parse(raw) as DocumentedEndpointRecord;

        const endpoint = assetRecordToEndpoint(data);
        if (!endpoint) {
          console.log(
            `[readAssets]   ${file}: failed schema validation (assetRecordToEndpoint returned null)`,
          );
          parseFailed++;
          continue;
        }

        if (isPageEndpoint(data)) {
          pages.push(endpoint);
        } else {
          apiEndpoints.push(endpoint);
        }
      } catch {
        console.warn(
          `[readAssets] Skipping unreadable asset file: ${entry}/${file}`,
        );
        parseFailed++;
      }
    }

    console.log(
      `[readAssets] App "${metadata.name}": ${pages.length} pages, ${apiEndpoints.length} API endpoints, ${parseFailed} failed`,
    );

    apps.push({
      name: metadata.name,
      type: (metadata.type as App["type"]) ?? "web_application",
      framework: metadata.framework,
      description: metadata.description,
      location: metadata.location,
      pages,
      apiEndpoints,
    });
  }

  return { apps, repoType, packageManager };
}

/**
 * Convert a {@link DocumentedEndpointRecord} (from document_endpoint) to an
 * {@link Endpoint} (for the whitebox result schema).
 */
function assetRecordToEndpoint(
  record: DocumentedEndpointRecord,
): Endpoint | null {
  const rawMethod = record.method;
  const method = Array.isArray(rawMethod)
    ? rawMethod.join(", ")
    : (rawMethod ?? "UNKNOWN");

  const path = record.routePath;
  const file = record.file ?? "";

  const parsed = EndpointSchema.safeParse({
    method,
    path,
    handler: record.handler,
    file,
    line: record.line,
    authRequired: record.authRequired,
    description: record.description,
    pentestObjectives: record.pentestObjectives ?? [],
    riskScore: record.riskScore,
    threatModel: record.threatModel,
  });

  return parsed.success ? parsed.data : null;
}

/**
 * Determine whether a documented endpoint record represents a web page
 * (as opposed to an API endpoint).
 */
function isPageEndpoint(record: DocumentedEndpointRecord): boolean {
  const method = record.method;
  if (typeof method === "string") {
    return method.toUpperCase() === "PAGE";
  }
  if (Array.isArray(method)) {
    return method.length === 1 && method[0].toUpperCase() === "PAGE";
  }
  return false;
}

// ---------------------------------------------------------------------------
// Objective builders
// ---------------------------------------------------------------------------

function buildAppsDiscoveryObjective(
  codebasePath: string,
  domains?: string[],
  environments?: string[],
): string {
  const domainSection = domains?.length
    ? `\n## Known Domains\nThe following domains are associated with this project. When you document an application, set the \`domain\` field on \`document_app\` if you can determine which domain the app is served from:\n${domains.map((d) => `- ${d}`).join("\n")}\n`
    : "";

  const environmentsSection = environments?.length
    ? `\n## Target Environments\nThis project is deployed to the following environments:\n${environments.map((e) => `- **${e}**`).join("\n")}\n
**Per-environment app creation:** When infrastructure-as-code or configuration defines resources that are dynamically named per environment (e.g. environment-prefixed S3 buckets, stage-scoped databases, per-environment API endpoints), you MUST create a **separate app entry for each environment**. Use the environment name as a prefix in the app name (e.g. \`${environments[0]}-user-uploads-bucket\`, \`${environments.length > 1 ? environments[1] : "staging"}-api-gateway\`).

**How to identify environment-scoped resources:**
- IaC that interpolates a stage/environment variable into resource names (e.g. \`\${stage}-my-bucket\`, \`\${env}-api\`, \`$app.$stage.example.com\`)
- Separate config blocks, Terraform workspaces, SST stages, or CDK stacks per environment
- Environment variables or config files that change resource identifiers per stage

**For each environment** (${environments.join(", ")}), create an app entry with:
- **name**: \`<environment>-<resource-name>\` (e.g. \`${environments[0]}-data-bucket\`)
- **domain**: Substitute the environment name into the IaC naming pattern to derive the environment-specific URL (e.g. IaC has \`\${stage}-data\` → \`https://${environments[0]}-data.s3.amazonaws.com\`). Omit if no naming pattern exists in the code.

**Shared resources:** If a resource is clearly shared across all environments (e.g. a single CDN distribution, a shared auth service), document it once without an environment prefix.\n`
    : "";

  return `# Identify All Applications in the Repository

## Codebase
- **Path:** ${codebasePath}
${domainSection}${environmentsSection}
## Task
Analyze the repository structure and identify every **deployed application or service** (APIs, web apps, microservices) defined within it. Also discover **cloud resources and external services** referenced in the code that are owned by the target (e.g. S3 buckets, cloud storage, CDN origins, message queues).

**IMPORTANT: Only include deployable apps, services, and owned cloud resources.** Exclude:
- Libraries, SDKs, and shared packages that are consumed by other code but not deployed on their own
- Git submodules (external dependencies)
- Build tools, scripts, CLI utilities, and dev tooling
- Test suites, fixtures, and test helpers
- Documentation packages
- Third-party SaaS services not owned by the target (e.g. Stripe, auth providers)
- **Individual API routes, web pages, or HTTP endpoints.** Endpoint enumeration is handled by a separate phase that runs after this one. Even if you discover route files (\`page.tsx\`, \`route.ts\`, controller methods) while navigating the codebase, do NOT call \`document_app\` for them. Each \`document_app\` call must represent a deployable application or cloud resource, never a single endpoint. The \`document_endpoint\` tool is intentionally not available to you.

An app/service qualifies if it **listens on a port, serves HTTP traffic, or runs as a deployed process** (e.g. an Express server, a Next.js app, a Django project, a FastAPI service, a background worker with an API).

A **cloud resource** qualifies if it is an **owned infrastructure resource** referenced in the code — S3 buckets, GCS buckets, Azure Blob Storage, CloudFront distributions, Redis/ElastiCache instances, SQS queues, etc. These are part of the attack surface because they may have misconfigured permissions, public access, or sensitive data.

### Steps
1. List the root directory and read top-level config files (package.json, requirements.txt, Cargo.toml, go.mod, etc.)
2. **Check for git submodules** — run \`git submodule status\` or check for a \`.gitmodules\` file. Exclude all submodule directories.
3. Determine the **repo type**: monorepo (workspaces), single-app, multi-package, etc.
4. Determine the **package manager**: npm, yarn, pnpm, pip, cargo, go modules, etc.
5. Identify all **deployable** applications/services (ignoring submodules, libraries, and shared packages):
   - For monorepos: look at workspace packages that have their own server entry point, Dockerfile, or deploy config — skip packages that are libraries/utilities consumed by other packages
   - For multi-service repos: look at separate service directories with their own server startup
   - For single apps: the root is the app
6. **Discover cloud resources** referenced in the codebase:
   - Search for S3 bucket references (\`s3://\`, \`new S3Client\`, \`boto3.client('s3')\`, bucket name strings in config)
   - Search for cloud storage URLs (e.g. \`*.s3.amazonaws.com\`, \`storage.googleapis.com\`)
   - Search for CDN/distribution configs (CloudFront, Cloudflare, etc.)
   - Search for message queue references (SQS, SNS, RabbitMQ, etc.)
   - Search for cache/database endpoints (ElastiCache, Redis, DynamoDB, etc.)
   - Check infrastructure-as-code files (Terraform, CloudFormation, CDK, Pulumi, SST, serverless.yml)
   - Document each cloud resource as an app with \`appType: "cloud_resource"\` or \`appType: "storage"\`
7. For each app/resource, determine:
   - **name**: the application or service name
   - **framework**: the web framework or cloud service (e.g. "AWS S3", "CloudFront", "Express")
   - **description**: brief summary of what it does
   - **location**: path relative to the repository root (for code) or the resource identifier (for cloud resources)
   - **type**: classify as \`"web_application"\` for frontend-only apps, \`"api"\` for backend API services, \`"full_stack"\` for frameworks serving both UI and API (Next.js, Remix, Nuxt, SvelteKit, Django with templates, Rails), \`"database"\` for databases, \`"cloud_resource"\` for owned cloud infra (SQS, CDN, etc.), \`"storage"\` for S3/GCS/blob storage.

### Setting the \`domain\` field on \`document_app\` — CRITICAL

**Only set \`domain\` when you can deterministically derive it from evidence** — Known Domains list, IaC resource definitions, configuration files, environment variables, or route definitions. Substituting a known environment/stage name into an IaC naming pattern IS deterministic (e.g. IaC defines \`\${stage}-bucket\` and the target environments include "production" → \`https://production-bucket.s3.amazonaws.com\` is valid). However, do NOT invent domains with no supporting evidence — if no domain can be derived from the source, **omit the \`domain\` field entirely**. A missing domain is far better than a hallucinated one.

When you CAN determine the domain, each resource must have its OWN unique, resource-specific domain. Never reuse a generic domain or another application's domain.

**For web apps and API services:** Use the public-facing URL from the Known Domains list, route configuration, or infrastructure definition (e.g., \`https://console.pensar.dev\`, \`https://api.example.com\`).

**For S3 / GCS / blob storage buckets:** Derive the **actual bucket name** from the infrastructure-as-code. The bucket name is defined in the IaC resource definition (e.g., SST \`new sst.aws.Bucket("ProjectData")\` produces a bucket with a name like \`console-staging-projectdata-abc123\`). Set domain to \`https://{actual-bucket-name}.s3.amazonaws.com\`. If the IaC uses a stage/environment variable in the name, substitute the known environment name (e.g. \`\${stage}-projectdata\` with environment "production" → \`https://production-projectdata.s3.amazonaws.com\`). **NEVER use \`https://s3.amazonaws.com\`** — that is the S3 service, not a bucket. If you cannot determine the bucket name at all, omit the domain.

**For databases (RDS, Aurora, DynamoDB):** Use the cluster/instance endpoint from IaC. If the exact endpoint isn't determinable, omit the domain.

**For Redis / ElastiCache:** Use the cache cluster endpoint if determinable, otherwise omit.

**For SQS queues:** Use \`https://sqs.{region}.amazonaws.com/{account}/{queue-name}\` if determinable, otherwise omit.

**For Lambda functions:** Use the Lambda Function URL or the API Gateway route — NOT a generic API domain shared by all functions. If no concrete URL is determinable, omit.

**For CloudFront / CDN:** Use the distribution domain or custom domain alias if determinable, otherwise omit.

**For WebSocket APIs:** Use the WebSocket endpoint URL if determinable, otherwise omit.

When finished, call the \`response\` tool with your structured findings. Do not call \`document_app\` for individual routes, pages, or endpoints — that is a separate phase's responsibility.`;
}

function buildPagesDiscoveryObjective(
  codebasePath: string,
  appInfo: z.infer<typeof AppInfoSchema>,
): string {
  return `# Find All Web Pages in ${appInfo.name}

## Codebase
- **Repository root:** ${codebasePath}
- **App location:** ${appInfo.location}
- **Framework:** ${appInfo.framework}

## Scope — CRITICAL
**Only document pages/views that are DEFINED within this application (\`${appInfo.location}\`).** A page belongs to this app if its route definition or component file lives inside \`${appInfo.location}\`.

Do NOT document:
- Routes defined in other applications or packages (even if this app imports/calls them)
- External URLs or cloud resource endpoints that this app links to or fetches from
- API endpoints (those are handled separately)

## Task
Find ALL web pages, views, and routes that render HTML or serve client-side UI **defined in this application's source code**.

### What to look for (by framework)
- **React/Next.js**: pages/ or app/ directory, route components, layout files
- **Express**: res.render(), res.sendFile(), static file serving, template routes
- **Django**: urls.py patterns pointing to template views, class-based views with template_name
- **Rails**: routes.rb entries pointing to controller actions that render views
- **Vue/Nuxt**: pages/ directory, router definitions
- **FastAPI**: routes returning HTMLResponse, Jinja2 template responses
- **Spring**: @Controller methods returning view names, Thymeleaf templates

### How to document each page
For each page, call \`document_endpoint\` with:
- **appName**: \`${appInfo.name}\`
- **endpointType**: \`"web-endpoint"\`
- **description**: Brief description of what this page shows
- **routePath**: The HTTP route this page serves (e.g., \`/dashboard\`). This is the URL path a client requests — it is the endpoint's identity. NOT a file path.
- **method**: \`"PAGE"\`
- **file**: Source-code file where this page is defined (e.g., \`src/pages/dashboard.tsx\`). Must be inside \`${appInfo.location}\`. This is NOT the route.
- **line**: Line number (if determinable)
- **handler**: Component or handler name
- **authRequired**: Whether the page requires authentication
- **riskLevel**: CRITICAL for admin/auth pages, HIGH for user data, MEDIUM for general, LOW for static/public

### Required workflow — NO MANIFESTS, NO BATCHING
**You MUST call \`document_endpoint\` directly, one page at a time, the moment you identify a route.** It is a hard error to:
- Build a JSON file, array, or list of pages-to-document and then "process" it (e.g. \`cat > /tmp/pages.json << EOF [...] EOF\`).
- Write a Python or shell script that emits \`document_endpoint\` calls.
- Defer documentation until "the end" or until "you have the full picture."
- Stop early because the calls feel repetitive or because you've documented "the important ones."

These patterns hit per-message output-token limits and silently drop pages — usually the alphabetically-later ones. The only correct loop is: identify route → call \`document_endpoint\` → identify next route → call \`document_endpoint\` → ...

You may use \`list_files\`, \`grep\`, or \`execute_command\` (e.g. \`find ... -name page.tsx\`) to **enumerate** the routes that exist. That enumeration step is fine and encouraged. What is not allowed is using a script to **emit the documentation calls themselves** — those must come directly from you, one tool call per route.

Be thorough — examine every route file, every page directory, every template **within \`${appInfo.location}\`**. Every page surfaced by your enumeration must result in its own \`document_endpoint\` call. Repetitive calls are expected; do not summarize, deduplicate to "interesting" routes, or skip any.

When finished, call \`response\` with a summary of how many pages you documented. The reported count must equal the number of successful \`document_endpoint\` calls you made.`;
}

function buildApiEndpointsDiscoveryObjective(
  codebasePath: string,
  appInfo: z.infer<typeof AppInfoSchema>,
): string {
  return `# Find All API Endpoints in ${appInfo.name}

## Codebase
- **Repository root:** ${codebasePath}
- **App location:** ${appInfo.location}
- **Framework:** ${appInfo.framework}

## Scope — CRITICAL
**Only document API routes that are DEFINED within this application (\`${appInfo.location}\`).** An endpoint belongs to this app if its route handler or route definition file lives inside \`${appInfo.location}\`.

Do NOT document:
- Routes defined in other applications or packages
- External API calls this app makes to third-party services or other internal services
- S3 bucket URLs, cloud resource endpoints, or CDN URLs that this app interacts with — those belong to the cloud resource, not this API
- Web pages/views (those are handled separately)

## Task
Find ALL API endpoints **whose route definitions live in this application's source code**.

### What to look for (by framework)
- **Express**: app.get(), app.post(), router.get(), router.post(), router.put(), router.delete(), etc.
- **Next.js**: app/api/ or pages/api/ route handlers (GET, POST, PUT, DELETE exports)
- **Django**: urls.py patterns pointing to API views, DRF viewsets, routers, @api_view decorators
- **FastAPI**: @app.get(), @app.post(), @app.put(), @app.delete() decorators
- **Rails**: routes.rb API namespaces, resources, controller actions
- **Spring**: @GetMapping, @PostMapping, @PutMapping, @DeleteMapping, @RequestMapping
- **Go**: http.HandleFunc, mux.Handle, gin router methods

### How to document each endpoint
For each **unique route path**, call \`document_endpoint\` with:
- **appName**: \`${appInfo.name}\`
- **endpointType**: \`"api-endpoint"\`
- **description**: Brief description of what this endpoint does across all its methods
- **routePath**: The HTTP route (e.g., \`/api/users\`, \`/api/orders/:id\`). This is the URL path a client requests — it is the endpoint's identity. NOT a source-file path.
- **method**: Array of ALL HTTP methods this path supports (e.g., \`["GET", "POST"]\`). **Do NOT create separate entries for each method — consolidate them.**
- **file**: Source-code file where the endpoint is defined (e.g., \`src/routes/users.ts\`). Must be inside \`${appInfo.location}\`. This is NOT the route.
- **line**: Line number (if determinable)
- **handler**: Handler function name (comma-separate if multiple handlers for different methods)
- **authRequired**: Whether the endpoint requires authentication (true if ANY method requires it)
- **riskLevel**: CRITICAL for auth/payment/admin, HIGH for user data mutations, MEDIUM for general, LOW for read-only public

**CRITICAL: ONE entry per route path.** If \`/api/products\` has GET (list) and POST (create), document it as ONE entry with \`method: ["GET", "POST"]\`. Do NOT create two separate entries.

**IMPORTANT — Method consolidation for document_endpoint:** When using the \`document_endpoint\` tool, do NOT create separate entries for different HTTP methods on the same route path. For example, if \`/api/users\` supports GET, POST, and DELETE, document it as ONE entry with \`method: ["GET", "POST", "DELETE"]\` and include pentest objectives covering all methods.

### Required workflow — NO MANIFESTS, NO BATCHING
**You MUST call \`document_endpoint\` directly, one route at a time, the moment you identify it.** It is a hard error to:
- Build a JSON file, array, or list of endpoints-to-document and then "process" it (e.g. \`cat > /tmp/endpoints.json << EOF [...] EOF\`).
- Write a Python or shell script that emits \`document_endpoint\` calls.
- Defer documentation until you've "mapped everything out."
- Stop early because the calls feel repetitive or because you've covered "the important ones."

These patterns hit per-message output-token limits and silently drop endpoints — usually the alphabetically-later ones. The only correct loop is: identify route → call \`document_endpoint\` → identify next route → call \`document_endpoint\` → ...

You may use \`list_files\`, \`grep\`, or \`execute_command\` to **enumerate** routes (e.g. extracting all route registrations into a list to read). That enumeration step is fine. What is not allowed is using a script to **emit the documentation calls themselves** — those must come directly from you, one tool call per unique route path.

Be thorough — trace through all route registrations, middleware chains, and controller files **within \`${appInfo.location}\`**. Every unique route path your enumeration surfaces must result in its own \`document_endpoint\` call.

When finished, call \`response\` with a summary of how many endpoints you documented. The reported count must equal the number of successful \`document_endpoint\` calls you made.`;
}

function buildCloudResourceEndpointsObjective(
  codebasePath: string,
  appInfo: z.infer<typeof AppInfoSchema>,
  environments?: string[],
): string {
  const envNote = environments?.length
    ? `\n## Target Environments\nThis resource may exist in the following environments: ${environments.join(", ")}. When documenting entry points, use the **environment-specific resource identifiers** (e.g. environment-prefixed bucket names, stage-scoped queue URLs, per-environment ARNs). If the app name already includes an environment prefix, use that environment's resource names in the endpoints.\n`
    : "";

  return `# Document Entry Points for Cloud Resource: ${appInfo.name}

## Codebase
- **Repository root:** ${codebasePath}
- **Resource location:** ${appInfo.location}
- **Service:** ${appInfo.framework}
${envNote}
## Context — Application Domain
The parent application for this cloud resource already has a domain/URL associated with it (set via \`document_app\`). **Do NOT create endpoints that simply repeat the base domain URL.** The domain is already stored on the application record — endpoints should document **distinct access patterns** that go beyond the base domain.

## Scope — CRITICAL
You are documenting the **distinct access patterns and resource identifiers** for this cloud resource — specific ways the resource can be accessed that are NOT just its base domain URL.

Do NOT document:
- The base domain URL of the resource (e.g. \`https://bucket-name.s3.amazonaws.com\`) — this is already the application's domain
- Code locations where the app calls/uses this resource (e.g. "line 42 of api.ts calls S3.putObject" is NOT an endpoint)
- API routes from other apps that happen to interact with this resource
- Internal SDK calls or client instantiations

DO document:
- **Specific access patterns** beyond the base domain (e.g. pre-signed URL patterns, static website hosting paths, object key patterns)
- **Resource ARNs** that represent programmatic access points (e.g. \`arn:aws:s3:::bucket-name\`, \`arn:aws:sqs:region:account:queue-name\`)
- **Alternative access URLs** (e.g. CDN distribution URL, static website hosting URL, regional endpoint variants)
- **Queue/topic URLs** for message-based resources

## Task
Find the **distinct access patterns and resource identifiers** for this cloud resource by reading infrastructure-as-code and configuration.

### Where to find entry point information
1. **Infrastructure-as-code** — Terraform (*.tf), CloudFormation (*.yaml/*.json), CDK constructs, SST components (sst.config.ts, infra/), Pulumi, serverless.yml — these define the resource and its access configuration
2. **Configuration files** — .env files, config modules, environment variable definitions that contain resource URLs
3. **Resource policies** — bucket policies, CORS configs, access control settings that reveal how the resource is exposed

### What qualifies as an entry point (by resource type)
- **S3 / GCS / Blob Storage**: Pre-signed URL patterns (e.g. \`/{objectKey}?X-Amz-Signature={sig}\`), static website hosting URL, ARN. Do NOT include the plain bucket HTTPS endpoint — that's the app domain.
- **CloudFront / CDN**: Custom domain aliases, origin access patterns
- **SQS / SNS / Message Queues**: Queue URL, topic ARN
- **Lambda / Cloud Functions**: Function URL, API Gateway integration URL
- **DynamoDB / ElastiCache / Redis**: Connection endpoint URL, ARN

### How to document each entry point
For each entry point, call \`document_endpoint\` with:
- **appName**: \`${appInfo.name}\`
- **endpointType**: \`"asset"\`
- **description**: What this entry point exposes (e.g., "Pre-signed HTTP URLs for temporary read access to objects", "AWS resource ARN for programmatic access through IAM policies")
- **routePath**: The specific access pattern, path template, or ARN — this is the endpoint's identity. NOT the base domain URL. Examples: \`/{objectKey}?X-Amz-Signature={signature}&X-Amz-Credential={credential}\`, \`arn:aws:s3:::bucket-name\`, \`https://sqs.region.amazonaws.com/account/queue-name\`
- **method**: Access methods on the resource (e.g., \`["GET", "PUT"]\` for S3, \`["SendMessage", "ReceiveMessage"]\` for SQS, \`["READ", "WRITE"]\` for generic)
- **file**: Infrastructure or config file where this resource is defined (e.g., \`infra/storage.ts\`). NOT application code that calls it.
- **line**: Line number if determinable
- **authRequired**: Whether external access requires authentication
- **riskLevel**: CRITICAL for publicly accessible storage with write access or sensitive data, HIGH for resources with broad IAM permissions, MEDIUM for internal resources, LOW for read-only public assets

### Required workflow — NO MANIFESTS, NO BATCHING
**You MUST call \`document_endpoint\` directly, one entry point at a time, the moment you identify it.** Do not build a JSON file or list of entry points to "process later," and do not write a script that emits \`document_endpoint\` calls. Those patterns hit per-message output-token limits and silently drop entries. The only correct loop is: identify entry point → call \`document_endpoint\` → identify next → call \`document_endpoint\` → ...

When finished, call \`response\` with a summary of how many entry points you documented. The reported count must equal the number of successful \`document_endpoint\` calls you made.`;
}

// ---------------------------------------------------------------------------
// Incremental whitebox attack surface workflow
// ---------------------------------------------------------------------------

/**
 * Incremental whitebox attack surface workflow for commit-triggered recon.
 *
 * Instead of scanning the entire codebase:
 * 1. Run `git diff` between the two commits and write the output to a file.
 * 2. Serialize existing assets into the session's assets directory (app folder structure).
 * 3. Spawn a CodeAgent to analyze the diff and update assets in-place.
 *    New endpoints get risk scores inline via document_endpoint.
 * 4. Read the final assets directory and reconstruct the result.
 * 5. Carry forward existing risk scores for unchanged endpoints.
 */
export async function runIncrementalWhiteboxAttackSurfaceWorkflow(
  input: IncrementalWhiteboxInput,
): Promise<WhiteboxAttackSurfaceResult> {
  const {
    codebasePath,
    previousCommitSha,
    currentCommitSha,
    existingResult,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    attackSurfaceRegistry,
    onStepFinish,
    projectThreatModel,
  } = input;

  // =========================================================================
  // Phase 1: Generate diff file
  // =========================================================================

  const diffPath = join(session.rootPath, "diff-output.txt");
  try {
    const diff = execFileSync(
      "git",
      ["diff", `${previousCommitSha}..${currentCommitSha}`],
      { cwd: codebasePath, maxBuffer: 50 * 1024 * 1024, encoding: "utf-8" },
    );
    writeFileSync(diffPath, diff, "utf-8");
  } catch (error) {
    console.error(
      "Failed to generate git diff, falling back to full recon:",
      error,
    );
    return runWhiteboxAttackSurfaceWorkflow(input);
  }

  // =========================================================================
  // Phase 2: Serialize existing assets to session's assets directory
  //          (app folder structure: assets/<app>/app.json + endpoint files)
  // =========================================================================

  const assetsPath = join(session.rootPath, "assets");
  mkdirSync(assetsPath, { recursive: true });

  let preloadedCount = 0;

  for (const app of existingResult.apps) {
    const appDir = join(assetsPath, sanitizeName(app.name));
    mkdirSync(appDir, { recursive: true });

    // Write app.json
    const metadata: AppMetadata = {
      name: app.name,
      type: app.type ?? "web_application",
      framework: app.framework,
      description: app.description,
      location: app.location,
    };
    writeFileSync(
      join(appDir, "app.json"),
      JSON.stringify(metadata, null, 2),
      "utf-8",
    );

    // Write endpoint assets
    for (const ep of [...app.pages, ...app.apiEndpoints]) {
      const isPage = app.pages.includes(ep);
      const rawKey = `${app.name}__${ep.path}`.toLowerCase();
      const hash = createHash("sha256")
        .update(rawKey)
        .digest("hex")
        .slice(0, 8);
      const sanitizedPath = sanitizeName(ep.path);
      const filename = `asset_${sanitizedPath}_${hash}.json`;

      const { riskScore: _staleScore, threatModel, ...epWithoutMeta } = ep;
      const assetData: Record<string, unknown> = {
        assetName: ep.path,
        assetType: "endpoint",
        appName: app.name,
        description: ep.description ?? `${ep.method} ${ep.path}`,
        details: {
          url: ep.path,
          method: isPage ? "PAGE" : ep.method,
          file: ep.file,
          line: ep.line,
          handler: ep.handler,
          authRequired: ep.authRequired,
        },
        riskLevel: "MEDIUM",
        pentestObjectives: epWithoutMeta.pentestObjectives ?? [],
        ...(threatModel ? { threatModel } : {}),
        discoveredAt: new Date().toISOString(),
        sessionId: session.id,
        target: "",
      };
      writeFileSync(
        join(appDir, filename),
        JSON.stringify(assetData, null, 2),
        "utf-8",
      );
      preloadedCount++;
    }
  }

  console.log(
    `Incremental recon: wrote ${preloadedCount} existing endpoint assets to ${assetsPath}`,
  );

  // =========================================================================
  // Phase 3: Agent analyzes diff and updates asset files
  // =========================================================================

  const IncrementalResultSchema = z.object({
    repoType: z.string(),
    packageManager: z.string(),
    changedApps: z
      .array(z.string())
      .describe("Names of applications that were affected by the diff"),
    addedEndpoints: z.number().describe("Count of new endpoints added"),
    modifiedEndpoints: z
      .number()
      .describe("Count of existing endpoints modified"),
    removedEndpoints: z.number().describe("Count of endpoints removed"),
    summary: z.string().describe("Brief summary of what changed"),
  });

  type IncrementalResult = z.infer<typeof IncrementalResultSchema>;

  const objective = buildIncrementalObjective(
    codebasePath,
    diffPath,
    assetsPath,
    existingResult,
    input.domains,
    input.environments,
  );

  const agent = new CodeAgent<IncrementalResult>({
    codebasePath,
    objective,
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    attackSurfaceRegistry,
    eventBus,
    subagentId: "whitebox-incremental",
    onStepFinish: (event) => onStepFinish?.(event),
    responseSchema: IncrementalResultSchema,
    projectThreatModel,
  });

  const agentResult = await agent.consume();

  console.log(
    `Incremental agent finished: ${agentResult?.summary ?? "no summary"}`,
  );

  // =========================================================================
  // Phase 4: Read final assets directory and reconstruct result
  // =========================================================================

  const { apps: parsedApps } = readAppsFromAssetsDirectory(assetsPath);

  // =========================================================================
  // Phase 5: Carry forward existing risk scores for endpoints that were
  //          not re-created via document_endpoint (i.e. modified via
  //          execute_command or unchanged). New endpoints already have
  //          inline risk scores from document_endpoint.
  // =========================================================================

  const existingEndpointMap = new Map<string, Endpoint>();
  for (const existingApp of existingResult.apps) {
    for (const ep of [...existingApp.pages, ...existingApp.apiEndpoints]) {
      existingEndpointMap.set(`${ep.method}:${ep.file}:${ep.path}`, ep);
    }
  }

  function carryForwardRiskScore(ep: Endpoint): Endpoint {
    if (ep.riskScore) return ep;
    const key = `${ep.method}:${ep.file}:${ep.path}`;
    const existing = existingEndpointMap.get(key);
    return existing?.riskScore ? { ...ep, riskScore: existing.riskScore } : ep;
  }

  const apps: App[] = parsedApps.map((app) => ({
    ...app,
    pages: app.pages.map(carryForwardRiskScore),
    apiEndpoints: app.apiEndpoints.map(carryForwardRiskScore),
  }));

  const totalPages = apps.reduce((sum, a) => sum + a.pages.length, 0);
  const totalApiEndpoints = apps.reduce(
    (sum, a) => sum + a.apiEndpoints.length,
    0,
  );
  const totalPentestObjectives = apps.reduce(
    (sum, a) =>
      sum +
      [...a.pages, ...a.apiEndpoints].reduce(
        (s, ep) => s + ep.pentestObjectives.length,
        0,
      ),
    0,
  );

  return {
    repoType: existingResult.repoType,
    packageManager: existingResult.packageManager,
    apps,
    summary: {
      totalApps: apps.length,
      totalPages,
      totalApiEndpoints,
      totalPentestObjectives,
    },
  };
}

// ---------------------------------------------------------------------------
// Incremental objective builder
// ---------------------------------------------------------------------------

function buildIncrementalObjective(
  codebasePath: string,
  diffPath: string,
  assetsPath: string,
  existingResult: WhiteboxAttackSurfaceResult,
  domains?: string[],
  environments?: string[],
): string {
  const appsSummary = existingResult.apps
    .map((app) => {
      const epCount = app.pages.length + app.apiEndpoints.length;
      return `  - **${app.name}** (${app.framework}) at \`${app.location}\` — ${epCount} endpoints`;
    })
    .join("\n");

  const domainSection = domains?.length
    ? `\n## Known Domains\nThe following domains are associated with this project. When documenting new apps, set the \`domain\` field on \`document_app\` if you can determine which domain serves the app:\n${domains.map((d) => `- ${d}`).join("\n")}\n`
    : "";

  const environmentsSection = environments?.length
    ? `\n## Target Environments\nThis project is deployed to: ${environments.join(", ")}. When the diff introduces new dynamically-named resources (e.g. environment-prefixed S3 buckets, stage-scoped databases), create a **separate app entry per environment** using the environment name as a prefix (e.g. \`${environments[0]}-<resource>\`). Use environment-specific identifiers in domains and endpoints.\n`
    : "";

  return `# Incremental Attack Surface Update

## Context
You are updating the attack surface map for a repository after a new commit. Rather than analyzing the entire codebase, you will analyze only the **changed files** and update the existing endpoint assets accordingly. Also check for any new cloud resources (S3 buckets, storage, CDN origins, etc.) introduced in the diff.

## Codebase
- **Path:** ${codebasePath}
- **Diff file:** ${diffPath} (contains \`git diff\` output between the previous and current commit)
- **Existing assets directory:** ${assetsPath}
${domainSection}${environmentsSection}
## Directory Structure
The assets directory uses app-scoped folders:
\`\`\`
assets/
  <app-name>/
    app.json           — app metadata (name, framework, description, location)
    asset_*.json       — one file per endpoint (written by document_endpoint)
\`\`\`

## Existing Applications
${appsSummary}

## Task

### Step 1: Read and understand the diff
Read the diff file at \`${diffPath}\`. If it's very large, read it in chunks. Identify which files were added, modified, or deleted.

### Step 2: Determine impact on the attack surface
For each changed file, determine if it affects any endpoints:
- **New route/endpoint definitions** → use \`document_endpoint\` with the appropriate \`appName\`
- **Modified route handlers** → read the existing asset file, then use \`execute_command\` to update it
- **Deleted route files or endpoint definitions** → delete the corresponding asset file
- **Non-route changes** (e.g. utility functions, configs, tests) → skip

### Step 3: Update assets
For new endpoints, use \`document_endpoint\` with:
- \`appName\` set to the correct application name
- \`routePath\` set to the HTTP route (e.g., \`/api/users\`) — this is NOT a file path
- \`method\` as an array of ALL HTTP methods the path supports
- \`file\` set to the source-code file (e.g., \`src/routes/users.ts\`) — this is NOT the route
- \`line\`, \`handler\`, \`authRequired\` filled in

For modified endpoints, update the existing JSON file via \`execute_command\`.
For removed endpoints, delete the file via \`execute_command\`.

**IMPORTANT: ONE entry per route path.** Do NOT create separate entries for different HTTP methods on the same path.

**IMPORTANT: NO MANIFESTS, NO BATCHING.** Call \`document_endpoint\` directly, one new endpoint at a time, the moment you identify it. Do not build a JSON file or list of endpoints-to-document and process it later, and do not write a script that emits \`document_endpoint\` calls — that pattern hits output-token limits and silently drops endpoints.

### Step 4: Report
When finished, call the \`response\` tool with a summary of your changes.

**IMPORTANT:** Be conservative. Only add/modify/remove endpoints that are clearly affected by the diff. Do not re-analyze the entire codebase.`;
}
