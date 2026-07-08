import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import pLimit from "p-limit";
import { z } from "zod";
import type { DocumentedEndpointRecord } from "../agents/specialized/attackSurface/schemas";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import {
  type App,
  type AppInfo,
  type AppsDiscoveryResult,
  AppsDiscoveryResultSchema,
  type DiscoverySummary,
  DiscoverySummarySchema,
  type Endpoint,
  EndpointSchema,
  WHITEBOX_APPS_DISCOVERY_SYSTEM_PROMPT,
  WHITEBOX_DISCOVERY_SYSTEM_PROMPT,
  type WhiteboxAttackSurfaceResult,
} from "../agents/specialized/whiteboxAttackSurface";
import { runAppEndpointDocumentation } from "../agents/specialized/whiteboxAttackSurface/endpointDocumentationAgent";
import type {
  AIAuthConfig,
  AIModel,
  CacheMetrics,
  OpenAIReasoningEffort,
  ThinkingEffort,
} from "../ai";
import type { AgentEventBus } from "../eventBus";
import { newSessionId } from "../id/id";
import { mapAppWithSurface } from "../integrations/surface";
import { createLogger } from "../logger/structured";
import type { SessionInfo } from "../session";
import { scopedLogger } from "../util/lazyLogger";
import { runWithBoundedConcurrency } from "../utils/concurrency";

const log = scopedLogger(() => createLogger("whitebox-workflow"));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CONCURRENCY = 5;

/**
 * Hard ceiling on CodeAgents running concurrently across ALL apps and their
 * endpoints. Previously the app-level cap (`DEFAULT_CONCURRENCY` = 5) and the
 * per-app endpoint cap (`ENDPOINT_DOCUMENTATION_CONCURRENCY` = 10) multiplied,
 * so a repo with many apps could run ~50 agents at once — the dominant memory
 * driver in the 8 GiB recon sandbox. A single shared `p-limit` gate makes the
 * cap independent of app/endpoint counts. Override via
 * `WhiteboxAttackSurfaceWorkflowInput.maxConcurrentAgents`.
 */
const MAX_CONCURRENT_AGENTS = 12;

type DiscoveryTaskType = "pages" | "apiEndpoints" | "cloudResourceEndpoints";

// Sibling cards under an app share the app name from their parent;
// label children by what they *do* instead.
const TASK_TYPE_LABELS = {
  pages: "Pages",
  apiEndpoints: "API Endpoints",
  cloudResourceEndpoints: "Cloud Resources",
} as const satisfies Record<DiscoveryTaskType, string>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

// Shape persisted to <app>/app.json. Equivalent to AppInfo — kept as a Pick
// so the field list can't drift out of sync with the schema.
type AppMetadata = Pick<
  AppInfo,
  "name" | "type" | "framework" | "description" | "location"
>;

function toAppMetadata(
  app: Pick<App, "name" | "type" | "framework" | "description" | "location">,
): AppMetadata {
  return {
    name: app.name,
    type: app.type,
    framework: app.framework,
    description: app.description,
    location: app.location,
  };
}

// System prompts and intermediate schemas live in
// `src/core/agents/specialized/whiteboxAttackSurface/{prompts,types}.ts`.
// This file is the orchestration layer that consumes them.

// ---------------------------------------------------------------------------
// Input types
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
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  /** Enable extended thinking for supported models (Anthropic Claude 3.7+). */
  enableThinking?: boolean;
  /** Adaptive-thinking effort hint (Anthropic Opus/Sonnet 4.6+); ignored elsewhere. */
  thinkingEffort?: ThinkingEffort | null;
  /** Known domains associated with the project — agents can map discovered apps to these. */
  domains?: string[];
  /** Project-level threat model content (e.g. from .pensar/threat_model.md), if found */
  projectThreatModel?: string;
  /** Deployment environment names (e.g. ["production", "staging"]) from project settings. */
  environments?: string[];
  /**
   * When false, Phase 2 skips the deterministic `@pensar/surface` path and
   * always runs the legacy pages + apiEndpoints discovery agent pair for
   * service apps. Defaults to `true`.
   */
  surfaceIntegrationEnabled?: boolean;
  /**
   * Hard ceiling on CodeAgents running concurrently across all apps/endpoints.
   * Defaults to {@link MAX_CONCURRENT_AGENTS}. Bounds total agent fan-out so it
   * doesn't scale with the number of apps in the repo.
   */
  maxConcurrentAgents?: number;
}

interface IncrementalWhiteboxInput extends WhiteboxAttackSurfaceWorkflowInput {
  previousCommitSha: string;
  currentCommitSha: string;
  existingResult: WhiteboxAttackSurfaceResult;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * Deterministic whitebox attack surface workflow.
 *
 * Phase 1: Spawn a single CodeAgent to identify all apps in the repo.
 * Phase 1.5: Create app folders with app.json metadata.
 * Phase 2: Per-app dispatch. When `surfaceIntegrationEnabled` (default), service
 *           apps run `mapAppWithSurface`; on `surface` mode a per-endpoint
 *           endpoint-documentation CodeAgent documents the deterministic list,
 *           on `fallback` the legacy pages+apiEndpoints agent pair runs. When
 *           `surfaceIntegrationEnabled` is false, every service app uses the
 *           legacy pair directly. Cloud resources always use the specialized
 *           cloud-resource agent. Threat models and risk scores are generated
 *           inline by document_endpoint.
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
    openAIReasoningEffort,
    enableThinking,
    thinkingEffort,
    domains,
    projectThreatModel,
    environments,
    surfaceIntegrationEnabled = true,
    maxConcurrentAgents = MAX_CONCURRENT_AGENTS,
  } = input;

  // Single shared gate for every CodeAgent run in this workflow (Phase 1
  // discovery, Phase 2 per-app discovery, and per-endpoint documentation). This
  // is what makes total concurrency independent of app count: the nested
  // app-level (`DEFAULT_CONCURRENCY`) and per-app endpoint-level
  // (`ENDPOINT_DOCUMENTATION_CONCURRENCY`) loops still control scheduling, but
  // the number of agents actually running at once can never exceed this.
  const agentSlots = pLimit(Math.max(1, maxConcurrentAgents));
  const agentLimiter = <T>(fn: () => Promise<T>): Promise<T> => agentSlots(fn);

  // =========================================================================
  // Phase 1: Identify all apps in the repository
  // =========================================================================

  // Umbrella node — real `ses_` id so the appsAgent span and its agent_sessions
  // row share one id; also the parent for per-app nodes (held open until Phase 2).
  const WORKFLOW_UMBRELLA_ID = newSessionId();

  const appsAgent = new CodeAgent<AppsDiscoveryResult>({
    codebasePath,
    objective: buildAppsDiscoveryObjective(codebasePath, domains, environments),
    // Phase 1 uses an apps-only system prompt (no document_endpoint guidance)
    // paired with `excludeTools: ["document_endpoint"]`. The shared
    // WHITEBOX_DISCOVERY_SYSTEM_PROMPT instructs every agent to call
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
    subagentId: WORKFLOW_UMBRELLA_ID,
    subagentName: "Whitebox Apps Discovery",
    onStepFinish: (event) => onStepFinish?.(event),
    onCacheMetrics,
    openAIReasoningEffort,
    enableThinking,
    thinkingEffort,
    responseSchema: AppsDiscoveryResultSchema,
    projectThreatModel,
    // Reserved for Phase 2's per-app task agents. Inline documentation
    // here would flatten the UI hierarchy under Phase 1.
    excludeTools: ["document_endpoint"],
  });

  log.info(
    `Phase 1: discovering apps in ${codebasePath}${domains?.length ? ` (${domains.length} known domains)` : ""}`,
  );

  eventBus?.emit("subagent-spawn", {
    subagentId: WORKFLOW_UMBRELLA_ID,
    name: "Whitebox Apps Discovery",
    input: { codebasePath },
  });

  const appsResult = await agentLimiter(() => appsAgent.consume());

  log.info(
    `Phase 1 complete: ${appsResult?.apps.length ?? 0} apps discovered` +
      (appsResult
        ? ` (repoType=${appsResult.repoType}, packageManager=${appsResult.packageManager})`
        : " (no result returned)"),
  );

  if (appsResult?.apps.length) {
    for (const app of appsResult.apps) {
      log.debug(
        `app: "${app.name}" type=${app.type} framework="${app.framework}" location="${app.location}"`,
      );
    }
  }

  if (!appsResult || appsResult.apps.length === 0) {
    eventBus?.emit("subagent-complete", {
      subagentId: WORKFLOW_UMBRELLA_ID,
      status: "completed",
    });
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
    writeFileSync(
      join(appDir, "app.json"),
      JSON.stringify(toAppMetadata(app), null, 2),
      "utf-8",
    );
  }

  // =========================================================================
  // Phase 2: Per-app dispatch — surface-driven documentation vs. fallback.
  //          When `surfaceIntegrationEnabled` is true, service apps try
  //          `mapAppWithSurface`; on `surface` mode run a per-endpoint
  //          endpoint-documentation CodeAgent against the deterministic list,
  //          on `fallback` run the legacy pages+apiEndpoints CodeAgent pair.
  //          When `surfaceIntegrationEnabled` is false, every service app
  //          uses the legacy pair directly — pre-PR behavior.
  //          Cloud resources always take the specialized objective — surface
  //          is HTTP-route-focused and doesn't enumerate cloud assets.
  // =========================================================================

  log.info(`Phase 2: surfaceIntegrationEnabled=${surfaceIntegrationEnabled}`);

  const NON_SERVICE_TYPES = ["cloud_resource", "storage", "database"];
  const serviceApps = appsResult.apps.filter(
    (app) => !NON_SERVICE_TYPES.includes(app.type),
  );
  const cloudApps = appsResult.apps.filter((app) =>
    NON_SERVICE_TYPES.includes(app.type),
  );

  log.info(
    `Phase 2: ${serviceApps.length} service apps (surface or fallback per app), ${cloudApps.length} cloud resources → ${appsResult.apps.length} total apps`,
  );

  const totalApps = appsResult.apps.length;
  let completedAppCount = 0;

  eventBus?.emit("app-analysis-progress", {
    totalApps,
    completedApps: 0,
  });

  // Synthetic grouping nodes between the umbrella and per-task agents,
  // so the UI nests pages/api/endpoint-doc agents under their app.
  const appNodeIdFor = (appName: string) => `app:${sanitizeName(appName)}`;
  const appAnyTaskFailed = new Map<string, boolean>();
  for (const app of appsResult.apps) {
    const appNodeId = appNodeIdFor(app.name);
    appAnyTaskFailed.set(app.name, false);
    eventBus?.emit("subagent-spawn", {
      subagentId: appNodeId,
      name: app.name,
      input: { app: app.name, type: app.type, framework: app.framework },
      parentSubagentId: WORKFLOW_UMBRELLA_ID,
    });
  }

  const spawnDiscoveryAgent = async (
    app: AppInfo,
    type: DiscoveryTaskType,
    objective: string,
  ): Promise<void> => {
    const subagentId = newSessionId();
    const appNodeId = appNodeIdFor(app.name);

    log.debug(
      `Phase 2: spawning agent id="${subagentId}" parent="${appNodeId}" (app="${app.name}", type=${type}, appType=${app.type})`,
    );

    eventBus?.emit("subagent-spawn", {
      subagentId,
      name: TASK_TYPE_LABELS[type],
      input: { app: app.name, type },
      parentSubagentId: appNodeId,
    });

    const agent = new CodeAgent<DiscoverySummary>({
      codebasePath,
      objective,
      system: WHITEBOX_DISCOVERY_SYSTEM_PROMPT,
      model,
      session,
      authConfig,
      abortSignal,
      attackSurfaceRegistry,
      eventBus,
      subagentId,
      subagentName: TASK_TYPE_LABELS[type],
      onStepFinish: (event) => onStepFinish?.(event),
      onCacheMetrics,
      openAIReasoningEffort,
      enableThinking,
      thinkingEffort,
      responseSchema: DiscoverySummarySchema,
      excludeTools: ["document_app"],
      projectThreatModel,
    });

    try {
      await agentLimiter(() => agent.consume());

      log.debug(`Phase 2: agent "${subagentId}" completed`);

      eventBus?.emit("subagent-complete", {
        subagentId,
        status: "completed",
        parentSubagentId: appNodeId,
      });
    } catch (error) {
      log.error(
        `Phase 2: agent "${subagentId}" FAILED`,
        error instanceof Error ? error : undefined,
        { error: String(error) },
      );

      appAnyTaskFailed.set(app.name, true);
      eventBus?.emit("subagent-complete", {
        subagentId,
        status: "failed",
        parentSubagentId: appNodeId,
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
      const appNodeId = appNodeIdFor(app.name);
      try {
        if (NON_SERVICE_TYPES.includes(app.type)) {
          // Cloud resources: surface doesn't enumerate these — always fallback.
          await spawnCloudResourceAgent(app);
        } else if (!surfaceIntegrationEnabled) {
          log.debug(`${app.name}: legacy (surfaceIntegrationEnabled=false)`);
          await Promise.all([
            spawnPagesAgent(app),
            spawnApiEndpointsAgent(app),
          ]);
        } else {
          const surfaceResult = mapAppWithSurface(
            join(codebasePath, app.location),
            codebasePath,
            { isSingleAppRepo: serviceApps.length === 1 },
          );
          if (surfaceResult.mode === "surface") {
            log.debug(
              `${app.name}: surface-driven (${surfaceResult.endpoints.length} endpoints, frameworks=${surfaceResult.frameworks.join(",")})`,
            );

            await runAppEndpointDocumentation({
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
              openAIReasoningEffort,
              enableThinking,
              thinkingEffort,
              projectThreatModel,
              parentSubagentId: appNodeId,
              agentLimiter,
            });
          } else {
            log.debug(`${app.name}: fallback (${surfaceResult.reason})`);
            await Promise.all([
              spawnPagesAgent(app),
              spawnApiEndpointsAgent(app),
            ]);
          }
        }
      } catch {
        appAnyTaskFailed.set(app.name, true);
      } finally {
        completedAppCount++;

        const appStatus = appAnyTaskFailed.get(app.name)
          ? ("failed" as const)
          : ("completed" as const);
        eventBus?.emit("subagent-complete", {
          subagentId: appNodeId,
          status: appStatus,
          parentSubagentId: WORKFLOW_UMBRELLA_ID,
        });

        eventBus?.emit("app-analysis-progress", {
          totalApps,
          completedApps: completedAppCount,
          appName: app.name,
        });
      }
    },
  );

  eventBus?.emit("subagent-complete", {
    subagentId: WORKFLOW_UMBRELLA_ID,
    status: "completed",
  });

  // =========================================================================
  // Phase 3: Read assets directory to build endpoint data
  // =========================================================================

  log.info(`Phase 3: reading assets from ${assetsPath}`);

  const {
    apps: parsedApps,
    repoType,
    packageManager,
  } = readAppsFromAssetsDirectory(assetsPath, appsResult);

  for (const app of parsedApps) {
    log.debug(
      `Phase 3: "${app.name}" → ${app.pages.length} pages, ${app.apiEndpoints.length} API endpoints`,
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
    log.debug(`readAssets: assets directory does not exist: ${assetsPath}`);
    return { apps: [], repoType, packageManager };
  }

  const entries = readdirSync(assetsPath);
  log.debug(
    `readAssets: found ${entries.length} entries in ${assetsPath}: [${entries.join(", ")}]`,
  );
  const apps: App[] = [];

  for (const entry of entries) {
    const entryPath = join(assetsPath, entry);
    if (!statSync(entryPath).isDirectory()) {
      log.debug(`readAssets: skipping non-directory: ${entry}`);
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
        log.warn(
          `readAssets: skipping app folder with unreadable app.json: ${entry}`,
        );
        continue;
      }
    } else {
      log.debug(`readAssets: skipping folder without app.json: ${entry}`);
      continue;
    }

    const pages: Endpoint[] = [];
    const apiEndpoints: Endpoint[] = [];

    const assetFiles = readdirSync(entryPath).filter(
      (f) => f.endsWith(".json") && f !== "app.json",
    );

    log.debug(
      `readAssets: app "${metadata.name}" (${entry}): ${assetFiles.length} asset files`,
    );

    let parseFailed = 0;
    for (const file of assetFiles) {
      try {
        const raw = readFileSync(join(entryPath, file), "utf-8");
        const data = JSON.parse(raw) as DocumentedEndpointRecord;

        const endpoint = assetRecordToEndpoint(data);
        if (!endpoint) {
          log.debug(
            `readAssets: ${file}: failed schema validation (assetRecordToEndpoint returned null)`,
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
        log.warn(
          `readAssets: skipping unreadable asset file: ${entry}/${file}`,
        );
        parseFailed++;
      }
    }

    log.debug(
      `readAssets: app "${metadata.name}": ${pages.length} pages, ${apiEndpoints.length} API endpoints, ${parseFailed} failed`,
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

## Phase scope — read this first
This objective is **Phase 1: app discovery only**. Your job is to enumerate
applications and call \`document_app\` for each. **Do NOT call
\`document_endpoint\` in this phase** — endpoints are documented in a later
phase by per-app subagents. The \`document_endpoint\` tool is intentionally
unavailable here. Ignore any general guidance in the system prompt that
tells you to call it; that guidance applies only to later phases.

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
  appInfo: AppInfo,
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
  appInfo: AppInfo,
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
- **gRPC**: \`.proto\` service definitions (\`service X { rpc Method (Req) returns (Resp); }\`), \`buf.yaml\`/\`buf.gen.yaml\`, or generated gRPC stubs

### gRPC / Connect services — do NOT flatten into HTTP paths
A gRPC method looks like a path (\`/package.Service/Method\`) but is NOT an HTTP route. When this app defines gRPC/Connect services, document **one \`document_endpoint\` per \`rpc\` method** with:
- **endpointType**: \`"api-endpoint"\` (a gRPC method is still an API endpoint)
- **transport**: \`"grpc"\` (or \`"grpc_web"\` / \`"connect"\` if the service is served that way)
- **routePath**: the wire path \`/package.Service/Method\` (e.g. \`/account.v1.AccountService/GetAccount\`) — do NOT prepend a host
- **grpc**: \`{ serviceFqn, method, fullMethodPath, streamingType, schemaSource: "proto" }\` where \`serviceFqn\` is the fully-qualified service (\`account.v1.AccountService\`), \`method\` is the rpc name, \`fullMethodPath\` equals \`routePath\`, and \`streamingType\` is one of \`unary | server_stream | client_stream | bidi\` (based on the \`stream\` keywords in the rpc signature). Set \`reflectionAvailable: true\` if the server registers the gRPC reflection service.
- If a REST/GraphQL gateway (e.g. grpc-gateway annotations, a GraphQL resolver) fronts a method, set \`grpc.frontingGatewayOperation\`.

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
  appInfo: AppInfo,
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
    log.error(
      "Failed to generate git diff, falling back to full recon",
      error instanceof Error ? error : undefined,
      { error: String(error) },
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

    writeFileSync(
      join(appDir, "app.json"),
      JSON.stringify(toAppMetadata(app), null, 2),
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

  log.info(
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
    system: WHITEBOX_DISCOVERY_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    attackSurfaceRegistry,
    eventBus,
    subagentId: newSessionId(),
    subagentName: "Incremental Recon",
    onStepFinish: (event) => onStepFinish?.(event),
    openAIReasoningEffort: input.openAIReasoningEffort,
    enableThinking: input.enableThinking,
    thinkingEffort: input.thinkingEffort,
    responseSchema: IncrementalResultSchema,
    projectThreatModel,
  });

  const agentResult = await agent.consume();

  log.info(
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
