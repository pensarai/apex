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
  type RiskScore,
} from "../agents/specialized/whiteboxAttackSurface/types";
import type { DocumentedEndpointRecord } from "../agents/specialized/attackSurface/schemas";
import type { AIModel, CacheMetrics } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";
import { runWithBoundedConcurrency } from "../utils/concurrency";
import { scoreEndpoints } from "./riskScoring";
import { execFileSync } from "child_process";
import { createHash } from "crypto";
import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";

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

const WHITEBOX_CODE_AGENT_SYSTEM_PROMPT = `You are an expert source-code analyst with direct filesystem access. You will be given a specific objective — focus exclusively on completing it.

Your focus is on **deployed applications and services** — APIs, web apps, microservices — that listen on a port and serve traffic. Ignore libraries, shared packages, SDKs, CLI tools, build scripts, and test suites unless they are part of a deployable service.

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

**CRITICAL — endpoint documentation rules:**
- **One entry per unique route path.** Do NOT create separate entries for different HTTP methods on the same path. If \`/api/users\` supports GET, POST, and DELETE, that is ONE entry with \`method: ["GET", "POST", "DELETE"]\`.
- **Use \`method: "PAGE"\`** for web pages and views (non-API routes).
- **Always set \`appName\`** to the application name provided in your objective.
- **Always set \`url\`** to the route path (e.g., \`/api/users/:id\`, \`/dashboard\`).
- **Always set \`file\`** to the source file where the route is defined.
- **Set \`line\`** to the line number when determinable.
- **Set \`handler\`** to the handler function or component name.
- **Set \`authRequired\`** to true/false based on middleware, guards, or decorators.


## response
When your objective includes structured output, call \`response\` with your final results once you are done. This ends your run.

# Working Approach
1. **Orient first** — list files and read key entry points to understand the structure.
2. **Ignore submodules** — check for a \`.gitmodules\` file or run \`git submodule status\`. Any directories that are git submodules are external dependencies and must be **completely excluded** from your analysis.
3. **Search, then read** — use grep to locate what you need, then read the relevant files.
4. **Document as you go** — call document_app for apps and document_endpoint for every endpoint you discover. Don't batch them up.
5. **Follow the trail** — trace through imports, function calls, and references to build full understanding.
6. **Be thorough** — don't stop at the first match. Cover everything relevant to the objective.
`;

// ---------------------------------------------------------------------------
// Intermediate schemas (structured output for each workflow step)
// ---------------------------------------------------------------------------

const AppInfoSchema = z.object({
  name: z.string().describe("Application or service name"),
  framework: z
    .string()
    .describe(
      "Framework in use (e.g. Express, Next.js, Django, FastAPI, Rails)",
    ),
  description: z.string().describe("Brief description of what this app does"),
  location: z
    .string()
    .describe("Path to the app root relative to the repository root"),
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

const DiscoverySummarySchema = z.object({
  endpointsDocumented: z
    .number()
    .describe("Number of endpoints documented via document_endpoint"),
  summary: z.string().describe("Brief summary of what was found"),
});

type DiscoverySummary = z.infer<typeof DiscoverySummarySchema>;

// ---------------------------------------------------------------------------
// Input type
// ---------------------------------------------------------------------------

export interface WhiteboxAttackSurfaceWorkflowInput {
  codebasePath: string;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
  attackSurfaceRegistry?: import("../findings/attackSurfaceRegistry").AttackSurfaceRegistry;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onCacheMetrics?: (metrics: CacheMetrics) => void;
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
 * Phase 3: Read the assets directory to build endpoint data.
 * Phase 4: Risk scoring.
 * Phase 5: Final assembly.
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
    callbacks,
    attackSurfaceRegistry,
    onStepFinish,
    onCacheMetrics,
  } = input;

  // =========================================================================
  // Phase 1: Identify all apps in the repository
  // =========================================================================

  const appsAgent = new CodeAgent<AppsDiscoveryResult>({
    codebasePath,
    objective: buildAppsDiscoveryObjective(codebasePath),
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    attackSurfaceRegistry,
    callbacks,
    onStepFinish: (event) => onStepFinish?.(event),
    onCacheMetrics,
    responseSchema: AppsDiscoveryResultSchema,
  });

  const appsResult = await appsAgent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCallStreaming: (d) => callbacks?.onToolCallStreaming?.(d),
    onToolCallDelta: (d) => callbacks?.onToolCallDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

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
  // Phase 2: For each app, discover pages + API endpoints via document_endpoint
  // =========================================================================

  type AppTask = {
    appInfo: z.infer<typeof AppInfoSchema>;
    type: "pages" | "apiEndpoints";
  };

  const tasks: AppTask[] = appsResult.apps.flatMap((app) => [
    { appInfo: app, type: "pages" as const },
    { appInfo: app, type: "apiEndpoints" as const },
  ]);

  await runWithBoundedConcurrency(
    tasks,
    DEFAULT_CONCURRENCY,
    async (task, _index) => {
      const subagentId = `${task.type}-${task.appInfo.name}`;

      callbacks?.subagentCallbacks?.onSubagentSpawn?.({
        subagentId,
        input: { app: task.appInfo.name, type: task.type },
        status: "pending",
      });

      const objective =
        task.type === "pages"
          ? buildPagesDiscoveryObjective(codebasePath, task.appInfo)
          : buildApiEndpointsDiscoveryObjective(codebasePath, task.appInfo);

      const agent = new CodeAgent<DiscoverySummary>({
        codebasePath,
        objective,
        system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
        model,
        session,
        authConfig,
        abortSignal,
        attackSurfaceRegistry,
        callbacks,
        onStepFinish: (event) => onStepFinish?.(event),
        onCacheMetrics,
        responseSchema: DiscoverySummarySchema,
      });

      try {
        await agent.consume({
          onError: (e) => callbacks?.onError?.(e),
          subagentCallbacks: callbacks?.subagentCallbacks
            ? {
                onTextDelta: (d) =>
                  callbacks.subagentCallbacks!.onTextDelta?.({
                    ...d,
                    subagentId,
                  }),
                onToolCallStreaming: (d) =>
                  callbacks.subagentCallbacks!.onToolCallStreaming?.({
                    ...d,
                    subagentId,
                  }),
                onToolCallDelta: (d) =>
                  callbacks.subagentCallbacks!.onToolCallDelta?.({
                    ...d,
                    subagentId,
                  }),
                onToolCall: (d) =>
                  callbacks.subagentCallbacks!.onToolCall?.({
                    ...d,
                    subagentId,
                  }),
                onToolResult: (d) =>
                  callbacks.subagentCallbacks!.onToolResult?.({
                    ...d,
                    subagentId,
                  }),
                onError: (e) => callbacks.subagentCallbacks!.onError?.(e),
              }
            : undefined,
        });

        callbacks?.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { app: task.appInfo.name, type: task.type },
          status: "completed",
        });
      } catch (error) {
        callbacks?.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { app: task.appInfo.name, type: task.type },
          status: "failed",
        });
      }
    },
  );

  // =========================================================================
  // Phase 3: Read assets directory to build endpoint data
  // =========================================================================

  const {
    apps: parsedApps,
    repoType,
    packageManager,
  } = readAppsFromAssetsDirectory(assetsPath, appsResult);

  // =========================================================================
  // Phase 4: Risk scoring — score all endpoints in parallel
  // =========================================================================

  const allEndpointsForScoring = parsedApps.flatMap((app) =>
    [...app.pages, ...app.apiEndpoints].map((ep) => ({
      ...ep,
      appName: app.name,
    })),
  );

  let riskScores = new Map<string, RiskScore>();

  if (allEndpointsForScoring.length > 0) {
    try {
      riskScores = await scoreEndpoints({
        codebasePath,
        endpoints: allEndpointsForScoring,
        model,
        session,
        authConfig,
        abortSignal,
        callbacks,
      });
      console.log(
        `Risk scoring complete: ${riskScores.size}/${allEndpointsForScoring.length} endpoints scored`,
      );
    } catch (error) {
      console.error(
        "Risk scoring phase failed, continuing without scores:",
        error,
      );
    }
  }

  // =========================================================================
  // Phase 5: Final assembly with risk scores attached
  // =========================================================================

  function attachRiskScore(ep: Endpoint): Endpoint {
    const key = `${ep.method}:${ep.file}:${ep.path}`;
    const score = riskScores.get(key);
    return score ? { ...ep, riskScore: score } : ep;
  }

  const apps: App[] = parsedApps.map((app) => ({
    ...app,
    pages: app.pages.map(attachRiskScore),
    apiEndpoints: app.apiEndpoints.map(attachRiskScore),
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
    return { apps: [], repoType, packageManager };
  }

  const entries = readdirSync(assetsPath);
  const apps: App[] = [];

  for (const entry of entries) {
    const entryPath = join(assetsPath, entry);
    if (!statSync(entryPath).isDirectory()) continue;

    const appJsonPath = join(entryPath, "app.json");
    let metadata: AppMetadata;

    if (existsSync(appJsonPath)) {
      try {
        metadata = JSON.parse(
          readFileSync(appJsonPath, "utf-8"),
        ) as AppMetadata;
      } catch {
        console.warn(`Skipping app folder with unreadable app.json: ${entry}`);
        continue;
      }
    } else {
      continue;
    }

    const pages: Endpoint[] = [];
    const apiEndpoints: Endpoint[] = [];

    const assetFiles = readdirSync(entryPath).filter(
      (f) => f.endsWith(".json") && f !== "app.json",
    );

    for (const file of assetFiles) {
      try {
        const raw = readFileSync(join(entryPath, file), "utf-8");
        const data = JSON.parse(raw) as DocumentedEndpointRecord;

        const endpoint = assetRecordToEndpoint(data);
        if (!endpoint) continue;

        if (isPageEndpoint(data)) {
          pages.push(endpoint);
        } else {
          apiEndpoints.push(endpoint);
        }
      } catch {
        console.warn(`Skipping unreadable asset file: ${entry}/${file}`);
      }
    }

    apps.push({
      name: metadata.name,
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
function assetRecordToEndpoint(record: DocumentedEndpointRecord): Endpoint | null {
  const rawMethod = record.method;
  const method = Array.isArray(rawMethod)
    ? rawMethod.join(", ")
    : (rawMethod ?? "UNKNOWN");

  const path = record.url ?? record.endpointName;
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

function buildAppsDiscoveryObjective(codebasePath: string): string {
  return `# Identify All Applications in the Repository

## Codebase
- **Path:** ${codebasePath}

## Task
Analyze the repository structure and identify every **deployed application or service** (APIs, web apps, microservices) defined within it.

**IMPORTANT: Only include deployable apps and services.** Exclude:
- Libraries, SDKs, and shared packages that are consumed by other code but not deployed on their own
- Git submodules (external dependencies)
- Build tools, scripts, CLI utilities, and dev tooling
- Test suites, fixtures, and test helpers
- Documentation packages

An app/service qualifies if it **listens on a port, serves HTTP traffic, or runs as a deployed process** (e.g. an Express server, a Next.js app, a Django project, a FastAPI service, a background worker with an API).

### Steps
1. List the root directory and read top-level config files (package.json, requirements.txt, Cargo.toml, go.mod, etc.)
2. **Check for git submodules** — run \`git submodule status\` or check for a \`.gitmodules\` file. Exclude all submodule directories.
3. Determine the **repo type**: monorepo (workspaces), single-app, multi-package, etc.
4. Determine the **package manager**: npm, yarn, pnpm, pip, cargo, go modules, etc.
5. Identify all **deployable** applications/services (ignoring submodules, libraries, and shared packages):
   - For monorepos: look at workspace packages that have their own server entry point, Dockerfile, or deploy config — skip packages that are libraries/utilities consumed by other packages
   - For multi-service repos: look at separate service directories with their own server startup
   - For single apps: the root is the app
6. For each app, determine:
   - **name**: the application or service name
   - **framework**: the web framework (Express, Next.js, Django, FastAPI, Rails, Spring, etc.)
   - **description**: brief summary of what it does
   - **location**: path relative to the repository root

When finished, call the \`response\` tool with your structured findings.`;
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

## Task
Find ALL web pages, views, and routes that render HTML or serve client-side UI in this application.

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
- **endpointName**: The route path (e.g., \`/dashboard\`, \`/admin\`, \`/settings\`)
- **endpointType**: \`"web-endpoint"\`
- **description**: Brief description of what this page shows
- **url**: The route path
- **method**: \`"PAGE"\`
- **file**: Source file where this page is defined
- **line**: Line number (if determinable)
- **handler**: Component or handler name
- **authRequired**: Whether the page requires authentication
- **riskLevel**: CRITICAL for admin/auth pages, HIGH for user data, MEDIUM for general, LOW for static/public
- **pentestObjectives**: Specific testing goals, e.g.:
  - "Test for XSS in user-editable fields on the profile page"
  - "Test for authorization bypass — access admin dashboard as regular user"
  - "Test for CSRF on the settings update form"

Be thorough — examine every route file, every page directory, every template.
When finished, call \`response\` with a summary of how many pages you documented.`;
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

## Task
Find ALL API endpoints defined in this application.

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
- **endpointName**: The route path (e.g., \`/api/users\`, \`/api/orders/:id\`)
- **endpointType**: \`"api-endpoint"\`
- **description**: Brief description of what this endpoint does across all its methods
- **url**: The route path
- **method**: Array of ALL HTTP methods this path supports (e.g., \`["GET", "POST"]\`). **Do NOT create separate entries for each method — consolidate them.**
- **file**: Source file where the endpoint is defined
- **line**: Line number (if determinable)
- **handler**: Handler function name (comma-separate if multiple handlers for different methods)
- **authRequired**: Whether the endpoint requires authentication (true if ANY method requires it)
- **riskLevel**: CRITICAL for auth/payment/admin, HIGH for user data mutations, MEDIUM for general, LOW for read-only public
- **pentestObjectives**: Specific testing goals covering ALL methods, e.g.:
  - "Test for SQL injection in the 'search' query parameter (GET)"
  - "Test for IDOR by accessing /api/orders/{id} with other users' order IDs (GET)"
  - "Test for mass assignment by sending extra fields in the POST body"
  - "Test for privilege escalation by calling admin-only endpoint as regular user"

**CRITICAL: ONE entry per route path.** If \`/api/products\` has GET (list) and POST (create), document it as ONE entry with \`method: ["GET", "POST"]\`. Do NOT create two separate entries.

**IMPORTANT — Method consolidation for document_endpoint:** When using the \`document_endpoint\` tool, do NOT create separate entries for different HTTP methods on the same route path. For example, if \`/api/users\` supports GET, POST, and DELETE, document it as ONE entry with \`method: ["GET", "POST", "DELETE"]\` and include pentest objectives covering all methods. However, when reporting endpoints via the \`response\` tool, you may still list each method+path combination individually for completeness — the consolidation rule applies specifically to \`document_endpoint\` calls.

Be thorough — trace through all route registrations, middleware chains, and controller files.
When finished, call \`response\` with a summary of how many endpoints you documented.`;
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
 * 4. Re-score only changed/new endpoints.
 * 5. Assemble the final result from the updated assets directory.
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
    callbacks,
    attackSurfaceRegistry,
    onStepFinish,
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

      const { riskScore: _staleScore, ...epWithoutScore } = ep;
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
        pentestObjectives: epWithoutScore.pentestObjectives ?? [],
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
    callbacks,
    onStepFinish: (event) => onStepFinish?.(event),
    responseSchema: IncrementalResultSchema,
  });

  const agentResult = await agent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCallStreaming: (d) => callbacks?.onToolCallStreaming?.(d),
    onToolCallDelta: (d) => callbacks?.onToolCallDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  console.log(
    `Incremental agent finished: ${agentResult?.summary ?? "no summary"}`,
  );

  // =========================================================================
  // Phase 4: Read final assets directory and reconstruct result
  // =========================================================================

  const { apps: parsedApps } = readAppsFromAssetsDirectory(assetsPath);

  // =========================================================================
  // Phase 5: Re-score changed/new endpoints
  // =========================================================================

  const changedEndpointsForScoring: Array<Endpoint & { appName: string }> = [];

  const existingEndpointMap = new Map<string, Endpoint>();
  for (const existingApp of existingResult.apps) {
    for (const ep of [...existingApp.pages, ...existingApp.apiEndpoints]) {
      existingEndpointMap.set(`${ep.method}:${ep.file}:${ep.path}`, ep);
    }
  }

  for (const app of parsedApps) {
    for (const ep of [...app.pages, ...app.apiEndpoints]) {
      const key = `${ep.method}:${ep.file}:${ep.path}`;
      const existing = existingEndpointMap.get(key);

      const isNew = !existing;
      const hasNoScore = existing && !existing.riskScore;
      const isModified =
        existing &&
        (existing.handler !== ep.handler ||
          existing.authRequired !== ep.authRequired ||
          existing.description !== ep.description ||
          existing.line !== ep.line ||
          JSON.stringify(existing.pentestObjectives) !==
            JSON.stringify(ep.pentestObjectives));

      if (isNew || hasNoScore || isModified) {
        changedEndpointsForScoring.push({ ...ep, appName: app.name });
      } else if (existing?.riskScore) {
        ep.riskScore = existing.riskScore;
      }
    }
  }

  let riskScores = new Map<string, RiskScore>();

  if (changedEndpointsForScoring.length > 0) {
    try {
      riskScores = await scoreEndpoints({
        codebasePath,
        endpoints: changedEndpointsForScoring,
        model,
        session,
        authConfig,
        abortSignal,
        callbacks,
      });
      console.log(
        `Incremental risk scoring complete: ${riskScores.size}/${changedEndpointsForScoring.length} scored`,
      );
    } catch (error) {
      console.error("Risk scoring failed during incremental recon:", error);
    }
  }

  // =========================================================================
  // Phase 6: Final assembly with risk scores
  // =========================================================================

  function attachRiskScore(ep: Endpoint): Endpoint {
    const key = `${ep.method}:${ep.file}:${ep.path}`;
    const score = riskScores.get(key);
    return score ? { ...ep, riskScore: score } : ep;
  }

  const apps: App[] = parsedApps.map((app) => ({
    ...app,
    pages: app.pages.map(attachRiskScore),
    apiEndpoints: app.apiEndpoints.map(attachRiskScore),
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
): string {
  const appsSummary = existingResult.apps
    .map((app) => {
      const epCount = app.pages.length + app.apiEndpoints.length;
      return `  - **${app.name}** (${app.framework}) at \`${app.location}\` — ${epCount} endpoints`;
    })
    .join("\n");

  return `# Incremental Attack Surface Update

## Context
You are updating the attack surface map for a repository after a new commit. Rather than analyzing the entire codebase, you will analyze only the **changed files** and update the existing endpoint assets accordingly.

## Codebase
- **Path:** ${codebasePath}
- **Diff file:** ${diffPath} (contains \`git diff\` output between the previous and current commit)
- **Existing assets directory:** ${assetsPath}

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
- \`method\` as an array of ALL HTTP methods the path supports
- \`file\`, \`line\`, \`handler\`, \`authRequired\` filled in

For modified endpoints, update the existing JSON file via \`execute_command\`.
For removed endpoints, delete the file via \`execute_command\`.

**IMPORTANT: ONE entry per route path.** Do NOT create separate entries for different HTTP methods on the same path.

### Step 4: Report
When finished, call the \`response\` tool with a summary of your changes.

**IMPORTANT:** Be conservative. Only add/modify/remove endpoints that are clearly affected by the diff. Do not re-analyze the entire codebase.`;
}
