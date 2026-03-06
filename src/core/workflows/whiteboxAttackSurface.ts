import { z } from "zod";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import {
  EndpointSchema,
  type WhiteboxAttackSurfaceResult,
  type Endpoint,
  type App,
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

## document_asset
**Use this to document every significant asset you discover.** Each call persists a JSON record to the session's assets directory. Document assets as you discover them — don't wait until the end.

Document these types of assets:
- **web_application**: Each application/service you identify (include framework and technology stack in details)
- **api**: API services or microservices (include base URL and authentication type in details)
- **admin_panel**: Admin interfaces, dashboards, management UIs
- **endpoint**: Notable endpoint groups — auth endpoints, file upload handlers, payment flows, admin routes
- **development_asset**: Dev/staging environments, CI/CD pipelines, internal tools

For each asset, include:
- **assetName**: A unique descriptive name (e.g., "user-api", "admin-dashboard", "payment-service")
- **assetType**: One of the types above
- **description**: What it is, what it does, why it matters for security
- **details**: Include \`technology\` (stack), \`endpoints\` (key routes), \`authentication\` (auth type), and \`url\` if known
- **riskLevel**: CRITICAL for auth/payment/admin, HIGH for user data, MEDIUM for general functionality, LOW for static/public

## response
When your objective includes structured output, call \`response\` with your final results once you are done. This ends your run — make sure all data is included.

# Working Approach
1. **Orient first** — list files and read key entry points to understand the structure.
2. **Ignore submodules** — check for a \`.gitmodules\` file or run \`git submodule status\`. Any directories that are git submodules are external dependencies and must be **completely excluded** from your analysis.
3. **Search, then read** — use grep to locate what you need, then read the relevant files.
4. **Document as you go** — call document_asset for every significant asset you discover. Don't batch them up.
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

const EndpointsDiscoveryResultSchema = z.object({
  endpoints: z.array(EndpointSchema).describe("All discovered endpoints"),
});

type EndpointsDiscoveryResult = z.infer<typeof EndpointsDiscoveryResultSchema>;

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
  onStepFinish?: (event: {
    usage?: {
      inputTokens?: number;
      outputTokens?: number;
      totalTokens?: number;
    };
  }) => void;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * Deterministic whitebox attack surface workflow.
 *
 * Phase 1: Spawn a single CodeAgent to identify all apps in the repo.
 * Phase 2: For each app, spawn two CodeAgents in parallel — one for
 *           pages, one for API endpoints.
 * Phase 3: Assemble the final {@link WhiteboxAttackSurfaceResult}.
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
  // Phase 2: For each app, discover pages + API endpoints in parallel
  // =========================================================================

  type AppTask = {
    appInfo: z.infer<typeof AppInfoSchema>;
    type: "pages" | "apiEndpoints";
  };

  const tasks: AppTask[] = appsResult.apps.flatMap((app) => [
    { appInfo: app, type: "pages" as const },
    { appInfo: app, type: "apiEndpoints" as const },
  ]);

  const taskResults = await runWithBoundedConcurrency(
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

      const agent = new CodeAgent<EndpointsDiscoveryResult>({
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
        responseSchema: EndpointsDiscoveryResultSchema,
      });

      try {
        const result = await agent.consume({
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

        return {
          appName: task.appInfo.name,
          type: task.type,
          endpoints: result?.endpoints ?? [],
        };
      } catch (error) {
        callbacks?.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { app: task.appInfo.name, type: task.type },
          status: "failed",
        });
        return { appName: task.appInfo.name, type: task.type, endpoints: [] };
      }
    },
  );

  // =========================================================================
  // Phase 3: Assemble the final result
  // =========================================================================

  const pagesByApp = new Map<string, Endpoint[]>();
  const apiEndpointsByApp = new Map<string, Endpoint[]>();

  for (const r of taskResults) {
    if (!r) continue;
    const map = r.type === "pages" ? pagesByApp : apiEndpointsByApp;
    map.set(r.appName, r.endpoints);
  }

  const apps: App[] = appsResult.apps.map((appInfo) => ({
    name: appInfo.name,
    framework: appInfo.framework,
    description: appInfo.description,
    location: appInfo.location,
    pages: pagesByApp.get(appInfo.name) ?? [],
    apiEndpoints: apiEndpointsByApp.get(appInfo.name) ?? [],
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
    repoType: appsResult.repoType,
    packageManager: appsResult.packageManager,
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

### For each page, provide
- **method**: "PAGE" or "GET"
- **path**: the route path (e.g. /dashboard, /settings)
- **handler**: the handler function or component name (if identifiable)
- **file**: the file where this page is defined
- **line**: line number (if determinable)
- **authRequired**: whether the page requires authentication (look for middleware, guards, decorators)
- **description**: brief description of what this page shows
- **pentestObjectives**: specific testing goals, e.g.:
  - "Test for XSS in user-editable fields on the profile page"
  - "Test for authorization bypass — access admin dashboard as regular user"
  - "Test for CSRF on the settings update form"

Be thorough — examine every route file, every page directory, every template.
When finished, call the \`response\` tool with your structured findings.`;
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

### For each endpoint, provide
- **method**: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
- **path**: the route path (e.g. /api/users/:id, /api/orders)
- **handler**: the handler function name (if identifiable)
- **file**: the file where this endpoint is defined
- **line**: line number (if determinable)
- **authRequired**: whether the endpoint requires authentication (look for auth middleware, decorators, guards)
- **description**: brief description of what this endpoint does
- **pentestObjectives**: specific testing goals, e.g.:
  - "Test for SQL injection in the 'search' query parameter"
  - "Test for IDOR by accessing /api/orders/{id} with other users' order IDs"
  - "Test for privilege escalation by calling admin-only endpoint as regular user"
  - "Test for mass assignment by sending extra fields in the POST body"
  - "Test for rate limiting on the login endpoint"

Be thorough — trace through all route registrations, middleware chains, and controller files.
When finished, call the \`response\` tool with your structured findings.`;
}
