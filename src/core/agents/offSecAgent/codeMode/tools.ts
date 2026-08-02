import { openai } from "@ai-sdk/openai";
import { type ModelMessage, type Tool, type ToolSet, tool } from "ai";
import { z } from "zod";
import type { AgentToolProtocol } from "../../../ai";
import type { CodeCellResult, CodeModeRuntime } from "./runtime";

/** Built-in lifecycle, persistence, interaction, and evidence contracts. */
export const CODE_MODE_DIRECT_TOOL_NAMES = [
  "response",
  "document_vulnerability",
  "document_app",
  "document_endpoint",
  "checkpoint_state",
  "browser_screenshot",
  "ask_user_questions",
  "report_error",
  "complete_authentication",
  "create_attack_surface_report",
  "provide_comparison_results",
  "submit_results",
  "submit_plan",
] as const;

const EXEC_DESCRIPTION = `Execute JavaScript in Apex's isolated orchestration runtime. Treat each exec as a bounded stage. The shell and browser are stateful, single-lane capabilities: never call them with Promise.all or mapLimit. For concurrent requests or scans, write one Python, JavaScript, or shell program in the persistent session workspace and invoke it once with tools.shell. Shell calls default to a 120-second timeout; set an explicit timeout only when chosen work needs longer. Use mapLimit only for independent, concurrency-safe capabilities. The runtime has no direct filesystem or network access, so effects go through the global tools object. Use text(value) to return selected evidence, and store/load for compact state across cells. Long-running cells return a cellId for wait.`;

type ExecutionOptions = {
  toolCallId: string;
  messages: ModelMessage[];
  abortSignal?: AbortSignal;
};

function serializeCellResult(result: CodeCellResult): string {
  return JSON.stringify(result);
}

function executeCode(
  runtime: CodeModeRuntime,
  code: string,
  options: ExecutionOptions,
  yieldTimeMs?: number,
): Promise<string> {
  return runtime
    .execute(
      code,
      {
        parentToolCallId: options.toolCallId,
        messages: options.messages,
        abortSignal: options.abortSignal,
      },
      yieldTimeMs,
    )
    .then(serializeCellResult);
}

/** Build the deliberately small model-facing tool surface for code mode. */
export function createCodeModeTools(
  protocol: Exclude<AgentToolProtocol, "direct">,
  runtime: CodeModeRuntime,
  canonicalTools: ToolSet,
  directToolNames: Iterable<string>,
): ToolSet {
  const schemaExec = tool({
    description: EXEC_DESCRIPTION,
    inputSchema: z.object({
      code: z.string().min(1).describe("JavaScript source to execute"),
      yield_time_ms: z
        .number()
        .int()
        .min(0)
        .max(60_000)
        .optional()
        .describe("How long to wait before yielding a resumable cellId"),
    }),
    execute: ({ code, yield_time_ms }, options) =>
      executeCode(runtime, code, options, yield_time_ms),
  });

  const nativeExec = {
    ...openai.tools.customTool({
      name: "exec",
      description: EXEC_DESCRIPTION,
      format: { type: "text" },
    }),
    execute: (code: string, options: ExecutionOptions) =>
      executeCode(runtime, code, options),
  } as Tool<string, string>;

  const wait = tool({
    description:
      "Resume a running exec cell, or terminate it. Call only with a cellId returned by exec or wait.",
    inputSchema: z.object({
      cell_id: z.string().min(1),
      yield_time_ms: z.number().int().min(0).max(60_000).optional(),
      terminate: z.boolean().optional(),
    }),
    execute: ({ cell_id, yield_time_ms, terminate }) =>
      runtime
        .wait(cell_id, { yieldTimeMs: yield_time_ms, terminate })
        .then(serializeCellResult),
  });

  const presented: ToolSet = {
    exec: protocol === "native-code" ? nativeExec : schemaExec,
    wait,
  };

  // Console contract tools remain first-class for every provider. This keeps
  // their exact schemas visible to the model and preserves stop conditions,
  // audit events, and UI rendering while still collapsing the broad action
  // surface behind exec.
  for (const name of directToolNames) {
    if (canonicalTools[name]) presented[name] = canonicalTools[name];
  }

  return presented;
}

export function buildCodeModeInstructions(
  _protocol: Exclude<AgentToolProtocol, "direct">,
): string {
  return `

## Code execution interface

You have a compact code-oriented interface. Prefer writing JavaScript in exec to compose work over issuing repetitive one-off calls. The exec runtime is isolated: it has no direct filesystem, process, or network APIs. All effects go through governed nested capabilities.

Available globals inside exec:
- tools.shell({ toolCallDescription, command, timeout?, allow_unprotected? })
- tools.call(name, input) for any allowed capability listed in ALL_TOOLS
- tools.browser.navigate({ url, toolCallDescription })
- tools.browser.runCode({ code, toolCallDescription }) for multi-step async (page) => { ... } Playwright programs on the managed Camoufox page
- tools.browser.snapshot({ toolCallDescription })
- tools.browser.click({ element, ref?, toolCallDescription })
- tools.browser.fill({ element, ref?, value, toolCallDescription })
- tools.browser.evaluate({ script, toolCallDescription })
- tools.browser.console({ toolCallDescription })
- tools.browser.getCookies({ urls?, toolCallDescription })
- text(value) to return intermediate output; store(key, value) and load(key) across cells
- mapLimit(items, concurrency, worker) for bounded fail-fast concurrency across concurrency-safe capabilities
- mapLimitSettled(items, concurrency, worker) for bounded concurrency across concurrency-safe capabilities when partial results are useful

Nested capability declarations:

\`\`\`ts
type ShellInput = {
  toolCallDescription: string;
  command: string;
  timeout?: number; // defaults to 120 seconds in code mode
  allow_unprotected?: boolean;
};
declare const tools: {
  shell(input: ShellInput): Promise<unknown>;
  call(name: string, input: unknown): Promise<unknown>;
  browser: {
    runCode(input: { code: string; toolCallDescription: string }): Promise<unknown>;
    navigate(input: { url: string; toolCallDescription: string }): Promise<unknown>;
    snapshot(input: { toolCallDescription: string }): Promise<unknown>;
    click(input: { element: string; ref?: string; toolCallDescription: string }): Promise<unknown>;
    fill(input: { element: string; ref?: string; value: string; toolCallDescription: string }): Promise<unknown>;
    evaluate(input: { script: string; toolCallDescription: string }): Promise<unknown>;
    console(input: { toolCallDescription: string }): Promise<unknown>;
    getCookies(input: { urls?: string[]; toolCallDescription: string }): Promise<unknown>;
  };
};
declare function mapLimit<T, R>(items: T[], concurrency: number, worker: (item: T, index: number) => Promise<R>): Promise<R[]>;
declare function mapLimitSettled<T, R>(items: T[], concurrency: number, worker: (item: T, index: number) => Promise<R>): Promise<PromiseSettledResult<R>[]>;
\`\`\`

Program-first execution policy:
1. \`tools.shell\` and \`execute_command\` share one persistent, single-lane shell. Call them at most once at a time and never wrap them in Promise.all, mapLimit, or mapLimitSettled. Omitted timeouts default to 120 seconds so one command cannot monopolize the shell.
2. Put concurrent HTTP requests, scans, payload generation, and result filtering inside one Python, JavaScript, or shell program in the persistent session workspace, then run that program with one shell call. Reuse the program as the exploit evolves.
   Every program inherits APEX_EXECUTION_POLICY_JSON. Parse it, declare an explicit concurrency, and apply its requests-per-second, burst, concurrency, destructive-action, and availability-impact limits before issuing target traffic. Preflight enforcement inspects referenced Bun, Python, and shell source before launch.
3. Browser operations and Console contract tools are stateful and single-lane. Await them sequentially.
4. Persist tokens, identifiers, attempted hypotheses, and useful artifacts once. Do not paste or reconstruct the same state in later cells.
5. Use mapLimit only for independent capabilities that are explicitly safe to invoke concurrently. Parallelism is for executing a chosen experiment faster, not for expanding reconnaissance scope.
6. When APEX_OAST_HTTP_BASE_URL and APEX_OAST_HTTP_PORT are present in the shell environment, they are the engagement's isolated HTTP callback ingress. Write your own correlated listener on 0.0.0.0:$APEX_OAST_HTTP_PORT and use the base URL in payloads. Do not send target data or synthetic flags to third-party callback services.

Example program-first stage:

\`\`\`js
const result = await tools.shell({
  toolCallDescription: "Run the reusable bounded probe program",
  command: "python3 probe.py",
  timeout: 60,
});
text(result);
\`\`\`

Use wait when exec returns status "running". Inspect the metrics and any guidance returned with each completed cell. Guidance is process feedback from the harness, not target evidence. A submitted response is terminal.

Use the top-level lifecycle, finding, checkpoint, interaction, and evidence tools for their normal Console contracts and exact schemas. Do not simulate those calls in prose. Prefer Bun for JavaScript/TypeScript programs and \`uv run\` or \`uvx\` for Python dependencies. Use \`browser_run_code\` inside exec for multi-step browser automation against Apex's managed Camoufox session; use the top-level \`browser_screenshot\` tool for durable Console evidence.`;
}
