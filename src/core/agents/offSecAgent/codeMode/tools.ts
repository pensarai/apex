import { openai } from "@ai-sdk/openai";
import { type ModelMessage, type Tool, type ToolSet, tool } from "ai";
import { z } from "zod";
import type { AgentToolProtocol } from "../../../ai";
import type { CodeCellResult, CodeModeRuntime } from "./runtime";

export const CODE_MODE_NESTED_TOOL_NAMES = [
  "execute_command",
  "document_vulnerability",
  "checkpoint_state",
  "response",
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
] as const;

const CODE_MODE_CONTRACT_TOOL_NAMES = [
  "response",
  "document_vulnerability",
  "checkpoint_state",
] as const;

const EXEC_DESCRIPTION = `Execute JavaScript in Apex's isolated orchestration runtime. Treat each exec as a bounded stage: group independent calls whose inputs are already known with mapLimit, mapLimitSettled, Promise.all, or Promise.allSettled; keep calls sequential only when one result determines the next. The runtime has no direct filesystem or network access, so effects go through the global tools object. Prefer writing and reusing scripts in the persistent session workspace over issuing repetitive one-off shell calls. Use text(value) to return selected evidence, and store/load for compact state across cells. Long-running cells return a cellId for wait.`;

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
  for (const name of CODE_MODE_CONTRACT_TOOL_NAMES) {
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
- tools.browser.snapshot({ toolCallDescription })
- tools.browser.screenshot({ filename, toolCallDescription })
- tools.browser.click({ element, ref?, toolCallDescription })
- tools.browser.fill({ element, ref?, value, toolCallDescription })
- tools.browser.evaluate({ script, toolCallDescription })
- tools.browser.console({ toolCallDescription })
- tools.browser.getCookies({ urls?, toolCallDescription })
- tools.findings.document(input), tools.checkpoint.record(input), tools.response.submit(result)
- text(value) to return intermediate output; store(key, value) and load(key) across cells
- mapLimit(items, concurrency, worker) for bounded fail-fast concurrency
- mapLimitSettled(items, concurrency, worker) for bounded concurrency when partial results are useful

Nested capability declarations:

\`\`\`ts
type ShellInput = {
  toolCallDescription: string;
  command: string;
  timeout?: number;
  allow_unprotected?: boolean;
};
declare const tools: {
  shell(input: ShellInput): Promise<unknown>;
  call(name: string, input: unknown): Promise<unknown>;
  browser: {
    navigate(input: { url: string; toolCallDescription: string }): Promise<unknown>;
    snapshot(input: { toolCallDescription: string }): Promise<unknown>;
    screenshot(input: { filename: string; toolCallDescription: string }): Promise<unknown>;
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
1. Batch known independent probes into one bounded exec stage. Do not split them across outer tool calls.
2. Keep adaptive dependencies, waits, browser mutations, and conflicting writes sequential.
3. After a few one-off shell calls, consolidate the exploit into a Python, JavaScript, or shell program in the persistent session workspace and rerun that program as it evolves.
4. Persist tokens, identifiers, attempted hypotheses, and useful artifacts once. Do not paste or reconstruct the same state in later cells.
5. Parallelism is for executing a chosen experiment faster, not for expanding reconnaissance scope.

Example bounded stage:

\`\`\`js
const endpoints = ["/api/me", "/api/admin", "/api/health"];
const results = await mapLimitSettled(endpoints, 4, endpoint =>
  tools.shell({
    toolCallDescription: \`Probe \${endpoint}\`,
    command: \`curl -sS -i \"\${load("target")}\${endpoint}\"\`,
    timeout: 20,
  }),
);
text(results);
\`\`\`

Use wait when exec returns status "running". Inspect the metrics and any guidance returned with each completed cell. Guidance is process feedback from the harness, not target evidence. A submitted response is terminal.

Use the top-level response, document_vulnerability, and checkpoint_state tools for their normal Console contract and exact schemas. Do not simulate those calls in prose. The nested aliases remain available when composition inside exec is necessary.`;
}
