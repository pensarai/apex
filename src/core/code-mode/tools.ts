import { openai } from "@ai-sdk/openai";
import { type ModelMessage, type Tool, type ToolSet, tool } from "ai";
import { z } from "zod";
import type { AgentToolProtocol } from "../ai";
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

const EXEC_DESCRIPTION = `Prefer exec for predictable tool orchestration and processing intermediate results when it reduces model round trips or unnecessary output. Use direct tools for standalone operations, when a native command or script handles the work naturally, or when the next step requires fresh model judgment. Do not wrap a call solely to use exec. Execute JavaScript in Apex's isolated QuickJS runtime; perform coordination and result processing directly in the cell, keep intermediate results there, and return relevant evidence with text(value). Use execute_command for native programs, installed libraries, services, and file processing. Compose available capabilities with tools.call(name, input); inspect ALL_TOOLS and tools.describe(name) for names and schemas. The runtime has no direct filesystem, process, or network APIs, so use provided capabilities for those effects. Use mapLimit only for independent, concurrency-safe capabilities within the engagement's rate limits; await shell commands and workspace writes sequentially. Use store/load for compact state across cells. Long-running cells return a cellId for wait.`;

type ExecutionOptions = {
  toolCallId: string;
  messages: ModelMessage[];
  abortSignal?: AbortSignal;
  experimental_context?: unknown;
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
        experimental_context: options.experimental_context,
      },
      yieldTimeMs,
    )
    .then(serializeCellResult);
}

export function resolveCodeModeToolPresentation(input: {
  activeTools: string[];
  extraTools?: string[];
  directTools?: string[];
  nestedTools?: string[];
}): { direct: string[]; nested: string[] } {
  const nested = new Set(input.nestedTools ?? []);
  const explicitDirect = new Set([
    ...CODE_MODE_DIRECT_TOOL_NAMES,
    ...(input.directTools ?? []),
  ]);
  for (const name of nested) {
    if (!input.extraTools?.includes(name) || explicitDirect.has(name)) {
      throw new Error(`Cannot present ${name} as a nested workflow tool`);
    }
  }
  const directOnly = new Set([
    ...explicitDirect,
    ...(input.extraTools ?? []).filter((name) => !nested.has(name)),
  ]);
  return {
    // Explicitly nested tools named exec/wait cannot replace the runtime tools.
    direct: input.activeTools.filter(
      (name) => !nested.has(name) || (name !== "exec" && name !== "wait"),
    ),
    nested: input.activeTools.filter((name) => !directOnly.has(name)),
  };
}

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
    execute: ({ cell_id, yield_time_ms, terminate }, options) =>
      runtime
        .wait(cell_id, {
          yieldTimeMs: yield_time_ms,
          terminate,
          abortSignal: options.abortSignal,
        })
        .then(serializeCellResult),
  });

  const presented: ToolSet = {
    exec: protocol === "native-code" ? nativeExec : schemaExec,
    wait,
  };

  // Contract schemas and stop conditions must survive the presentation change.
  for (const name of directToolNames) {
    if (!Object.hasOwn(canonicalTools, name)) continue;
    if (name === "exec" || name === "wait") {
      throw new Error(
        `${name} is reserved by code mode; present the injected tool as nested`,
      );
    }
    Object.defineProperty(presented, name, {
      value: canonicalTools[name],
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }

  return presented;
}

export function buildCodeModeInstructions(
  _protocol: Exclude<AgentToolProtocol, "direct">,
): string {
  return `

## Code execution interface

Prefer exec for predictable tool orchestration and processing intermediate results when it reduces model round trips or unnecessary output. Use direct tools for standalone operations, when a native command or script handles the work naturally, or when the next step requires fresh model judgment. Do not wrap a call solely to use exec. Within exec, keep intermediate results in the cell, inspect them before dependent calls, and return relevant evidence with text. Your ordinary tools remain available directly alongside exec and wait.

For workflows that benefit from exec, write JavaScript directly in exec cells to compose provided tools, generate payloads, parse responses, and compare results. The isolated QuickJS runtime has no direct filesystem, process, or network APIs; use available nested capabilities for those effects. Each cell has fresh globals; only explicitly stored state survives across cells.

Available globals inside exec:
- ALL_TOOLS, the exact allowed nested capability names for this run
- tools.describe(name), which returns one allowed capability's description and exact input JSON Schema without executing it
- tools.call(name, input) for any allowed capability listed in ALL_TOOLS
- tools.browser.navigate({ url, toolCallDescription })
- tools.browser.snapshot({ toolCallDescription })
- tools.browser.click({ element, ref?, toolCallDescription })
- tools.browser.fill({ element, ref?, value, toolCallDescription })
- tools.browser.evaluate({ script, toolCallDescription })
- tools.browser.console({ toolCallDescription })
- tools.browser.getCookies({ urls?, toolCallDescription })
- text(value) to return intermediate output; store(key, value) and load(key) across cells for compact state only (1,000,000 serialized characters per value and per-cell load budget); page and persist larger artifacts with governed file tools
- Buffer, btoa/atob, sleep(ms), and setTimeout for bounded encoding and delays; require supports only "buffer" and "timers/promises"
- mapLimit(items, concurrency, worker) for bounded fail-fast concurrency across concurrency-safe capabilities
- mapLimitSettled(items, concurrency, worker) for bounded concurrency across concurrency-safe capabilities when partial results are useful
- completed and failed exec/wait results include evidence entries with the exact nested toolCallId and toolName; cite those values verbatim when another tool requests trace-linked evidence

Nested capability declarations:

\`\`\`ts
declare const tools: {
  describe(name: string): Promise<{ name: string; description?: string; inputSchema: unknown }>;
  call(name: string, input: unknown): Promise<unknown>;
  browser: {
    navigate(input: { url: string; toolCallDescription: string }): Promise<unknown>;
    snapshot(input: { toolCallDescription: string }): Promise<unknown>;
    click(input: { element: string; ref?: string; toolCallDescription: string }): Promise<unknown>;
    fill(input: { element: string; ref?: string; value: string; toolCallDescription: string }): Promise<unknown>;
    evaluate(input: { script: string; toolCallDescription: string }): Promise<unknown>;
    console(input: { toolCallDescription: string }): Promise<unknown>;
    getCookies(input: { urls?: string[]; toolCallDescription: string }): Promise<unknown>;
  };
};
declare const ALL_TOOLS: readonly string[];
declare function mapLimit<T, R>(items: T[], concurrency: number, worker: (item: T, index: number) => Promise<R>): Promise<R[]>;
declare function mapLimitSettled<T, R>(items: T[], concurrency: number, worker: (item: T, index: number) => Promise<R>): Promise<PromiseSettledResult<R>[]>;
declare const Buffer: {
  from(value: string | number[] | Uint8Array, encoding?: "utf8" | "base64" | "hex"): Uint8Array & { toString(encoding?: "utf8" | "base64" | "hex"): string };
};
declare function btoa(value: string): string;
declare function atob(value: string): string;
declare function sleep(ms: number): Promise<void>;
declare function setTimeout(callback: (...args: unknown[]) => void, ms: number, ...args: unknown[]): Promise<void>;
declare function require(name: "buffer"): { Buffer: typeof Buffer };
declare function require(name: "timers/promises"): { setTimeout: typeof sleep };
\`\`\`

Execution policy:
1. Inspect ALL_TOOLS once before coordinating nested capabilities. Use its exact names; do not guess or probe capability names. Call tools.describe(name) before first use when a nested capability's input shape is not already available from its direct tool schema or these instructions.
2. For a single HTTP request, use http_request directly. For predictable composed HTTP tests that benefit from exec, call http_request from JavaScript loops or helper functions when it is available inside exec, and inspect its results in the cell. Use sleep for pacing and mapLimit for independent requests only when the engagement permits concurrency.
3. Use execute_command for native programs, installed libraries, services, and file processing. Call it directly when a native command or script handles the work naturally. Coordinate commands with tools.call("execute_command", input) inside exec when follow-up calls can be derived programmatically and grouping them reduces model round trips or unnecessary output. It is single-lane: await each command sequentially, including across direct calls and running cells. Each command runs in a fresh process; files persist in the session workspace. Omitted command timeouts inside exec default to 120 seconds. Write external scripts when they are task deliverables or fit the native workflow.
4. Browser operations and workspace writes are stateful and single-lane. Await them sequentially. Browser aliases require their corresponding browser_* capabilities in ALL_TOOLS.
5. Persist compact tokens, identifiers, and hypothesis state once. Do not reconstruct multi-megabyte artifacts through store/load; page them and maintain authoritative state with the governed file tools.
6. Use mapLimit only for independent capabilities that are explicitly safe to invoke concurrently. Parallelism is for executing a chosen experiment faster, not for expanding reconnaissance scope.

Example bounded HTTP stage, after checking that http_request is available and inspecting its schema. Replace the example origin and paths with approved targets:

\`\`\`js
const origin = "https://target.example";
const observations = [];
for (const path of ["/", "/api/config"]) {
  if (observations.length) await sleep(1000);
  const result = await tools.call("http_request", {
    url: origin + path,
    method: "GET",
    followRedirects: false,
    toolCallDescription: "Inspect response for " + path,
  });
  observations.push({ path, status: result.status, body: result.body.slice(0, 500) });
}
store("observations", observations);
text(observations);
\`\`\`

Example comparing two small text files in one cell, after checking read_file in ALL_TOOLS and its schema. Replace paths with the task's actual files; page truncated reads before drawing conclusions:

\`\`\`js
const paths = ["config/current.txt", "config/expected.txt"];
const contents = await mapLimit(paths, 2, async (path) => {
  const result = await tools.call("read_file", {
    path,
    toolCallDescription: "Read comparison input " + path,
  });
  if (!result.success) throw new Error(result.error);
  if (result.truncated) throw new Error("Page the remaining content of " + path);
  return result.content;
});
text({ paths, identical: contents[0] === contents[1] });
\`\`\`

Example sequencing workspace writes in one cell, after checking create_file in ALL_TOOLS and its schema. Replace the paths and contents with required task artifacts:

\`\`\`js
const artifacts = [
  { path: "scratchpad/input.txt", content: "example input" },
  { path: "scratchpad/expected.txt", content: "expected result" },
];
for (const artifact of artifacts) {
  const result = await tools.call("create_file", {
    ...artifact,
    toolCallDescription: "Write task artifact " + artifact.path,
  });
  if (!result.success) throw new Error(result.error);
  text({ path: result.path, success: result.success });
}
\`\`\`

Use wait when exec returns status "running". Inspect the metrics and any guidance returned with each completed cell. Guidance is process feedback from the harness, not target evidence. A submitted response is terminal.

Use the top-level lifecycle, finding, checkpoint, interaction, and evidence tools for their normal Console contracts and exact schemas. Do not simulate those calls in prose. Use the available tools.browser operations for managed browser automation and the top-level \`browser_screenshot\` tool for durable evidence.`;
}
