// --live makes paid API calls; see docs/bounded-tool-output.md for methodology.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { generateText, stepCountIs, type Tool, type ToolSet, tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../src/core/agents/offSecAgent/tools/types";

const MAX_STEPS = 8;
type ToolResultOutput = Awaited<ReturnType<NonNullable<Tool["toModelOutput"]>>>;
const MAX_OUTPUT_TOKENS = 4096;
const REFERENCE_RE =
  /tool-output:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
const DISCLAIMER =
  "Evidence-retrieval benchmark for bounded tool output; NOT a measure of general pentest success.";
const SYSTEM_PROMPT = `You are assisting with a benign evidence-retrieval benchmark; no real systems or targets are involved. A single harmless fixture shell command was executed earlier by the execute_command tool and its output was captured. Recover the EVIDENCE_TOKEN (a string beginning with EVIDENCE_TOKEN_) embedded in that captured output and report the command's observed exit status. You may re-issue exactly the fixture command given below through execute_command to receive the captured result — the harness replays the capture and does not re-execute it; any other command is rejected. You may also use read_file and grep to inspect retained captured evidence. Finish your final message with a line of exactly this form: RESULT: token=<token> exit=<integer>`;

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    baseline: { type: "string" },
    candidate: { type: "string" },
    output: { type: "string" },
    seed: { type: "string", default: "apex-bounded-tool-output" },
    reps: { type: "string", default: "5" },
    live: { type: "boolean", default: false },
    repetitions: { type: "string", default: "3" },
    model: { type: "string", default: "z-ai/glm-5.3" },
    "run-timeout-ms": { type: "string", default: "180000" },
  },
  strict: true,
});

function fail(message: string): never {
  throw new Error(message);
}

function intArg(
  raw: string | undefined,
  min: number,
  max: number,
  name: string,
): number {
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    fail(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

if (!values.baseline || !values.candidate || !values.output) {
  fail("--baseline, --candidate and --output are required");
}
const baselinePath = resolve(values.baseline);
const candidatePath = resolve(values.candidate);
const outputPath = resolve(values.output);
const reps = intArg(values.reps, 1, 100, "--reps");
const repetitions = values.live
  ? intArg(values.repetitions, 1, 10, "--repetitions")
  : 0;
const runTimeoutMs = intArg(
  values["run-timeout-ms"],
  1000,
  600000,
  "--run-timeout-ms",
);
const modelId = values.model ?? "z-ai/glm-5.3";
if (values.live && !process.env.OPENROUTER_API_KEY) {
  fail("--live requires OPENROUTER_API_KEY in the environment");
}

function mulberry32(seedValue: number): () => number {
  let a = seedValue >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const seedUInt32 = (seed: string): number =>
  createHash("sha256").update(seed).digest().readUInt32BE(0);

const sha256 = (value: string): string =>
  createHash("sha256").update(value).digest("hex");

function hexToken(rng: () => number, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += Math.floor(rng() * 16).toString(16);
  return out;
}

function gitInfo(checkout: string): {
  sha: string | null;
  dirtyFiles: string[];
} {
  try {
    const sha = execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
    const status = execFileSync(
      "git",
      ["-C", checkout, "status", "--porcelain"],
      { encoding: "utf8" },
    );
    return {
      sha,
      dirtyFiles: status
        .split("\n")
        .filter(Boolean)
        .map((line) => line.slice(3))
        .slice(0, 100),
    };
  } catch {
    return { sha: null, dirtyFiles: [] };
  }
}

type ExecTool = {
  description: string;
  execute: (
    input: Record<string, unknown>,
    options: { toolCallId: string; messages: unknown[] },
  ) => Promise<Record<string, unknown>>;
  toModelOutput?: (options: {
    toolCallId: string;
    input: unknown;
    output: unknown;
  }) => unknown;
};

type SimpleTool = {
  execute: (
    input: Record<string, unknown>,
    options: { toolCallId: string; messages: unknown[] },
  ) => Promise<Record<string, unknown>>;
};

type LoadedVariant = {
  label: "baseline" | "candidate";
  checkout: string;
  sha: string | null;
  dirtyFiles: string[];
  makeShell: (cwd: string) => { dispose: () => unknown };
  makeExecute: (ctx: ToolContext) => ExecTool;
  makeReadFile: (ctx: ToolContext) => SimpleTool;
  makeGrep: (ctx: ToolContext) => SimpleTool;
};

async function importFile(path: string): Promise<Record<string, unknown>> {
  return (await import(pathToFileURL(path).href)) as Record<string, unknown>;
}

async function loadVariant(
  label: "baseline" | "candidate",
  checkout: string,
): Promise<LoadedVariant> {
  const toolsDir = join(checkout, "src/core/agents/offSecAgent/tools");
  const [execMod, readMod, grepMod, shellMod] = await Promise.all([
    importFile(join(toolsDir, "executeCommand.ts")),
    importFile(join(toolsDir, "readFile.ts")),
    importFile(join(toolsDir, "grep.ts")),
    importFile(join(toolsDir, "perCommandShell.ts")),
  ]);
  if (typeof execMod.executeCommand !== "function") {
    fail(`${checkout}: executeCommand export missing`);
  }
  if (typeof readMod.readFile !== "function") {
    fail(`${checkout}: readFile export missing`);
  }
  if (typeof grepMod.grep !== "function") {
    fail(`${checkout}: grep export missing`);
  }
  if (typeof shellMod.PerCommandShell !== "function") {
    fail(`${checkout}: PerCommandShell export missing`);
  }
  const { sha, dirtyFiles } = gitInfo(checkout);
  const makeExecute = execMod.executeCommand as unknown as (
    ctx: ToolContext,
  ) => ExecTool;
  const makeReadFile = readMod.readFile as unknown as (
    ctx: ToolContext,
  ) => SimpleTool;
  const makeGrep = grepMod.grep as unknown as (ctx: ToolContext) => SimpleTool;
  return {
    label,
    checkout,
    sha,
    dirtyFiles,
    makeShell: (cwd) =>
      new (
        shellMod.PerCommandShell as unknown as new (opts?: {
          cwd?: string;
        }) => { dispose: () => unknown }
      )({ cwd }),
    makeExecute,
    makeReadFile,
    makeGrep,
  };
}

const tempRoots: string[] = [];

async function makeBenchCtx(
  variant: LoadedVariant,
  tag: string,
): Promise<{ ctx: ToolContext; shell: { dispose: () => unknown } }> {
  const root = await mkdtemp(join(tmpdir(), `apex-tooloutput-${tag}-`));
  tempRoots.push(root);
  const shell = variant.makeShell(root);
  const session = {
    id: "ses_benchmark",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath: root,
    logsPath: join(root, "logs"),
    findingsPath: join(root, "findings"),
    scratchpadPath: join(root, "scratchpad"),
    pocsPath: join(root, "pocs"),
  };
  const ctx = {
    session,
    agentCwd: root,
    fileWorkspaceRoot: join(root, "workspace"),
    commandShell: shell,
  } as unknown as ToolContext;
  await mkdir(join(root, "workspace"), { recursive: true });
  return { ctx, shell };
}

const SCENARIO_KINDS = ["control", "stderr-120k", "stdout-6000-lines"] as const;
type ScenarioKind = (typeof SCENARIO_KINDS)[number];

type Scenario = {
  kind: ScenarioKind;
  command: string;
  token: string;
  expectedExit: number;
  stdoutBytes: number;
  stderrBytes: number;
  stdoutLines: number;
  stderrLines: number;
};

const shellQuote = (value: string): string =>
  `'${value.replaceAll("'", "'\\''")}'`;

async function buildScenario(
  kind: ScenarioKind,
  rng: () => number,
  fixturesDir: string,
): Promise<Scenario> {
  const token = `EVIDENCE_TOKEN_${hexToken(rng, 12)}`;
  if (kind === "control") {
    const script = join(fixturesDir, `${kind}.sh`);
    await writeFile(script, `printf '${token}\\n'\nexit 0\n`);
    return {
      kind,
      command: `sh ${shellQuote(script)}`,
      token,
      expectedExit: 0,
      stdoutBytes: Buffer.byteLength(token) + 1,
      stderrBytes: 0,
      stdoutLines: 1,
      stderrLines: 0,
    };
  }
  if (kind === "stderr-120k") {
    const lineCount = 1900;
    const tokenLine = Math.floor(lineCount / 2);
    const lines: string[] = [];
    for (let i = 0; i < lineCount; i++) {
      lines.push(
        i === tokenLine
          ? token
          : `filler-${String(i).padStart(6, "0")}`.padEnd(64, "."),
      );
    }
    const data = `${lines.join("\n")}\n`;
    const dataPath = join(fixturesDir, `${kind}.data`);
    const script = join(fixturesDir, `${kind}.sh`);
    await writeFile(dataPath, data);
    await writeFile(script, `cat ${shellQuote(dataPath)} >&2\nexit 3\n`);
    return {
      kind,
      command: `sh ${shellQuote(script)}`,
      token,
      expectedExit: 3,
      stdoutBytes: 0,
      stderrBytes: Buffer.byteLength(data),
      stdoutLines: 0,
      stderrLines: lineCount,
    };
  }
  const lineCount = 6000;
  const tokenLine = Math.floor(lineCount / 2);
  const lines: string[] = [];
  for (let i = 0; i < lineCount; i++) {
    lines.push(i === tokenLine ? token : `e${String(i).padStart(6, "0")}`);
  }
  const data = `${lines.join("\n")}\n`;
  const dataPath = join(fixturesDir, "stdout-6000-lines.data");
  const script = join(fixturesDir, "stdout-6000-lines.sh");
  await writeFile(dataPath, data);
  await writeFile(script, `cat ${shellQuote(dataPath)}\nexit 5\n`);
  return {
    kind: "stdout-6000-lines",
    command: `sh ${shellQuote(script)}`,
    token,
    expectedExit: 5,
    stdoutBytes: Buffer.byteLength(data),
    stderrBytes: 0,
    stdoutLines: lineCount,
    stderrLines: 0,
  };
}

type Capture = {
  result: Record<string, unknown>;
  capturedBytes: number;
  capturedStdoutBytes: number;
  capturedStderrBytes: number;
  exitCodeReported: number | undefined;
  captureMs: number;
};

async function captureFixture(
  execTool: ExecTool,
  command: string,
  tag: string,
): Promise<Capture> {
  const input = {
    command,
    toolCallDescription: "benchmark fixture capture",
    timeout: 60,
  };
  const start = performance.now();
  const result = await execTool.execute(input, {
    toolCallId: `bench-capture-${tag}`,
    messages: [],
  });
  return {
    result,
    capturedBytes: Buffer.byteLength(JSON.stringify(result)),
    capturedStdoutBytes:
      typeof result.stdout === "string" ? Buffer.byteLength(result.stdout) : -1,
    capturedStderrBytes:
      typeof result.stderr === "string" ? Buffer.byteLength(result.stderr) : -1,
    exitCodeReported:
      typeof result.exitCode === "number" ? result.exitCode : undefined,
    captureMs: performance.now() - start,
  };
}

type Boundary = {
  kind: "toModelOutput" | "json-serialization";
  outputType: "json" | "text";
  latencyMedianMs: number;
  latencyP95Ms: number;
  visibleBytes: number;
  visibleLines: number;
  previewContainsToken: boolean;
  references: string[];
};

function percentile(sorted: number[], q: number): number {
  return sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)];
}

function visibleOf(visible: unknown): {
  outputType: "json" | "text";
  text: string;
} {
  if (typeof visible === "string") return { outputType: "json", text: visible };
  if (visible !== null && typeof visible === "object" && "type" in visible) {
    const record = visible as { type: unknown; value: unknown };
    if (record.type === "text" && typeof record.value === "string") {
      return { outputType: "text", text: record.value };
    }
    if (record.type === "json") {
      return { outputType: "json", text: JSON.stringify(record.value) };
    }
  }
  return { outputType: "json", text: JSON.stringify(visible) };
}

async function measureBoundary(
  execTool: ExecTool,
  input: Record<string, unknown>,
  result: Record<string, unknown>,
  token: string,
  boundaryReps: number,
): Promise<Boundary> {
  const hasBoundary = typeof execTool.toModelOutput === "function";
  const latencies: number[] = [];
  let visible: unknown;
  for (let i = 0; i < boundaryReps; i++) {
    const start = performance.now();
    // Without toModelOutput the SDK ships JSON.stringify(result) — that is the
    // baseline's real boundary cost.
    visible = hasBoundary
      ? await execTool.toModelOutput?.({
          toolCallId: `bench-boundary-${i}`,
          input,
          output: result,
        })
      : JSON.stringify(result);
    latencies.push(performance.now() - start);
  }
  const { outputType, text } = visibleOf(visible);
  const sorted = [...latencies].sort((a, b) => a - b);
  return {
    kind: hasBoundary ? "toModelOutput" : "json-serialization",
    outputType,
    latencyMedianMs: percentile(sorted, 0.5),
    latencyP95Ms: percentile(sorted, 0.95),
    visibleBytes: Buffer.byteLength(text),
    visibleLines: text === "" ? 0 : text.split("\n").length,
    previewContainsToken: text.includes(token),
    references: [...text.matchAll(REFERENCE_RE)].map((match) => match[0]),
  };
}

type Recovery = {
  reference: string | undefined;
  readFile: { recovered: boolean; pages: number } | null;
  grep: { recovered: boolean } | null;
  outputFileProbe: { reachable: boolean; tokenFound: boolean } | null;
};

async function recoverViaReadFile(
  readTool: SimpleTool,
  reference: string,
  token: string,
): Promise<{ recovered: boolean; pages: number }> {
  let startLine: number | undefined;
  for (let page = 1; page <= 80; page++) {
    const input: Record<string, unknown> = {
      path: reference,
      toolCallDescription: "benchmark evidence recovery",
    };
    if (startLine !== undefined) input.startLine = startLine;
    const res = await readTool.execute(input, {
      toolCallId: `bench-read-${page}`,
      messages: [],
    });
    if (res.success !== true) return { recovered: false, pages: page };
    const content = typeof res.content === "string" ? res.content : "";
    if (content.includes(token)) return { recovered: true, pages: page };
    // stoppedAtLine is the resume cursor; its absence (with totalLines set)
    // means EOF was reached without the token.
    if (typeof res.stoppedAtLine !== "number") {
      return { recovered: false, pages: page };
    }
    startLine = res.stoppedAtLine;
  }
  return { recovered: false, pages: 80 };
}

async function recoverViaGrep(
  grepTool: SimpleTool,
  reference: string,
  token: string,
): Promise<{ recovered: boolean }> {
  const res = await grepTool.execute(
    {
      pattern: token,
      directory: reference,
      flags: "-n",
      toolCallDescription: "benchmark evidence recovery",
    },
    { toolCallId: "bench-grep", messages: [] },
  );
  return {
    recovered:
      res.success === true &&
      typeof res.output === "string" &&
      res.output.includes(token),
  };
}

async function probeReadFile(
  readTool: SimpleTool,
  path: string,
  token: string,
): Promise<{ reachable: boolean; tokenFound: boolean }> {
  const res = await readTool.execute(
    { path, toolCallDescription: "benchmark evidence recovery" },
    { toolCallId: "bench-probe", messages: [] },
  );
  const content = typeof res.content === "string" ? res.content : "";
  return {
    reachable: res.success === true,
    tokenFound: content.includes(token),
  };
}

function pickUsage(usage: unknown): Record<string, number | undefined> {
  const record = (usage ?? {}) as Record<string, unknown>;
  const out: Record<string, number | undefined> = {};
  for (const key of [
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "reasoningTokens",
    "cachedInputTokens",
  ] as const) {
    const value = record[key];
    out[key] = typeof value === "number" ? value : undefined;
  }
  return out;
}

type WireUsage = {
  id?: string;
  provider?: string;
  model?: string;
  usage?: Record<string, string | number>;
};

function sanitizeUsage(
  raw: Record<string, unknown>,
): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "number" || typeof value === "string")
      out[key] = value;
  }
  return out;
}

function makeCollectingFetch(sink: WireUsage[]): typeof fetch {
  const collecting = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const response = await fetch(input, init);
    try {
      const parsed = (await response.clone().json()) as Record<string, unknown>;
      sink.push({
        id: typeof parsed.id === "string" ? parsed.id : undefined,
        provider:
          typeof parsed.provider === "string" ? parsed.provider : undefined,
        model: typeof parsed.model === "string" ? parsed.model : undefined,
        usage:
          typeof parsed.usage === "object" && parsed.usage !== null
            ? sanitizeUsage(parsed.usage as Record<string, unknown>)
            : undefined,
      });
    } catch {
      // Non-JSON responses have no billing evidence; never report them as free.
    }
    return response;
  };
  return collecting as unknown as typeof fetch;
}

type LiveRecord = {
  variant: "baseline" | "candidate";
  scenario: ScenarioKind;
  repetition: number;
  firstInPair: boolean;
  ok: boolean;
  error?: string;
  elapsedMs: number;
  steps: number;
  executeReplays: number;
  executeRejections: number;
  retrievalCalls: number;
  usage: Record<string, number | undefined>;
  wire: WireUsage[];
  tokenCorrect: boolean;
  exitCorrect: boolean;
  tokenReportedSha: string | undefined;
};

async function runLive(
  variant: LoadedVariant,
  ctx: ToolContext,
  scenario: Scenario,
  capture: Capture,
  repetition: number,
  firstInPair: boolean,
): Promise<LiveRecord> {
  const execTool = variant.makeExecute(ctx);
  const counters = { replays: 0, rejections: 0, steps: 0, retrievals: 0 };
  const completedUsage: Record<string, number> = {};
  const hasBoundary = typeof execTool.toModelOutput === "function";
  const wrapped = tool({
    description: `${execTool.description}\n\nBENCHMARK CONSTRAINT: this run permits exactly one command — the fixture command from the task. The harness replays its already-captured result and does not re-execute it; every other command is rejected.`,
    inputSchema: z.object({ command: z.string() }),
    execute: async (input: { command: string }) => {
      if (input.command.trim() === scenario.command && counters.replays === 0) {
        counters.replays++;
        return capture.result;
      }
      counters.rejections++;
      return {
        success: false,
        error:
          "Benchmark: the designated fixture may be issued only once. Inspect the existing capture with read_file or grep.",
        stdout: "",
        stderr: "",
        command: input.command,
      };
    },
    ...(hasBoundary
      ? {
          toModelOutput: (options: {
            toolCallId: string;
            input: unknown;
            output: unknown;
          }): Promise<ToolResultOutput> | ToolResultOutput =>
            execTool.toModelOutput?.(options) as
              | Promise<ToolResultOutput>
              | ToolResultOutput,
        }
      : {}),
  });
  const tools = {
    execute_command: wrapped,
    read_file: variant.makeReadFile(ctx),
    grep: variant.makeGrep(ctx),
  } as unknown as ToolSet;
  const wire: WireUsage[] = [];
  const provider = createOpenRouter({
    apiKey: process.env.OPENROUTER_API_KEY,
    compatibility: "strict",
    fetch: makeCollectingFetch(wire),
  });
  const start = performance.now();
  const base = {
    variant: variant.label,
    scenario: scenario.kind,
    repetition,
    firstInPair,
    executeReplays: counters.replays,
    executeRejections: counters.rejections,
    wire,
  };
  try {
    const result = await generateText({
      model: provider(modelId),
      system: SYSTEM_PROMPT,
      prompt: `The fixture command was: ${scenario.command}\nRecover the EVIDENCE_TOKEN and the observed exit status now.`,
      tools,
      maxOutputTokens: MAX_OUTPUT_TOKENS,
      maxRetries: 0,
      stopWhen: stepCountIs(MAX_STEPS),
      abortSignal: AbortSignal.timeout(runTimeoutMs),
      providerOptions:
        modelId === "z-ai/glm-5.3"
          ? {
              openrouter: {
                provider: { only: ["z-ai"], allow_fallbacks: false },
              },
            }
          : undefined,
      onStepFinish: (step) => {
        counters.steps++;
        counters.retrievals += step.toolCalls.filter(
          (call) => call.toolName === "read_file" || call.toolName === "grep",
        ).length;
        for (const [key, value] of Object.entries(pickUsage(step.usage))) {
          if (value !== undefined)
            completedUsage[key] = (completedUsage[key] ?? 0) + value;
        }
      },
    });
    const elapsedMs = performance.now() - start;
    const matches = [
      ...result.text.matchAll(/RESULT:\s*token=(\S+)\s+exit=(-?\d+)/g),
    ];
    const last = matches[matches.length - 1];
    return {
      ...base,
      ok: true,
      elapsedMs,
      steps: result.steps.length,
      executeReplays: counters.replays,
      executeRejections: counters.rejections,
      retrievalCalls: counters.retrievals,
      usage: pickUsage(result.totalUsage),
      tokenCorrect: last ? last[1] === scenario.token : false,
      exitCorrect: last ? Number(last[2]) === scenario.expectedExit : false,
      tokenReportedSha: last ? sha256(last[1]) : undefined,
    };
  } catch (error) {
    return {
      ...base,
      ok: false,
      error: error instanceof Error ? error.name : "UnknownError",
      elapsedMs: performance.now() - start,
      steps: counters.steps,
      executeReplays: counters.replays,
      executeRejections: counters.rejections,
      retrievalCalls: counters.retrievals,
      usage: completedUsage,
      tokenCorrect: false,
      exitCorrect: false,
      tokenReportedSha: undefined,
    };
  }
}

function medianOf(list: number[]): number | undefined {
  if (list.length === 0) return undefined;
  const sorted = [...list].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function runCost(record: LiveRecord): number | undefined {
  if (
    !record.ok ||
    record.wire.length === 0 ||
    record.wire.some((entry) => typeof entry.usage?.cost !== "number")
  )
    return undefined;
  return record.wire.reduce((sum, entry) => sum + Number(entry.usage?.cost), 0);
}

function assertSanitized(serialized: string): void {
  const key = process.env.OPENROUTER_API_KEY;
  if (key && serialized.includes(key)) {
    fail("refusing to write: report contains the API key");
  }
  if (serialized.includes("EVIDENCE_TOKEN_")) {
    fail("refusing to write: report contains fixture token material");
  }
  if (serialized.includes("You are assisting")) {
    fail("refusing to write: report contains prompt text");
  }
}

async function main(): Promise<void> {
  const variants: LoadedVariant[] = [
    await loadVariant("baseline", baselinePath),
    await loadVariant("candidate", candidatePath),
  ];
  if (baselinePath === candidatePath) {
    console.error(
      "warning: --baseline and --candidate point at the same checkout",
    );
  }
  const fixturesDir = await mkdtemp(
    join(tmpdir(), "apex-tooloutput-fixtures-"),
  );
  tempRoots.push(fixturesDir);

  type OfflineRecord = {
    variant: "baseline" | "candidate";
    scenario: ScenarioKind;
    capturedBytes: number;
    capturedStdoutBytes: number;
    capturedStderrBytes: number;
    exitCodeReported: number | undefined;
    captureMs: number;
    boundary: Boundary;
    recovery: Recovery;
  };
  const offline: OfflineRecord[] = [];
  for (const kind of SCENARIO_KINDS) {
    const scenario = await buildScenario(
      kind,
      mulberry32(seedUInt32(`${values.seed}:${kind}:offline`)),
      fixturesDir,
    );
    for (const variant of variants) {
      const { ctx, shell } = await makeBenchCtx(
        variant,
        `${kind}-${variant.label}-offline`,
      );
      try {
        const execTool = variant.makeExecute(ctx);
        const capture = await captureFixture(
          execTool,
          scenario.command,
          `${kind}-${variant.label}`,
        );
        const boundary = await measureBoundary(
          execTool,
          {
            command: scenario.command,
            toolCallDescription: "benchmark fixture capture",
            timeout: 60,
          },
          capture.result,
          scenario.token,
          reps,
        );
        const reference = boundary.references[0];
        const recovery: Recovery = {
          reference,
          readFile: null,
          grep: null,
          outputFileProbe: null,
        };
        if (reference) {
          recovery.readFile = await recoverViaReadFile(
            variant.makeReadFile(ctx),
            reference,
            scenario.token,
          );
          recovery.grep = await recoverViaGrep(
            variant.makeGrep(ctx),
            reference,
            scenario.token,
          );
        }
        if (typeof capture.result.outputFile === "string") {
          recovery.outputFileProbe = await probeReadFile(
            variant.makeReadFile(ctx),
            capture.result.outputFile,
            scenario.token,
          );
        }
        offline.push({
          variant: variant.label,
          scenario: kind,
          capturedBytes: capture.capturedBytes,
          capturedStdoutBytes: capture.capturedStdoutBytes,
          capturedStderrBytes: capture.capturedStderrBytes,
          exitCodeReported: capture.exitCodeReported,
          captureMs: capture.captureMs,
          boundary,
          recovery,
        });
        console.log(
          `[offline] ${variant.label} ${kind}: visible=${boundary.visibleBytes}B/${boundary.visibleLines}L (${boundary.kind}) read=${recovery.readFile?.recovered ?? "-"} grep=${recovery.grep?.recovered ?? "-"}`,
        );
      } finally {
        await Promise.resolve(shell.dispose());
      }
    }
  }

  const live: LiveRecord[] = [];
  if (values.live) {
    for (let repetition = 1; repetition <= repetitions; repetition++) {
      for (const kind of SCENARIO_KINDS) {
        const scenario = await buildScenario(
          kind,
          mulberry32(seedUInt32(`${values.seed}:${kind}:rep-${repetition}`)),
          fixturesDir,
        );
        const order =
          repetition % 2 === 1 ? variants : [variants[1], variants[0]];
        for (const [index, variant] of order.entries()) {
          const { ctx, shell } = await makeBenchCtx(
            variant,
            `${kind}-${variant.label}-r${repetition}`,
          );
          try {
            const execTool = variant.makeExecute(ctx);
            const capture = await captureFixture(
              execTool,
              scenario.command,
              `live-${kind}-${variant.label}-r${repetition}`,
            );
            const record = await runLive(
              variant,
              ctx,
              scenario,
              capture,
              repetition,
              index === 0,
            );
            live.push(record);
            const checkpoint = JSON.stringify({
              model: modelId,
              seed: values.seed,
              baselineSha: variants[0].sha,
              candidateSha: variants[1].sha,
              record,
            });
            assertSanitized(checkpoint);
            await appendFile(`${outputPath}.jsonl`, `${checkpoint}\n`);
            console.log(
              `[live] r${repetition} ${variant.label} ${kind}: token=${record.tokenCorrect} exit=${record.exitCorrect} input=${record.usage.inputTokens ?? "unknown"} cost=${runCost(record) ?? "unknown"} elapsed=${Math.round(record.elapsedMs)}ms`,
            );
          } finally {
            await Promise.resolve(shell.dispose());
          }
        }
      }
    }
  }

  const liveSummary: Array<Record<string, unknown>> = [];
  for (const variant of variants) {
    for (const kind of SCENARIO_KINDS) {
      const runs = live.filter(
        (record) =>
          record.variant === variant.label && record.scenario === kind,
      );
      if (runs.length === 0) continue;
      liveSummary.push({
        variant: variant.label,
        scenario: kind,
        runs: runs.length,
        okRuns: runs.filter((record) => record.ok).length,
        tokenCorrect: runs.filter((record) => record.tokenCorrect).length,
        exitCorrect: runs.filter((record) => record.exitCorrect).length,
        medianElapsedMs: medianOf(runs.map((record) => record.elapsedMs)),
        medianSteps: medianOf(runs.map((record) => record.steps)),
        medianInputTokens: medianOf(
          runs
            .map((record) => record.usage.inputTokens)
            .filter((value): value is number => typeof value === "number"),
        ),
        medianOutputTokens: medianOf(
          runs
            .map((record) => record.usage.outputTokens)
            .filter((value): value is number => typeof value === "number"),
        ),
        costReportedRuns: runs.filter((record) => runCost(record) !== undefined)
          .length,
        medianCostUsd: medianOf(
          runs
            .map(runCost)
            .filter((value): value is number => value !== undefined),
        ),
        medianRetrievalCalls: medianOf(
          runs.map((record) => record.retrievalCalls),
        ),
      });
    }
  }

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    benchmark: "bounded-tool-output",
    disclaimer: DISCLAIMER,
    mode: values.live ? "live" : "offline",
    model: values.live ? modelId : undefined,
    seed: values.seed,
    offlineReps: reps,
    liveRepetitions: repetitions || undefined,
    maxSteps: MAX_STEPS,
    maxOutputTokens: MAX_OUTPUT_TOKENS,
    runTimeoutMs,
    openRouterKeyPresent: Boolean(process.env.OPENROUTER_API_KEY),
    variants: variants.map((variant) => ({
      label: variant.label,
      checkout: variant.checkout,
      sha: variant.sha,
      dirty: variant.dirtyFiles.length > 0,
      dirtyFiles: variant.dirtyFiles,
    })),
    offline,
    live,
    liveSummary,
  };
  const serialized = JSON.stringify(report, null, 2);
  assertSanitized(serialized);
  await writeFile(outputPath, serialized);
  console.log(`wrote ${outputPath}`);
  console.log(DISCLAIMER);
}

try {
  await main();
} finally {
  await Promise.allSettled(
    tempRoots.map((root) => rm(root, { recursive: true, force: true })),
  );
}
