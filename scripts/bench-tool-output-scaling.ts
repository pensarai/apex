// --live makes paid calls; this measures retained-context retrieval, not pentest success.
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import {
  generateText,
  type ModelMessage,
  stepCountIs,
  type Tool,
  type ToolSet,
  tool,
} from "ai";
import { z } from "zod";
import type { ToolContext } from "../src/core/agents/offSecAgent/tools/types";

const MODEL = "z-ai/glm-5.3";
const OUTPUT_LIMIT = 2048;
const STEP_LIMIT = 12;
const PROFILES = { occasional: 8, frequent: 4 } as const;
type Profile = keyof typeof PROFILES;
type Label = "baseline" | "candidate";
type Output = Awaited<ReturnType<NonNullable<Tool["toModelOutput"]>>>;
type BenchTool = Tool & {
  execute: (
    input: Record<string, unknown>,
    options: { toolCallId: string; messages: ModelMessage[] },
  ) => Promise<Record<string, unknown>>;
};
type Variant = {
  label: Label;
  checkout: string;
  sha: string;
  dirty: string;
  execute: (ctx: ToolContext) => BenchTool;
  read: (ctx: ToolContext) => BenchTool;
  grep: (ctx: ToolContext) => BenchTool;
  shell: new (options: { cwd: string }) => { dispose: () => unknown };
};
type Fixture = {
  command: string;
  token: string;
  exit: number;
  kind: string;
  digest: string;
};
type Wire = {
  task: number;
  id?: string;
  provider?: string;
  httpStatus: number;
  elapsedMs: number;
  input?: number;
  cached?: number;
  output?: number;
  cost?: number;
};

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    baseline: { type: "string" },
    candidate: { type: "string" },
    output: { type: "string" },
    live: { type: "boolean", default: false },
    stages: { type: "string", default: "32" },
    repetitions: { type: "string", default: "3" },
    "start-repetition": { type: "string", default: "1" },
    profile: { type: "string" },
    seed: { type: "string", default: "apex-scaling-v1" },
    "budget-usd": { type: "string", default: "15" },
  },
});
if (!values.baseline || !values.candidate || !values.output)
  throw new Error("--baseline, --candidate and --output are required");
const stages = Number(values.stages);
const repetitions = Number(values.repetitions);
const startRepetition = Number(values["start-repetition"]);
if (
  !Number.isInteger(startRepetition) ||
  startRepetition < 1 ||
  startRepetition + repetitions - 1 > 10
)
  throw new Error("Invalid repetition range (1-10)");
if (values.profile && !Object.hasOwn(PROFILES, values.profile))
  throw new Error("--profile must be occasional or frequent");
const selectedProfiles: Profile[] = values.profile
  ? [values.profile as Profile]
  : ["occasional", "frequent"];
const budget = Number(values["budget-usd"]);
if (
  !Number.isInteger(stages) ||
  stages < 1 ||
  stages > 32 ||
  !Number.isInteger(repetitions) ||
  repetitions < 1 ||
  repetitions > 10 ||
  !Number.isFinite(budget) ||
  budget <= 0 ||
  budget > 50
)
  throw new Error(
    "Invalid stages (1-32), repetitions (1-10), or budget (0-50 USD)",
  );
if (values.live && !process.env.OPENROUTER_API_KEY)
  throw new Error("--live requires OPENROUTER_API_KEY");
const outputPath = resolve(values.output);
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const roots: string[] = [];
let spent = 0;
let reserved = 0;
let billingUnknown = false;
let budgetStopped = false;
const rates = { input: 0.0000014, cached: 0.00000026, output: 0.0000044 };

async function checkpoint(record: unknown) {
  const text = JSON.stringify(record);
  if (
    (process.env.OPENROUTER_API_KEY &&
      text.includes(process.env.OPENROUTER_API_KEY)) ||
    text.includes("EVIDENCE_TOKEN_")
  )
    throw new Error("Unsafe benchmark checkpoint");
  await appendFile(`${outputPath}.jsonl`, `${text}\n`);
}

async function loadVariant(label: Label, checkout: string): Promise<Variant> {
  const directory = join(checkout, "src/core/agents/offSecAgent/tools");
  const [execute, read, grep, shell] = await Promise.all(
    ["executeCommand", "readFile", "grep", "perCommandShell"].map(
      (name) => import(pathToFileURL(join(directory, `${name}.ts`)).href),
    ),
  );
  return {
    label,
    checkout,
    sha: execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim(),
    dirty: execFileSync("git", ["-C", checkout, "status", "--porcelain"], {
      encoding: "utf8",
    }).trim(),
    execute: execute.executeCommand,
    read: read.readFile,
    grep: grep.grep,
    shell: shell.PerCommandShell,
  };
}

async function setup(variant: Variant, profile: Profile, repetition: number) {
  const root = await mkdtemp(join(tmpdir(), "apex-scaling-"));
  roots.push(root);
  const shell = new variant.shell({ cwd: root });
  await mkdir(join(root, "workspace"));
  const ctx = {
    agentCwd: root,
    fileWorkspaceRoot: join(root, "workspace"),
    commandShell: shell,
    session: {
      id: "ses_scaling",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: root,
      logsPath: join(root, "logs"),
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
    },
  } as unknown as ToolContext;
  const fixtures: Fixture[] = [];
  for (let stage = 1; stage <= stages; stage++) {
    const token = `EVIDENCE_TOKEN_${sha256(`${values.seed}:${profile}:${repetition}:${stage}`).slice(0, 16)}`;
    const large = (stage - 1) % PROFILES[profile] === 0;
    const stderr =
      large && Math.floor((stage - 1) / PROFILES[profile]) % 2 === 0;
    const count = large ? (stderr ? 1900 : 6000) : 1;
    const data = `${Array.from({ length: count }, (_, i) => (i === Math.floor(count / 2) ? token : stderr ? `filler-${String(i).padStart(6, "0")}`.padEnd(64, ".") : `e${String(i).padStart(6, "0")}`)).join("\n")}\n`;
    const exit = large ? (stderr ? 3 : 5) : 0;
    await writeFile(join(root, `capture-${stage}.data`), data);
    await writeFile(
      join(root, `capture-${stage}.sh`),
      `cat capture-${stage}.data${stderr ? " >&2" : ""}\nexit ${exit}\n`,
    );
    fixtures.push({
      command: `sh capture-${stage}.sh`,
      token,
      exit,
      kind: large ? (stderr ? "stderr-120k" : "stdout-6000-lines") : "control",
      digest: sha256(data),
    });
  }
  return { root, shell, ctx, fixtures };
}

function metrics(wire: Wire[]) {
  const complete =
    wire.length > 0 &&
    wire.every((w) =>
      [w.input, w.cached, w.output, w.cost].every((n) => typeof n === "number"),
    );
  const input = wire.reduce((n, w) => n + (w.input ?? 0), 0);
  const cached = wire.reduce((n, w) => n + (w.cached ?? 0), 0);
  const output = wire.reduce((n, w) => n + (w.output ?? 0), 0);
  return {
    complete,
    calls: wire.length,
    input,
    cached,
    uncached: input - cached,
    output,
    reportedCost: wire.reduce((n, w) => n + (w.cost ?? 0), 0),
    billedCost: complete ? wire.reduce((n, w) => n + (w.cost ?? 0), 0) : null,
    modeledNoCacheCost: complete
      ? input * rates.input + output * rates.output
      : null,
    peakInput: Math.max(0, ...wire.map((w) => w.input ?? 0)),
    cacheRateReconciliationError: complete
      ? wire.reduce(
          (n, w) =>
            n +
            Math.abs(
              (w.cost ?? 0) -
                (((w.input ?? 0) - (w.cached ?? 0)) * rates.input +
                  (w.cached ?? 0) * rates.cached +
                  (w.output ?? 0) * rates.output),
            ),
          0,
        )
      : null,
  };
}

async function run(variant: Variant, profile: Profile, repetition: number) {
  const { shell, ctx, fixtures } = await setup(variant, profile, repetition);
  const runId = randomUUID();
  const identity = { variant: variant.label, profile, repetition, runId };
  const wire: Wire[] = [];
  let current = 0;
  let executed = false;
  let retrievals = 0;
  let rejected = 0;
  let visibleBytes = 0;
  let correct = 0;
  let recallCorrect = 0;
  const checkpoints: Record<string, unknown>[] = [];
  const calls: Array<{ task: number; tool: string; argumentSha: string }> = [];
  const rawExecute = variant.execute(ctx);
  const execute = tool({
    description: `${rawExecute.description}\nBenchmark: only the current task's exact command may execute, once. Use read_file or grep for retained evidence.`,
    inputSchema: z.object({ command: z.string() }),
    execute: async ({ command }) => {
      if (command.trim() !== fixtures[current - 1].command || executed) {
        rejected++;
        return {
          success: false,
          error:
            "Only the current fixture command may execute once; retrieve existing evidence with read_file or grep.",
          stdout: "",
          stderr: "",
          command,
        };
      }
      executed = true;
      return rawExecute.execute(
        {
          command,
          timeout: 60,
          toolCallDescription: "Collect benchmark evidence",
        },
        { toolCallId: `capture-${current}`, messages: [] },
      );
    },
    toModelOutput: async (options) => {
      const output: Output = rawExecute.toModelOutput
        ? await rawExecute.toModelOutput(options)
        : { type: "json", value: options.output as never };
      visibleBytes += Buffer.byteLength(
        output.type === "text" ? output.value : JSON.stringify(output),
      );
      return output;
    },
  });
  const tools = {
    execute_command: execute,
    read_file: variant.read(ctx),
    grep: variant.grep(ctx),
  } as ToolSet;
  const collectingFetch = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => {
    const request = JSON.parse(String(init?.body)) as {
      messages: unknown;
      tools: unknown;
      max_tokens?: number;
    };
    const reservation =
      (Buffer.byteLength(JSON.stringify(request)) + 10000) * rates.input +
      OUTPUT_LIMIT * rates.output;
    if (
      billingUnknown ||
      budgetStopped ||
      spent + reserved + reservation > budget
    ) {
      budgetStopped = true;
      const error = new Error(
        "No new requests allowed within the remaining budget",
      );
      error.name = "BenchmarkSpendLimit";
      throw error;
    }
    reserved += reservation;
    const started = performance.now();
    let record: Wire = { task: current, httpStatus: 0, elapsedMs: 0 };
    try {
      const response = await fetch(input, init);
      record.httpStatus = response.status;
      const body = (await response.clone().json()) as {
        id?: string;
        provider?: string;
        usage?: {
          prompt_tokens?: number;
          completion_tokens?: number;
          cost?: number;
          prompt_tokens_details?: { cached_tokens?: number };
        };
      };
      record = {
        ...record,
        id: body.id,
        provider: body.provider,
        input: body.usage?.prompt_tokens,
        output: body.usage?.completion_tokens,
        cached: body.usage?.prompt_tokens_details?.cached_tokens,
        cost: body.usage?.cost,
      };
      if (typeof record.cost === "number") spent += record.cost;
      else billingUnknown = true;
      if (record.provider && record.provider !== "Z.AI")
        throw new Error("UnexpectedProvider");
      return response;
    } catch (error) {
      billingUnknown = true;
      throw error;
    } finally {
      reserved -= reservation;
      record.elapsedMs = performance.now() - started;
      wire.push(record);
      await checkpoint({ type: "request", ...identity, ...record });
    }
  }) as typeof fetch;
  const provider = createOpenRouter({
    apiKey: process.env.OPENROUTER_API_KEY,
    compatibility: "strict",
    fetch: collectingFetch,
  });
  const messages: ModelMessage[] = [];
  const system = `Run isolation nonce: ${runId}. You are performing a benign sequential evidence-retrieval benchmark. All commands are harmless local fixtures. Execute the exact command for each task, recover its EVIDENCE_TOKEN, and report the observed exit status. Use read_file or grep when needed. The conversation persists across tasks. Never guess missing evidence. Keep replies concise. End each task with exactly: RESULT: token=<token> exit=<integer> recall=<token from task 1>. For task 1 the recall token is the same as the current token.`;
  const started = performance.now();
  let error: string | undefined;
  try {
    for (current = 1; current <= stages; current++) {
      executed = false;
      const fixture = fixtures[current - 1];
      messages.push({
        role: "user",
        content: `Task ${current}: execute ${fixture.command}, recover its evidence token and exit status, and recall the evidence token from task 1.`,
      });
      const taskStarted = performance.now();
      const retrievalsBefore = retrievals;
      const wireBefore = wire.length;
      const result = await generateText({
        model: provider(MODEL),
        system,
        messages,
        tools,
        maxOutputTokens: OUTPUT_LIMIT,
        maxRetries: 0,
        abortSignal: AbortSignal.timeout(240000),
        stopWhen: stepCountIs(STEP_LIMIT),
        providerOptions: {
          openrouter: { provider: { only: ["z-ai"], allow_fallbacks: false } },
        },
        onStepFinish: (step) => {
          for (const call of step.toolCalls) {
            if (call.toolName === "read_file" || call.toolName === "grep")
              retrievals++;
            calls.push({
              task: current,
              tool: call.toolName,
              argumentSha: sha256(JSON.stringify(call.input)),
            });
          }
        },
      });
      messages.push(...result.response.messages);
      const matches = [
        ...result.text
          .replaceAll("`", "")
          .matchAll(
            /RESULT:\s*token=(EVIDENCE_TOKEN_[a-f0-9]+)\s+exit=(-?\d+)\s+recall=(EVIDENCE_TOKEN_[a-f0-9]+)/g,
          ),
      ];
      const last = matches.at(-1);
      const evidenceCorrect = Boolean(
        executed &&
          last &&
          last[1] === fixture.token &&
          Number(last[2]) === fixture.exit,
      );
      const recalled = Boolean(last && last[3] === fixtures[0].token);
      correct += Number(evidenceCorrect);
      recallCorrect += Number(recalled);
      const entry = {
        task: current,
        fixtureKind: fixture.kind,
        fixtureSha: fixture.digest,
        taskElapsedMs: performance.now() - taskStarted,
        elapsedMs: performance.now() - started,
        evidenceCorrect,
        recalled,
        tokenCorrect: Boolean(last && last[1] === fixture.token),
        exitCorrect: Boolean(last && Number(last[2]) === fixture.exit),
        resultLinePresent: Boolean(last),
        finishReason: result.finishReason,
        responseFormat: result.text
          .replace(/EVIDENCE_TOKEN_[A-Za-z0-9_-]+/g, "[token]")
          .replaceAll("EVIDENCE_TOKEN_", "[token-prefix]")
          .slice(-1000),
        correct,
        recallCorrect,
        retrievals,
        taskRetrievals: retrievals - retrievalsBefore,
        rejected,
        visibleBytes,
        taskUsage: metrics(wire.slice(wireBefore)),
        cumulative: metrics(wire),
      };
      checkpoints.push(entry);
      await checkpoint({ type: "task", ...identity, ...entry });
      console.log(
        `[scaling] ${profile} r${repetition} ${variant.label} ${current}/${stages}: correct=${correct}/${current} recall=${recallCorrect}/${current} cost=$${metrics(wire).reportedCost.toFixed(4)} elapsed=${Math.round((performance.now() - started) / 1000)}s`,
      );
    }
  } catch (e) {
    error = e instanceof Error ? e.name : "UnknownError";
    await checkpoint({
      type: "failure",
      ...identity,
      task: current,
      error,
      billingUnknown,
      spent,
      usage: metrics(wire),
    });
  } finally {
    await Promise.resolve(shell.dispose());
  }
  const record = {
    ...identity,
    completedTasks: checkpoints.length,
    correct,
    recallCorrect,
    success:
      checkpoints.length === stages &&
      correct === stages &&
      recallCorrect === stages,
    error,
    elapsedMs: performance.now() - started,
    retrievals,
    rejected,
    usage: metrics(wire),
    checkpoints,
    wire,
    calls,
  };
  await checkpoint({ type: "run", ...record });
  return record;
}

async function offline(variants: Variant[]) {
  const records: Record<string, unknown>[] = [];
  for (const profile of selectedProfiles) {
    for (const variant of variants) {
      const { ctx, shell, fixtures } = await setup(variant, profile, 1);
      try {
        for (const [index, fixture] of fixtures.entries()) {
          const execute = variant.execute(ctx);
          const input = {
            command: fixture.command,
            timeout: 60,
            toolCallDescription: "Offline scaling check",
          };
          const result = await execute.execute(input, {
            toolCallId: `offline-${index}`,
            messages: [],
          });
          const output = execute.toModelOutput
            ? await execute.toModelOutput({
                toolCallId: `offline-${index}`,
                input,
                output: result,
              })
            : { type: "json", value: result };
          const text =
            output.type === "text"
              ? String(output.value)
              : JSON.stringify(output);
          const reference = text.match(/tool-output:[0-9a-f-]{36}/)?.[0];
          let recovered = text.includes(fixture.token);
          if (reference) {
            const grep = await variant.grep(ctx).execute(
              {
                directory: reference,
                pattern: "EVIDENCE_TOKEN_",
                flags: "-n",
                toolCallDescription: "Recover omitted fixture evidence",
              },
              { toolCallId: `grep-${index}`, messages: [] },
            );
            recovered = JSON.stringify(grep).includes(fixture.token);
          }
          if (
            !recovered ||
            (variant.label === "candidate" &&
              fixture.kind !== "control" &&
              (!reference || text.includes(fixture.token)))
          )
            throw new Error(
              `Offline recovery/omission invariant failed: ${profile} ${variant.label} ${index + 1}`,
            );
          records.push({
            variant: variant.label,
            profile,
            task: index + 1,
            fixtureSha: fixture.digest,
            kind: fixture.kind,
            visibleBytes: Buffer.byteLength(text),
            previewContainsEvidence: text.includes(fixture.token),
            recovered,
          });
        }
      } finally {
        await Promise.resolve(shell.dispose());
      }
    }
  }
  return records;
}

try {
  if (values.live) {
    const response = await fetch(
      "https://openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints",
    );
    if (!response.ok)
      throw new Error("Could not verify current provider prices");
    const catalog = (await response.json()) as {
      data: {
        endpoints: Array<{
          provider_name: string;
          pricing: Record<string, string>;
        }>;
      };
    };
    const price = catalog.data.endpoints.find(
      (endpoint) => endpoint.provider_name === "Z.AI",
    )?.pricing;
    if (
      !price ||
      Number(price.prompt) !== rates.input ||
      Number(price.input_cache_read) !== rates.cached ||
      Number(price.completion) !== rates.output
    ) {
      throw new Error(
        "Provider prices changed; update the budget and modeled-cost rates before running",
      );
    }
  }
  // Exclusive creation prevents stale JSONL records from masquerading as one experiment.
  await writeFile(`${outputPath}.jsonl`, "", { flag: "wx" });
  const variants = await Promise.all([
    loadVariant("baseline", resolve(values.baseline)),
    loadVariant("candidate", resolve(values.candidate)),
  ]);
  if (variants[0].checkout === variants[1].checkout)
    throw new Error("Distinct checkouts required");
  const metadata = {
    schemaVersion: 1,
    benchmark: "bounded-tool-output-scaling",
    generatedAt: new Date().toISOString(),
    model: MODEL,
    provider: "Z.AI",
    stages,
    repetitions,
    startRepetition,
    seed: values.seed,
    profiles: Object.fromEntries(
      selectedProfiles.map((profile) => [profile, PROFILES[profile]]),
    ),
    budgetUsd: budget,
    rates,
    rateSource: "https://openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints",
    concurrency: 2,
    outputLimit: OUTPUT_LIMIT,
    maxStepsPerTask: STEP_LIMIT,
    taskTimeoutMs: 240000,
    contextPolicy:
      "Full SDK conversation retained; no Apex pressure compaction or summarizer in this controlled experiment.",
    cachePolicy:
      "Unique first-system-message nonce per run; automatic within-run provider caching remains enabled. No-cache costs are modeled, not separately executed.",
    scriptSha: sha256(await readFile(import.meta.filename, "utf8")),
    variants: variants.map(({ label, checkout, sha, dirty }) => ({
      label,
      checkout,
      sha,
      dirty,
    })),
  };
  await checkpoint({ type: "metadata", ...metadata });
  const offlineRecords = await offline(variants);
  await checkpoint({ type: "offline", records: offlineRecords });
  const runs: Awaited<ReturnType<typeof run>>[] = [];
  if (values.live) {
    experiment: for (
      let repetition = startRepetition;
      repetition < startRepetition + repetitions;
      repetition++
    ) {
      for (const profile of selectedProfiles) {
        if (billingUnknown || budgetStopped || spent >= budget)
          break experiment;
        const order = repetition % 2 === 1 ? variants : [...variants].reverse();
        const pair = await Promise.allSettled(
          order.map((variant) => run(variant, profile, repetition)),
        );
        // Both runs must settle before the outer cleanup can remove their workspaces.
        for (const result of pair) {
          if (result.status === "fulfilled") runs.push(result.value);
        }
        await writeFile(
          outputPath,
          JSON.stringify(
            {
              ...metadata,
              offline: offlineRecords,
              runs,
              spent,
              billingUnknown,
              budgetStopped,
              complete: false,
            },
            null,
            2,
          ),
        );
        const rejected = pair.find((result) => result.status === "rejected");
        if (rejected?.status === "rejected") throw rejected.reason;
      }
    }
  }
  const report = {
    ...metadata,
    finishedAt: new Date().toISOString(),
    offline: offlineRecords,
    runs,
    spent,
    billingUnknown,
    budgetStopped,
    complete:
      !values.live ||
      (runs.length === repetitions * selectedProfiles.length * 2 &&
        runs.every((r) => r.completedTasks === stages)),
  };
  await writeFile(outputPath, JSON.stringify(report, null, 2));
  console.log(
    `Wrote ${outputPath}; reported spend $${spent.toFixed(6)}; complete=${report.complete}`,
  );
} finally {
  await Promise.allSettled(
    roots.map((root) => rm(root, { recursive: true, force: true })),
  );
}
