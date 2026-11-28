import { createHash } from "node:crypto";
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadTopology } from "../src/core/agents/offSecAgent/tools/topologyRecords";
import { type AIModel, onUsage, type UsageRecorder } from "../src/core/ai";
import { runGeneralizedAttackSurface } from "../src/core/api/attackSurface";
import { AgentEventBus } from "../src/core/eventBus";
import { GOAL_LIMITS, readGoalFile } from "../src/core/goals";
import { sessions } from "../src/core/session";
import { runReconWithGoal } from "./recon-tracker/goal";
import {
  assertCleanRuntime,
  runtimeFingerprint,
} from "./recon-tracker/revision";
import {
  csv,
  inspectTracker,
  loadScope,
  seedTracker,
} from "./recon-tracker/scope";

const { values } = parseArgs({
  options: {
    arm: { type: "string" },
    scope: { type: "string" },
    output: { type: "string" },
    model: { type: "string", default: "anthropic/claude-opus-4.6" },
    "prepare-only": { type: "boolean", default: false },
  },
  strict: true,
});
if (
  !values.scope ||
  !values.output ||
  !["baseline", "tracker", "goal-tracker"].includes(values.arm ?? "")
)
  throw new Error(
    "Usage: --arm baseline|tracker|goal-tracker --scope <csv> --output <new-directory> [--prepare-only]",
  );
assertCleanRuntime(resolve(import.meta.dir, ".."));
const source = readFileSync(resolve(values.scope), "utf8");
const scope = loadScope(source);
const withTracker = values.arm !== "baseline";
const withGoal = values.arm === "goal-tracker";
const output = resolve(values.output);
if (existsSync(output)) throw new Error("Output directory must be new");
mkdirSync(output, { recursive: true });
const save = (name: string, value: unknown) =>
  writeFileSync(join(output, name), JSON.stringify(value, null, 2));
const log = (name: string, value: unknown) =>
  appendFileSync(
    join(output, name),
    JSON.stringify({ at: new Date().toISOString(), ...(value as object) }) +
      "\n",
  );
const objective = `Create an attack surface and useful component-level threat models covering all ${scope.items.length} supplied domains. Account for each domain, including aliases, nonproduction services, unreachable hosts and third-party tenant services. Group domains only when their shared application or trust boundary justifies it; preserve all members and material differences. Develop distinct, meaningful threat hypotheses proportional to complexity, stating prerequisites, impact and useful follow-up tests. Do not impose a threat quota or claim vulnerabilities are confirmed without evidence. Explain justified absence and visibility limits. Use the standard recon workflow and its available probing, shell, browser and file tools. There are no supplied repositories or cloud integrations. scope.csv in the session directory contains the authoritative deduplicated inventory. This is a fresh independent evaluation: do not reuse other runs or their reports. Check coverage and threat-model depth before creating the final report; report limitations honestly.`;
const trackerGuidance = `\nUse coverage.csv as your durable work tracker until this recon is finished. It already has one pending row per supplied domain. Read it at the start and after context compaction. Preserve all IDs, domains and columns. Update it incrementally using the existing execute_command tool (Python’s csv module is available). Quote CSV cells containing commas, quotes or newlines correctly. The orchestrator is the only writer; give workers explicit domain IDs, ask them for results and evidence references, then merge their progress yourself. Statuses: pending, in_progress, assessed, covered_by_shared_model, blocked, excluded. A probe alone is not assessed: identify the service or limitation, map it to saved component IDs, and consider applicable distinct threats or explain why no additional threats are warranted. For assessed/shared rows fill component_ids, evidence_refs and reason. Shared-model rows must explain why the model applies to that particular domain; sampling must not silently complete unexamined members. Blocked/excluded rows need concrete evidence or scope references and a reason; they are limitations, not full coverage. Before reporting, reread every row, resolve pending/in_progress rows and verify record/evidence references. Continue corrective work for gaps. Do not mark rows complete merely to finish. Summarize assessed, shared, blocked, excluded and unresolved counts in the final output.`;
const session = await sessions.create({
  name: `recon-csv-${values.arm}`,
  targets: scope.items.map((item) => item.origin),
  config: {
    prompt: objective + (withTracker ? trackerGuidance : ""),
    enumerateSubdomains: false,
  },
});
writeFileSync(
  join(session.rootPath, "scope.csv"),
  csv([["id", "domain"], ...scope.items.map((item) => [item.id, item.domain])]),
);
if (withTracker)
  writeFileSync(
    join(session.rootPath, "coverage.csv"),
    seedTracker(scope.items),
  );
writeFileSync(join(output, "source.csv"), source);
save("scope.json", scope);
const commit = Bun.spawnSync(["git", "rev-parse", "HEAD"], {
  cwd: resolve(import.meta.dir, ".."),
})
  .stdout.toString()
  .trim();
const agentSourceTree = Bun.spawnSync(["git", "rev-parse", "HEAD:src"], {
  cwd: resolve(import.meta.dir, ".."),
})
  .stdout.toString()
  .trim();
const inputs = {
  arm: values.arm,
  model: values.model,
  commit,
  agentSourceTree,
  runtimeFingerprint: runtimeFingerprint(
    resolve(import.meta.dir, ".."),
    commit,
  ),
  sourceSha256: createHash("sha256").update(source).digest("hex"),
  domains: scope.items.length,
  duplicates: scope.duplicates,
  session: { id: session.id, rootPath: session.rootPath },
  prompt: session.config?.prompt,
  goalEnabled: withGoal,
  goalLimits: withGoal ? GOAL_LIMITS : undefined,
  goalImplementation: withGoal
    ? "native src/core/goals + local recon adapter"
    : undefined,
  auditEnabled: false,
  runtimeTrackerGate: false,
  toolPolicy: "apex-default",
  timeLimit: null,
  costLimit: null,
  toolProtocol: "apex-default",
  startMode: "fresh",
};
save("inputs.json", inputs);
mkdirSync(join(output, "implementation"));
cpSync(
  import.meta.path,
  join(output, "implementation", "eval-recon-tracker.ts"),
);
cpSync(
  join(import.meta.dir, "recon-tracker"),
  join(output, "implementation", "recon-tracker"),
  { recursive: true },
);
writeFileSync(
  join(output, "implementation", "tracked.patch"),
  Bun.spawnSync(["git", "diff", "HEAD", "--binary"], {
    cwd: resolve(import.meta.dir, ".."),
  }).stdout,
);
if (values["prepare-only"]) {
  console.log(JSON.stringify(inputs));
  process.exit(0);
}

const catalogResponse = await fetch("https://openrouter.ai/api/v1/models");
if (!catalogResponse.ok)
  throw new Error(`Pricing catalog failed: ${catalogResponse.status}`);
const catalog = (await catalogResponse.json()) as {
  data: { id: string; pricing: Record<string, string> }[];
};
const candidates = catalog.data.filter(
  (entry) =>
    entry.id === values.model || entry.id.split("/").at(-1) === values.model,
);
const selected =
  candidates.find((entry) => entry.id === values.model) ??
  (candidates.length === 1 ? candidates[0] : undefined);
const price = selected?.pricing;
save("pricing.json", { model: selected?.id ?? null, pricing: price ?? null });
let calls = 0,
  inputTokens = 0,
  outputTokens = 0;
let estimatedUsd: number | null = price ? 0 : null;
const usage: UsageRecorder = (model, input, tokensOut, context) => {
  const cached = context?.cacheReadTokens ?? 0,
    written = context?.cacheWriteTokens ?? 0;
  const estimate = price
    ? Math.max(0, input - cached - written) * Number(price.prompt) +
      cached * Number(price.input_cache_read ?? price.prompt) +
      written * Number(price.input_cache_write ?? price.prompt) +
      tokensOut * Number(price.completion)
    : null;
  calls++;
  inputTokens += input;
  outputTokens += tokensOut;
  if (estimatedUsd !== null && estimate !== null) estimatedUsd += estimate;
  log("usage.jsonl", {
    model,
    input,
    output: tokensOut,
    context,
    estimatedUsd: estimate,
  });
};
onUsage(usage);
const controller = new AbortController();
const stop = () => controller.abort(new Error("Stopped by operator"));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
const eventBus = new AgentEventBus();
for (const event of [
  "tool-call-complete",
  "tool-result",
  "subagent-spawn",
  "subagent-complete",
  "error",
  "text-delta",
] as const)
  eventBus.on(event, (data) => log("events.jsonl", { event, data }));
const start = Date.now();
save("inputs.json", { ...inputs, startedAt: new Date(start).toISOString() });
console.log(
  JSON.stringify({
    event: "started",
    output,
    session: session.rootPath,
    domains: scope.items.length,
    arm: values.arm,
  }),
);
const heartbeat = setInterval(
  () =>
    save("progress.json", {
      elapsedSeconds: (Date.now() - start) / 1000,
      calls,
      inputTokens,
      outputTokens,
      estimatedUsd,
    }),
  15_000,
);
let status = "completed",
  error: string | undefined;
try {
  const input = {
    target: scope.items[0].origin,
    model: values.model as AIModel,
    session,
    eventBus,
    abortSignal: controller.signal,
    usageRecorder: usage,
  };
  if (withGoal) {
    const goal = await runReconWithGoal(input);
    if (goal.status !== "complete") status = goal.status;
  } else await runGeneralizedAttackSurface(input);
  if (controller.signal.aborted) status = "stopped";
} catch (caught) {
  status = controller.signal.aborted ? "stopped" : "failed";
  error = caught instanceof Error ? caught.message : String(caught);
} finally {
  clearInterval(heartbeat);
  onUsage(null);
  process.off("SIGINT", stop);
  process.off("SIGTERM", stop);
}
const topology = loadTopology(session.rootPath);
save("topology.json", topology);
for (const file of [
  "attack-surface-results.json",
  "coverage.csv",
  "scope.csv",
  "goal.json",
])
  if (existsSync(join(session.rootPath, file)))
    cpSync(join(session.rootPath, file), join(output, file));
if (withTracker) {
  try {
    save(
      "tracker-check.json",
      inspectTracker(
        readFileSync(join(session.rootPath, "coverage.csv"), "utf8"),
        scope.items,
      ),
    );
  } catch (caught) {
    save("tracker-check.json", { errors: [String(caught)] });
  }
}
const result = {
  status,
  error,
  goal: withGoal ? readGoalFile(session.rootPath) : undefined,
  elapsedSeconds: (Date.now() - start) / 1000,
  calls,
  inputTokens,
  outputTokens,
  estimatedUsd,
  counts: Object.fromEntries(
    Object.entries(topology).map(([key, records]) => [key, records.length]),
  ),
  costCaveat:
    "Catalog estimate of recorded usage, not an invoice. No evaluation time or cost cap. Agent/provider limits still apply.",
  completionCaveat: withGoal
    ? "Completed means native goal settlement accepted the model's cited tool outputs, not independently verified coverage or a current report."
    : "Completed means the unmodified recon utility returned a report, not independently verified coverage.",
};
save("result.json", result);
console.log(JSON.stringify({ output, ...result }));
process.exit(status === "completed" ? 0 : 1);
