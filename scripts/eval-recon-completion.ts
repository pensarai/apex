import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { inProcessSubagentSpawner } from "../src/core/agents/offSecAgent/subagentSpawner";
import { loadTopology } from "../src/core/agents/offSecAgent/tools/topologyRecords";
import { readCompletionLedger } from "../src/core/agents/specialized/attackSurface/completionAudit";
import { GENERALIZED_ATTACK_SURFACE_TOOLS } from "../src/core/agents/specialized/attackSurface/reconToolset";
import { type AIModel, onUsage, type UsageRecorder } from "../src/core/ai";
import { runGeneralizedAttackSurface } from "../src/core/api/attackSurface";
import { AgentEventBus } from "../src/core/eventBus";
import { readGoalFile } from "../src/core/goals";
import { sessions } from "../src/core/session";
import { LocalBackends, type ToolPolicy } from "../src/core/tools/backends";

const { values } = parseArgs({
  options: {
    arm: { type: "string" },
    fixture: { type: "string" },
    output: { type: "string" },
    model: { type: "string", default: "anthropic/claude-opus-4.6" },
    minutes: { type: "string", default: "10" },
    dollars: { type: "string", default: "12" },
    "objective-file": { type: "string" },
  },
  strict: true,
});
if (
  !values.fixture ||
  !values.output ||
  !["goal", "audit"].includes(values.arm ?? "")
)
  throw new Error(
    "Usage: --arm goal|audit --fixture <customer-source-repo> --output <new-directory>",
  );
const minutes = Number(values.minutes),
  dollars = Number(values.dollars);
if (!(minutes > 0 && minutes <= 30 && dollars > 0 && dollars <= 30))
  throw new Error("Use 0–30 minutes and 0–30 estimated USD per arm");
const output = resolve(values.output);
if (existsSync(output)) throw new Error("Output directory already exists");
mkdirSync(output, { recursive: true });
const target = "http://portal.corp.localtest.me:18080";
const fixture = realpathSync(values.fixture);
const model = values.model as AIModel;
const objective = values["objective-file"]
  ? readFileSync(resolve(values["objective-file"]), "utf8").trim()
  : "Map the supplied corporate application from all supplied source files, including its boundaries, components, data flows, assets, trust assumptions, distinct source-supported threats and applicable controls. Check the complete map for omissions, duplicates, contradictions and unsupported claims before finishing. Explain justified absence and unavailable deployment evidence. Do not invent threats or controls. Preserve third-party dependencies as threat vectors without authorizing provider testing. No live security tests or network requests are authorized; this is a source-only analysis.";
const session = await sessions.create({
  name: `recon-${values.arm}-comparison`,
  targets: [target],
  config: {
    connectedRepositories: [
      { id: "corporate-source", name: "corporate-source", url: fixture },
    ],
    prompt: `${objective}\nThe corporate-source repository is already copied to the session's customer-source/ directory. Read it directly; cloning and network access are disabled. This is a synthetic source-only fixture; do not claim live exploit verification.`,
  },
});
cpSync(fixture, join(session.rootPath, "customer-source"), {
  recursive: true,
  filter: (p) => !p.split(/[\\/]/).includes(".git"),
});
const controller = new AbortController();
const timer = setTimeout(
  () => controller.abort(new Error("Evaluation deadline reached")),
  minutes * 60_000,
);
let estimatedUsd = 0,
  inputTokens = 0,
  outputTokens = 0,
  calls = 0;
const catalog = await fetch("https://openrouter.ai/api/v1/models").then((r) => {
  if (!r.ok) throw new Error(`Model catalog: ${r.status}`);
  return r.json();
});
const selected = catalog.data.find(
  (entry: { id: string }) => entry.id === model,
);
if (!selected) throw new Error(`Model ${model} absent from provider catalog`);
const price = selected.pricing;
const usage: UsageRecorder = (modelId, input, tokensOut, context) => {
  inputTokens += input;
  outputTokens += tokensOut;
  calls++;
  const cached = context?.cacheReadTokens ?? 0,
    written = context?.cacheWriteTokens ?? 0;
  const estimate =
    Math.max(0, input - cached - written) * Number(price.prompt) +
    cached * Number(price.input_cache_read ?? price.prompt) +
    written * Number(price.input_cache_write ?? price.prompt) +
    tokensOut * Number(price.completion);
  estimatedUsd += estimate;
  appendFileSync(
    join(output, "usage.jsonl"),
    JSON.stringify({
      at: new Date().toISOString(),
      modelId,
      input,
      output: tokensOut,
      context,
      estimatedUsd: estimate,
    }) + "\n",
  );
  if (estimatedUsd >= dollars)
    controller.abort(new Error("Evaluation estimated cost limit reached"));
};
onUsage(usage);
const policy: ToolPolicy = {
  beforeCall({ backend, op, args }) {
    if (backend !== "fs")
      return {
        allow: false,
        reason:
          "Source-only evaluation: network, browser, shell and inbox access disabled",
      };
    if (["git", "repoClone", "applyPatch", "delete"].includes(op))
      return { allow: false, reason: "Fixture and answer-key isolation" };
    const a = args as {
      path?: string;
      dir?: string;
      directory?: string;
      pattern?: string;
    };
    const path = resolve(
      session.rootPath,
      a.path ?? a.dir ?? a.directory ?? ".",
    );
    const inside = (p: string) => {
      const rel = relative(session.rootPath, p);
      return !rel.startsWith("..") && !isAbsolute(rel);
    };
    let ancestor = path;
    while (!existsSync(ancestor)) ancestor = dirname(ancestor);
    if (!inside(path) || !inside(realpathSync(ancestor)))
      return {
        allow: false,
        reason: "Only this run's source and records may be accessed",
      };
    if (
      op === "glob" &&
      a.pattern &&
      (isAbsolute(a.pattern) || a.pattern.split("/").includes(".."))
    )
      return { allow: false, reason: "Glob must stay inside the run" };
    return { allow: true };
  },
};
const backends = LocalBackends(
  {
    session,
    agentCwd: session.rootPath,
    fileWorkspaceRoot: session.rootPath,
    subagentSpawner: inProcessSubagentSpawner,
  },
  policy,
);
const allowed = new Set([
  "read_file",
  "list_files",
  "grep",
  "glob",
  "document_boundary",
  "document_component",
  "document_flow",
  "document_control",
  "document_threat",
  "update_record",
  "review_topology",
  "retire_record",
  "merge_records",
  "create_attack_surface_report",
]);
const eventBus = new AgentEventBus();
for (const event of [
  "tool-call-complete",
  "tool-result",
  "subagent-spawn",
  "subagent-complete",
  "error",
] as const)
  eventBus.on(event, (data) =>
    appendFileSync(
      join(output, "events.jsonl"),
      JSON.stringify({ event, at: new Date().toISOString(), data }) + "\n",
    ),
  );
mkdirSync(join(output, "implementation"));
for (const name of [
  "generalizedAgent.ts",
  "reconGoal.ts",
  "reconGoal.test.ts",
]) {
  cpSync(
    resolve(
      import.meta.dir,
      "../src/core/agents/specialized/attackSurface",
      name,
    ),
    join(output, "implementation", name),
  );
}
cpSync(
  import.meta.path,
  join(output, "implementation", "eval-recon-completion.ts"),
);
writeFileSync(
  join(output, "implementation", "tracked.patch"),
  Bun.spawnSync(["git", "diff", "--binary"], {
    cwd: resolve(import.meta.dir, ".."),
  }).stdout,
);
const start = Date.now();
const commit = Bun.spawnSync(["git", "rev-parse", "HEAD"], {
  cwd: resolve(import.meta.dir, ".."),
})
  .stdout.toString()
  .trim();
writeFileSync(
  join(output, "inputs.json"),
  JSON.stringify(
    {
      arm: values.arm,
      model,
      commit,
      fixture,
      target,
      objective,
      sourcePolicy: "source-only; no live requests",
      minutes,
      dollars,
      pricing: price,
      session: { id: session.id, rootPath: session.rootPath },
      startedAt: new Date(start).toISOString(),
    },
    null,
    2,
  ),
);
let status = "completed",
  error: string | undefined;
try {
  await runGeneralizedAttackSurface({
    target,
    model,
    session,
    eventBus,
    backends,
    abortSignal: controller.signal,
    usageRecorder: usage,
    harness: "general",
    toolProtocol: "direct",
    excludeTools: GENERALIZED_ATTACK_SURFACE_TOOLS.filter(
      (t) => !allowed.has(t),
    ),
    ...(values.arm === "goal"
      ? { goal: { objective, maxRounds: 4, workSteps: 100 } }
      : {
          completion: {
            version: 1 as const,
            mode: "enforce" as const,
            maxPasses: 4,
            auditConcurrency: 6,
            workSteps: 100,
          },
        }),
  });
} catch (e) {
  status = "failed";
  error = e instanceof Error ? e.message : String(e);
} finally {
  clearTimeout(timer);
  onUsage(null);
}
const topology = loadTopology(session.rootPath);
writeFileSync(join(output, "topology.json"), JSON.stringify(topology, null, 2));
const goal = readGoalFile(session.rootPath),
  audit = readCompletionLedger(session.rootPath, session.id);
const result = {
  status,
  error,
  elapsedSeconds: (Date.now() - start) / 1000,
  calls,
  inputTokens,
  outputTokens,
  estimatedUsd,
  costCaveat:
    "Catalog estimate of successful recorded usage; not a provider invoice. In-flight calls can overshoot the threshold.",
  goal,
  audit,
  counts: Object.fromEntries(
    Object.entries(topology).map(([k, v]) => [
      k,
      Array.isArray(v) ? v.length : null,
    ]),
  ),
};
writeFileSync(join(output, "result.json"), JSON.stringify(result, null, 2));
const report = join(session.rootPath, "attack-surface-results.json");
if (existsSync(report))
  writeFileSync(join(output, "report.json"), readFileSync(report));
console.log(
  JSON.stringify({
    output,
    ...result,
    audit: audit
      ? { status: audit.status, pass: audit.pass, gaps: audit.gaps }
      : null,
  }),
);
process.exit(status === "completed" ? 0 : 1);
