// Direct Bun executor for public API crash tests; no live model calls.
import { mock } from "bun:test";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { runOffensiveSecurityAgent } from "../../api/offesecAgent";

const scenario = process.env.APEX_RECOVERY_SCENARIO;
const dbPath = process.env.APEX_RECOVERY_DB!;
const dataDir = process.env.APEX_RECOVERY_DATA_DIR!;
const cwd = process.env.APEX_RECOVERY_CWD!;
const sessionRoot = process.env.APEX_RECOVERY_SESSION_ROOT!;
const port = Number(process.env.APEX_RECOVERY_PORT);
const runId = process.env.APEX_RECOVERY_RUN_ID!;
const maxModelAttempts = Number(process.env.APEX_RECOVERY_MAX_ATTEMPTS ?? "4");
const baseSystem = "Custom base system for recovery acceptance.";
process.env.PENSAR_DATA_DIR = dataDir;
for (const leaf of ["", "findings", "scratchpad", "logs", "pocs"]) {
  mkdirSync(join(sessionRoot, leaf), { recursive: true });
}
mkdirSync(cwd, { recursive: true });

const sessions = await import("../../session");
mock.module(join(import.meta.dirname, "../../session/index.ts"), () => ({
  ...sessions,
  create: async (input: Parameters<typeof sessions.create>[0]) => {
    const session = {
      id: input.id,
      version: "fixture",
      targets: input.targets,
      name: input.name,
      time: { created: Date.now(), updated: Date.now() },
      rootPath: sessionRoot,
      scratchpadPath: join(sessionRoot, "scratchpad"),
      findingsPath: join(sessionRoot, "findings"),
      pocsPath: join(sessionRoot, "pocs"),
      logsPath: join(sessionRoot, "logs"),
      config: input.config,
    };
    writeFileSync(join(sessionRoot, "session.json"), JSON.stringify(session));
    return session;
  },
  get: async () =>
    JSON.parse(readFileSync(join(sessionRoot, "session.json"), "utf8")),
}));

const stall = async () => {
  // A pending promise alone does not keep Bun alive.
  setInterval(() => {}, 1000);
  console.log(`MARKER:${scenario}:200`);
  await new Promise<never>(() => {});
};

mock.module(join(import.meta.dirname, "../../api/offesecAgent.ts"), () => ({
  runOffensiveSecurityAgent: async (
    input: Parameters<typeof runOffensiveSecurityAgent>[0],
  ) => {
    const { buildSessionWorkspaceSection } = await import(
      "../../agents/offSecAgent"
    );
    const { wrapRecordedTools } = await import(
      "../../agents/offSecAgent/recordedTools"
    );
    const { getInferenceRecorder } = await import("../../ai");
    const { startInferenceAttempt } = await import(
      "../../ai/inference-attempt"
    );
    if (
      !input.session ||
      !input.contextRecorder ||
      !input.toolExecutionRecorder
    ) {
      throw new Error("Missing recorded execution inputs");
    }
    const system =
      baseSystem +
      buildSessionWorkspaceSection(input.session, cwd, ["http_request"]);
    await input.contextRecorder.checkpoint({
      messages: [{ role: "user", content: input.prompt }],
      system,
    });
    const recorder = getInferenceRecorder();
    if (!recorder) throw new Error("Missing inference recorder");
    const attempt = startInferenceAttempt({
      operationKind: "agent.stream",
      requested: { provider: "anthropic", modelId: "claude-haiku-4-5" },
    });
    await recorder.beforeDispatch(attempt.started);
    await recorder.beforeToolCall(attempt.attemptId, {
      toolCallId: "tc_recovery_1",
      toolName: "http_request",
    });
    const schema = z.object({ url: z.string(), method: z.literal("POST") });
    const tools = wrapRecordedTools(
      {
        http_request: tool({
          inputSchema: schema,
          execute: async ({ url, method }) => {
            const response = await fetch(url, { method });
            if (response.status !== 200)
              throw new Error("Fixture target failed");
            await response.text();
            if (scenario === "crash-after-post") await stall();
            writeFileSync(
              join(sessionRoot, "pocs", "receipt.txt"),
              "Fixture POST completed",
            );
            return { status: response.status, from: "child" };
          },
        }),
      },
      input.toolExecutionRecorder,
    );
    const execute = tools.http_request.execute;
    if (!execute) throw new Error("Missing executable fixture tool");
    await execute(
      schema.parse({ url: `http://127.0.0.1:${port}/mutate`, method: "POST" }),
      {
        toolCallId: "tc_recovery_1",
        messages: [],
      },
    );
    if (scenario === "crash-after-settle") await stall();
    throw new Error("Unknown crash scenario");
  },
}));

const { runRecordedAgent } = await import("../../api/recordedRun");
const { openSqliteRunStore } = await import("../sqliteRunStore");
const store = await openSqliteRunStore(dbPath);
try {
  await runRecordedAgent({
    spec: {
      schemaVersion: 1,
      configVersion: 1,
      runId,
      prompt: "Request the target homepage once and summarize the response.",
      system: baseSystem,
      target: `http://127.0.0.1:${port}`,
      model: "claude-haiku-4-5",
      activeTools: ["http_request"],
      environment: { kind: "local", cwd },
      scope: {
        version: 1,
        allowedHosts: ["127.0.0.1"],
        allowedPorts: [port],
        strictScope: true,
        allowDestructiveActions: false,
        allowRateLimitTesting: false,
      },
      credentialRefs: [],
      limits: { maxModelAttempts },
    },
    store,
  });
} finally {
  store.close();
}
