// Real worker/store lifecycle; only the provider and session setup are fixtures.

import { mock } from "bun:test";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { runOffensiveSecurityAgent } from "../../api/offesecAgent";

const scenario = process.env.APEX_WORKER_SCENARIO ?? "complete";
const dbPath = process.env.APEX_WORKER_DB!;
const dataDir = process.env.APEX_WORKER_DATA_DIR!;
const cwd = process.env.APEX_WORKER_CWD!;
const sessionRoot = process.env.APEX_WORKER_SESSION_ROOT!;
const port = Number(process.env.APEX_WORKER_PORT);
const runId = process.env.APEX_WORKER_RUN_ID!;
const idleTimeoutMs = Number(process.env.APEX_WORKER_IDLE_TIMEOUT ?? "30000");
const settledTimeoutMs = Number(
  process.env.APEX_WORKER_SETTLED_TIMEOUT ?? "2000",
);
const baseSystem = "Custom base system for recovery acceptance.";

process.env.PENSAR_DATA_DIR = dataDir;
for (const leaf of ["", "findings", "scratchpad", "logs", "pocs"]) {
  mkdirSync(join(sessionRoot, leaf), { recursive: true });
}
mkdirSync(cwd, { recursive: true });
// Cleanup handle for the acceptance suite; beside the database, never
// inside the evidence root.

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

const stall = (): Promise<never> =>
  new Promise(() => {
    // A pending promise alone does not keep Bun alive.
    setInterval(() => {}, 1000);
  });

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

    // Resumed execution: the reconstructed receipt is already in the
    // messages — consume it, never re-POST.
    const resumed = (input.messages ?? []).some(
      (m) => (m as { role?: string }).role === "tool",
    );

    if (!resumed) {
      await input.contextRecorder.checkpoint({
        messages: [{ role: "user", content: input.prompt }],
        system,
      });
    }

    const recorder = getInferenceRecorder();
    if (!recorder) throw new Error("Missing inference recorder");
    const attempt = startInferenceAttempt({
      operationKind: "agent.stream",
      requested: { provider: "anthropic", modelId: "claude-haiku-4-5" },
    });
    await recorder.beforeDispatch(attempt.started);

    if (resumed) {
      await input.contextRecorder.checkpoint({
        messages: [
          ...(input.messages ?? []),
          {
            role: "assistant",
            content: [{ type: "text", text: "Resumed without re-execution." }],
          },
        ],
        system,
      });
      recorder.settle(
        attempt.complete({
          tokens: {
            inclusiveInput: 60,
            uncachedInput: 60,
            cacheRead: 0,
            cacheWrite: 0,
            output: 8,
          },
        }),
      );
      return { streamResult: {}, session: {} };
    }

    await recorder.beforeToolCall(attempt.attemptId, {
      toolCallId: "tc_worker_1",
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
            return { status: response.status, from: "worker" };
          },
        }),
      },
      input.toolExecutionRecorder,
    );
    const wrapped = tools.http_request as {
      execute?: (i: never, o: never) => Promise<unknown> | unknown;
    };
    if (typeof wrapped.execute !== "function") {
      throw new Error("http_request is not executable");
    }
    const gate = (await Promise.resolve(
      wrapped.execute(
        { url: `http://127.0.0.1:${port}/mutate`, method: "POST" } as never,
        { toolCallId: "tc_worker_1" } as never,
      ),
    )) as { status: number };
    if (scenario === "crash-after-settle") await stall();
    if (scenario === "pause-after-settle") {
      while (!existsSync(`${dbPath}.continue`)) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      await recorder.beforeDispatch(
        startInferenceAttempt({
          operationKind: "agent.stream",
          requested: { provider: "anthropic", modelId: "claude-haiku-4-5" },
        }).started,
      );
      throw new Error("Paused dispatch was unexpectedly admitted");
    }
    recorder.settle(
      attempt.complete({
        tokens: {
          inclusiveInput: 100,
          uncachedInput: 100,
          cacheRead: 0,
          cacheWrite: 0,
          output: 12,
        },
      }),
    );
    await input.contextRecorder.checkpoint({
      messages: [
        { role: "user", content: input.prompt },
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              toolCallId: "tc_worker_1",
              toolName: "http_request",
              input: { url: `http://127.0.0.1:${port}/mutate`, method: "POST" },
            },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "tc_worker_1",
              toolName: "http_request",
              output: {
                type: "json",
                value: { status: gate.status, from: "worker" },
              },
            },
          ],
        },
      ],
      system,
    });
    return { streamResult: {}, session: {} };
  },
}));

const { runRecordedAgent, resumeRecordedAgent } = await import(
  "../../api/recordedRun"
);
const { serveLocalRunWorker } = await import("../localRunWorker");

await serveLocalRunWorker({
  runId,
  databasePath: dbPath,
  idleTimeoutMs,
  settledTimeoutMs,
  execute: async ({ request, store, signal }) => {
    writeFileSync(`${dbPath}.fixture-pid`, String(process.pid));
    if (request.method === "start") {
      return runRecordedAgent({
        spec: request.spec,
        store,
        abortSignal: signal,
      });
    }
    return resumeRecordedAgent({
      runId,
      expectedAttemptId: request.expectedAttemptId,
      store,
      abortSignal: signal,
    });
  },
});
