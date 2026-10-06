import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { type AIAuthConfig, buildAuthConfig } from "../core/ai";
import {
  inspectSessionEvidence,
  RunRecoveryBlockedError,
  resumeRecordedAgent,
  runRecordedAgent,
} from "../core/api";
import { config } from "../core/config";
import { AgentEventBus } from "../core/eventBus";
import {
  launchLocalWorker,
  resolveWorkerExecutable,
} from "../core/runtime/launchLocalWorker";
import type { LocalWorkerRequest } from "../core/runtime/localWorkerProtocol";
import {
  LocalWorkerTransportError,
  workerRequest,
} from "../core/runtime/localWorkerTransport";
import { RecordedRunSpecSchema } from "../core/runtime/runStore";
import { openSqliteRunStore } from "../core/runtime/sqliteRunStore";

const HELP = `pensar agent-runs — Record and inspect local agent runs

Usage:
  pensar agent-runs start --spec <file> [--detach] [--store <database>]
  pensar agent-runs resume <runId> [--detach] [--store <database>]
  pensar agent-runs list [--store <database>]
  pensar agent-runs show <runId> [--context] [--evidence] [--models] [--tools] [--control] [--recovery] [--store <database>]
  pensar agent-runs pause <runId> [--store <database>]
  pensar agent-runs stop <runId> [--store <database>]
  pensar agent-runs approve <runId> --approval <approvalId> [--store <database>]
  pensar agent-runs reject <runId> --approval <approvalId> [--store <database>]

The JSON spec supplies a stable runId and explicit model, tools and scope.
Repeating a runId never starts another execution. Changed inputs are rejected.
Statuses describe the last saved state, not whether a worker is still alive.
Pause and stop persist a cooperative request: the run applies it at its next
dispatch boundary, and accepted work may still finish. Approvals survive a
lost client until decided. Resume continues an enrolled run in the same
environment only; every failed prerequisite is reported as a blocker.
--detach hosts the run in a local worker that outlives this process; the
worker prints its log path and the run starts there, not here.

Recording requires Bun or Node 22.13+. See docs/recorded-runs.md.
`;

const COMMANDS = [
  "start",
  "resume",
  "list",
  "show",
  "pause",
  "stop",
  "approve",
  "reject",
] as const;

type AgentRunsStore = Awaited<ReturnType<typeof openSqliteRunStore>>;

// Mirrors openSqliteRunStore's default so the worker opens the same database.
function absoluteDatabasePath(explicit?: string): string {
  return resolve(
    explicit ??
      join(
        process.env.PENSAR_DATA_DIR ?? join(homedir(), ".pensar"),
        "runtime",
        "runs.sqlite",
      ),
  );
}

export async function runAgentRunsCommand(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      spec: { type: "string" },
      store: { type: "string" },
      context: { type: "boolean" },
      evidence: { type: "boolean" },
      models: { type: "boolean" },
      tools: { type: "boolean" },
      control: { type: "boolean" },
      recovery: { type: "boolean" },
      approval: { type: "string" },
      detach: { type: "boolean" },
      run: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: true,
  });
  if (values.help || positionals[0] === "help" || !positionals.length) {
    console.log(HELP);
    return;
  }
  const [command, runId, ...extra] = positionals;

  if (command === "worker") {
    if (
      extra.length ||
      runId !== undefined ||
      !values.run ||
      !values.store ||
      Object.keys(values).some((key) => key !== "run" && key !== "store")
    ) {
      throw new Error(
        "agent-runs worker requires --run <runId> and --store <absolute database>",
      );
    }
    if (!isAbsolute(values.store)) {
      throw new Error("agent-runs worker requires --store <absolute database>");
    }
    const { serveLocalRunWorker } = await import("../core/api");
    await serveLocalRunWorker({
      runId: values.run,
      databasePath: resolve(values.store),
    });
    return;
  }

  const showFlag =
    values.context ||
    values.evidence ||
    values.models ||
    values.tools ||
    values.control ||
    values.recovery;
  const takesRunId =
    command === "show" ||
    command === "pause" ||
    command === "stop" ||
    command === "approve" ||
    command === "reject" ||
    command === "resume";
  if (
    extra.length ||
    !COMMANDS.includes(command as (typeof COMMANDS)[number]) ||
    takesRunId !== (runId !== undefined) ||
    (command === "start" && !values.spec) ||
    (command !== "start" && values.spec !== undefined) ||
    (command !== "show" && showFlag) ||
    (command !== "approve" &&
      command !== "reject" &&
      values.approval !== undefined) ||
    ((command === "approve" || command === "reject") && !values.approval) ||
    (values.detach && command !== "start" && command !== "resume") ||
    (values.run !== undefined && command !== "worker")
  ) {
    throw new Error(`Invalid agent-runs arguments.\n${HELP}`);
  }

  const store: AgentRunsStore = await openSqliteRunStore(values.store);
  try {
    if (command === "list") {
      console.log(JSON.stringify(await store.list(), null, 2));
      return;
    }
    if (command === "show" && runId) {
      const record = await store.get(runId);
      if (!record) throw new Error(`Run not found: ${runId}`);
      const evidence = values.evidence
        ? await store.getEvidence(runId)
        : undefined;
      const attempts = values.models
        ? await store.listModelAttempts(runId)
        : undefined;
      console.log(
        JSON.stringify(
          {
            ...record,
            ...(values.tools
              ? {
                  tools: {
                    journaled: await store.hasToolJournal(runId),
                    operations: await store.listToolOperations(runId),
                  },
                }
              : {}),
            ...(attempts
              ? {
                  models: {
                    attempts,
                    retries: await store.listRetries(runId),
                    limits: {
                      maxModelAttempts:
                        record.spec.limits?.maxModelAttempts ?? null,
                      reservedModelAttempts: attempts.length,
                      remainingModelAttempts:
                        record.spec.limits?.maxModelAttempts === undefined
                          ? null
                          : Math.max(
                              0,
                              record.spec.limits.maxModelAttempts -
                                attempts.length,
                            ),
                      deadlineAt: record.spec.limits?.deadlineAt ?? null,
                    },
                  },
                }
              : {}),
            ...(values.context
              ? { context: (await store.getContext(runId)) ?? null }
              : {}),
            ...(values.evidence
              ? {
                  evidence: evidence
                    ? {
                        rootPath: evidence.rootPath,
                        files: await inspectSessionEvidence(
                          evidence,
                          evidence.files,
                        ),
                      }
                    : null,
                }
              : {}),
            ...(values.control
              ? {
                  control: {
                    record: (await store.getControl(runId)) ?? null,
                    approvals: await store.listApprovals(runId),
                  },
                }
              : {}),
            ...(values.recovery
              ? {
                  recovery: {
                    enrollment:
                      (await store.getRecoveryEnrollment(runId)) ?? null,
                    history: await store.listRecoveries(runId),
                  },
                }
              : {}),
          },
          null,
          2,
        ),
      );
      return;
    }

    if (command === "pause" || command === "stop") {
      const run = await store.get(runId);
      if (!run) throw new Error(`Run not found: ${runId}`);
      const control = await store.getControl(runId);
      if (!control) {
        throw new Error(`Run has no control record: ${runId}`);
      }
      const updated = await store.requestControl(
        runId,
        command,
        control.revision,
      );
      // The persisted request, not an instantaneous state change: the
      // run's last saved status is printed with the recorded intent.
      console.log(
        JSON.stringify({ status: run.status, control: updated }, null, 2),
      );
      return;
    }

    if (command === "approve" || command === "reject") {
      const approvalId = values.approval;
      if (!approvalId) throw new Error("An approval id is required");
      const approval = await store.resolveApproval(
        runId,
        approvalId,
        command === "approve" ? "approved" : "denied",
      );
      console.log(JSON.stringify(approval, null, 2));
      return;
    }

    if (command === "resume") {
      if (values.detach) {
        const record = await store.get(runId);
        if (!record) throw new Error(`Run not found: ${runId}`);
        await detachExecution(values.store, runId, {
          protocolVersion: 1,
          method: "resume",
          expectedAttemptId: record.attemptId,
        });
        return;
      }
      await runExecution(async (execution) =>
        resumeRecordedAgent({ runId, store, ...execution }),
      );
      return;
    }

    if (!values.spec) throw new Error("A run spec is required");
    const spec = JSON.parse(await readFile(values.spec, "utf8"));
    if (values.detach) {
      // The worker performs admission; the CLI only resolves the run id.
      const normalized = RecordedRunSpecSchema.parse(spec);
      await detachExecution(values.store, normalized.runId, {
        protocolVersion: 1,
        method: "start",
        spec: normalized,
      });
      return;
    }
    await runExecution(async (execution) =>
      runRecordedAgent({ spec, store, ...execution }),
    );
  } finally {
    store.close();
  }
}

/** Launch the worker, dispatch the execution request, report the result. */
async function detachExecution(
  store: string | undefined,
  runId: string,
  request: Extract<LocalWorkerRequest, { method: "start" | "resume" }>,
): Promise<void> {
  const launched = await launchLocalWorker({
    runId,
    databasePath: absoluteDatabasePath(store),
    executable: resolveWorkerExecutable(),
  });
  // A lost acknowledgement is uncertain by contract: never auto-retried.
  const snapshot = await workerRequest(launched.socketPath, request).catch(
    (error: unknown) => {
      if (error instanceof LocalWorkerTransportError && error.uncertain) {
        console.error(
          `The ${request.method} request outcome is uncertain and was NOT retried. ` +
            `Inspect the run before issuing it again: pensar agent-runs show ${runId}`,
        );
      }
      throw error;
    },
  );
  console.log(
    JSON.stringify(
      {
        detached: true,
        socketPath: launched.socketPath,
        logPath: launched.logPath,
        snapshot,
      },
      null,
      2,
    ),
  );
}

type Execution = {
  authConfig: AIAuthConfig;
  eventBus: AgentEventBus;
  abortSignal: AbortSignal;
};

/** Shared start/resume wiring: auth, streamed text, and process signals. */
async function runExecution(
  invoke: (
    execution: Execution,
  ) => Promise<{ started: boolean; record: unknown }>,
): Promise<void> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const eventBus = new AgentEventBus();
  const onText = ({ text }: { text: string }) => process.stderr.write(text);
  eventBus.on("text-delta", onText);
  process.on("SIGINT", abort);
  process.on("SIGTERM", abort);
  try {
    const outcome = await invoke({
      authConfig: buildAuthConfig(await config.get()),
      eventBus,
      abortSignal: controller.signal,
    }).catch((error: unknown) => {
      if (error instanceof RunRecoveryBlockedError) {
        // Blockers are the actionable answer; rethrow keeps the exit code.
        console.log(
          JSON.stringify({ blocked: true, blockers: error.blockers }, null, 2),
        );
      }
      throw error;
    });
    console.log(
      JSON.stringify(
        { started: outcome.started, record: outcome.record },
        null,
        2,
      ),
    );
  } finally {
    process.off("SIGINT", abort);
    process.off("SIGTERM", abort);
    eventBus.off("text-delta", onText);
  }
}
