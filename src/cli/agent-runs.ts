import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { buildAuthConfig } from "../core/ai";
import { inspectSessionEvidence, runRecordedAgent } from "../core/api";
import { config } from "../core/config";
import { AgentEventBus } from "../core/eventBus";
import { openSqliteRunStore } from "../core/runtime/sqliteRunStore";

const HELP = `pensar agent-runs — Record and inspect local agent runs

Usage:
  pensar agent-runs start --spec <file> [--store <database>]
  pensar agent-runs list [--store <database>]
  pensar agent-runs show <runId> [--context] [--evidence] [--models] [--tools] [--store <database>]

The JSON spec supplies a stable runId and explicit model, tools and scope.
Repeating a runId never starts another execution. Changed inputs are rejected.
Statuses describe the last saved state, not whether a worker is still alive.
Interrupted runs cannot resume yet. Existing sessions are unchanged.

Recording requires Bun or Node 22.13+. See docs/recorded-runs.md.
`;

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
  if (
    extra.length ||
    (command !== "show" && runId !== undefined) ||
    !["start", "list", "show"].includes(command) ||
    (command === "show" && !runId) ||
    (command === "start" && !values.spec) ||
    (command !== "show" &&
      (values.context || values.evidence || values.models || values.tools)) ||
    (command !== "start" && values.spec !== undefined)
  ) {
    throw new Error(`Invalid agent-runs arguments.\n${HELP}`);
  }

  const store = await openSqliteRunStore(values.store);
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
          },
          null,
          2,
        ),
      );
      return;
    }

    if (!values.spec) throw new Error("A run spec is required");
    const spec = JSON.parse(await readFile(values.spec, "utf8"));
    const controller = new AbortController();
    const abort = () => controller.abort();
    const eventBus = new AgentEventBus();
    const onText = ({ text }: { text: string }) => process.stderr.write(text);
    eventBus.on("text-delta", onText);
    process.on("SIGINT", abort);
    process.on("SIGTERM", abort);
    try {
      const outcome = await runRecordedAgent({
        spec,
        store,
        authConfig: buildAuthConfig(await config.get()),
        eventBus,
        abortSignal: controller.signal,
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
  } finally {
    store.close();
  }
}
