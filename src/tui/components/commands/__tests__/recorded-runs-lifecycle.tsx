import { mock } from "bun:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act, useEffect, useRef } from "react";
import {
  LocalWorkerRequestRejectedError,
  LocalWorkerTransportError,
} from "../../../../core/runtime/localWorkerTransport";
import type {
  RecordedRunClient,
  RecordedRunView,
} from "../../../../core/runtime/recordedRunClient";
import type {
  RecordedApproval,
  RunControlRecord,
} from "../../../../core/runtime/runControlStore";
import type { RunObservation } from "../../../../core/runtime/runObservation";
import type { RecordedRunSpec } from "../../../../core/runtime/runStore";
import { RunRecordSchema } from "../../../../core/runtime/runStore";

const scenario = process.argv[2];
assert.ok(scenario, "a scenario argument is required");

const RUN_ID = "run_c5_lifecycle";
const EXEC_ID = "exec_00000000-0000-4000-8000-00000000c5ee";

const spec: RecordedRunSpec = {
  schemaVersion: 1,
  configVersion: 1,
  runId: RUN_ID,
  prompt: "Request the target homepage once and summarize the response.",
  target: "http://127.0.0.1:8080",
  model: "claude-haiku-4-5",
  activeTools: ["http_request", "execute_command"],
  environment: { kind: "local", cwd: "/tmp" },
  scope: {
    version: 1,
    allowedHosts: ["127.0.0.1"],
    allowedPorts: [8080],
    strictScope: true,
    allowDestructiveActions: false,
    allowRateLimitTesting: false,
  },
  credentialRefs: [],
};

const record = RunRecordSchema.parse({
  schemaVersion: 1,
  spec,
  sessionId: "ses_c5lifecycle000000000000000",
  attemptId: EXEC_ID,
  runtimeVersion: "c5-test",
  status: "running",
  admittedAt: "2026-10-06T10:00:00.000Z",
  updatedAt: "2026-10-06T10:01:00.000Z",
});

const control: RunControlRecord = {
  schemaVersion: 1,
  runId: RUN_ID,
  executionAttemptId: EXEC_ID,
  intent: "run",
  revision: 3,
  updatedAt: "2026-10-06T10:01:00.000Z",
};

const approvals: RecordedApproval[] = [
  {
    schemaVersion: 1,
    approvalId: "11111111-1111-4111-8111-111111111111",
    runId: RUN_ID,
    executionAttemptId: EXEC_ID,
    toolCallId: "tc_a",
    toolName: "http_request",
    input: { url: "http://127.0.0.1:8080/" },
    specDigest: "f".repeat(64),
    context: { epoch: 1, revision: 1 },
    state: "pending",
    createdAt: "2026-10-06T10:00:30.000Z",
  },
  {
    schemaVersion: 1,
    approvalId: "22222222-2222-4222-8222-222222222222",
    runId: RUN_ID,
    executionAttemptId: EXEC_ID,
    toolCallId: "tc_b",
    toolName: "execute_command",
    input: { command: "id" },
    specDigest: "f".repeat(64),
    context: { epoch: 1, revision: 1 },
    state: "pending",
    createdAt: "2026-10-06T10:00:40.000Z",
  },
];

const observation: RunObservation = {
  record,
  context: {
    epoch: 1,
    revision: 1,
    messages: [{ role: "user", content: "first" }],
    system: "system prompt",
  },
  control,
  approvals,
};

const savedRunningOffline: RecordedRunView = {
  runId: RUN_ID,
  observation,
  worker: null,
  connection: "offline",
};

type Call = { method: string; args: unknown[] };
const calls: Call[] = [];
let watchSignal: AbortSignal | undefined;
let closes = 0;
let nextView: RecordedRunView | undefined;
let wake: (() => void) | undefined;
const saved =
  scenario === "scroll-transcript"
    ? {
        ...savedRunningOffline,
        observation: {
          ...observation,
          context: {
            ...observation.context!,
            messages: [
              {
                role: "user" as const,
                content: Array.from(
                  { length: 60 },
                  (_, i) => `committed-line-${i}`,
                ).join("\n"),
              },
            ],
          },
        },
      }
    : savedRunningOffline;
const snapshot = {
  protocolVersion: 1 as const,
  workerId: "worker-test",
  runId: RUN_ID,
  phase: "executing" as const,
  sequence: 1,
  observation,
};
// The spec-started run is distinct from the pre-existing listed run so a
// hijack (following the wrong run) cannot pass by coincidence.
const STARTED_RUN_ID = "run_c5_spec_started";
const startedSpec: RecordedRunSpec = { ...spec, runId: STARTED_RUN_ID };
const startedRecord =
  scenario === "spec-start-once"
    ? record
    : RunRecordSchema.parse({ ...record, spec: startedSpec });
const startedSnapshot =
  scenario === "spec-start-once"
    ? snapshot
    : {
        ...snapshot,
        runId: STARTED_RUN_ID,
        observation: { ...observation, record: startedRecord },
      };
// Rows ordered by run_id like the real store: early sorts before the
// pre-existing run, zulu after it.
const EARLY_RUN_ID = "run_c5_early_admit";
const ZULU_RUN_ID = "run_c5_zulu";
const earlyRecord = RunRecordSchema.parse({
  ...record,
  spec: { ...spec, runId: EARLY_RUN_ID },
});
const zuluRecord = RunRecordSchema.parse({
  ...record,
  spec: { ...spec, runId: ZULU_RUN_ID },
});
const listedRecords =
  scenario === "list-refresh-preserves-pending-move" ||
  scenario === "list-refresh-replaces-vanished-selection"
    ? [record, zuluRecord]
    : [record];
const client: RecordedRunClient = {
  databasePath: "/fake/runs.sqlite",
  list: async () => {
    if (listGated)
      await new Promise<void>((resolve) => {
        finishList = resolve;
      });
    return [...listedRecords];
  },
  observe: async () => {
    throw new Error("the dialog follows through watch");
  },
  watch: async function* (runId, signal) {
    calls.push({ method: "watch", args: [runId] });
    watchSignal = signal;
    yield saved;
    while (!signal.aborted) {
      await new Promise<void>((resolve) => {
        wake = () => resolve();
        if (nextView || signal.aborted) resolve();
        else signal.addEventListener("abort", wake, { once: true });
      });
      if (wake) signal.removeEventListener("abort", wake);
      wake = undefined;
      if (nextView) {
        const update = nextView;
        nextView = undefined;
        yield update;
      }
    }
  },
  start: async (...args) => {
    assert.ok(
      scenario.startsWith("spec-start"),
      "observation must never start execution",
    );
    calls.push({ method: "start", args });
    if (scenario === "spec-start-uncertain") {
      listedRecords.push(startedRecord);
      throw new LocalWorkerTransportError("Worker response was interrupted", {
        uncertain: true,
      });
    }
    if (scenario !== "spec-start-once") {
      // Pending starts complete only when the scenario resolves them, so
      // the dialog state at completion time is under test control.
      await new Promise<void>((resolve) => {
        finishStart = resolve;
      });
      listedRecords.push(startedRecord);
    }
    return {
      socketPath: "/fake/socket",
      logPath: "/fake/log",
      snapshot: startedSnapshot,
    };
  },
  resume: async (...args) => {
    calls.push({ method: "resume", args });
    if (scenario === "resume-uncertain") {
      throw new LocalWorkerTransportError("Worker response was interrupted", {
        uncertain: true,
      });
    }
    if (scenario === "resume-rejected") {
      throw new LocalWorkerRequestRejectedError(
        "Recovery attempt changed; inspect the run again",
      );
    }
    return { socketPath: "/fake/socket", logPath: "/fake/log", snapshot };
  },
  requestControl: async (...args) => {
    calls.push({ method: "requestControl", args });
    return { ...control, intent: args[1], revision: args[2] + 1 };
  },
  resolveApproval: async (...args) => {
    calls.push({ method: "resolveApproval", args });
    const approval = approvals.find((item) => item.approvalId === args[1]);
    assert.ok(approval);
    return { ...approval, state: args[2] };
  },
  close: async () => {
    closes += 1;
  },
};
let finishOpen: ((client: RecordedRunClient) => void) | undefined;
let finishStart: (() => void) | undefined;
let listGated = false;
let finishList: (() => void) | undefined;
mock.module(
  `${import.meta.dirname}/../../../../core/runtime/recordedRunClient.ts`,
  () => ({
    openRecordedRunClient: () =>
      new Promise<RecordedRunClient>((resolve) => {
        finishOpen = resolve;
      }),
  }),
);
const { RecordedRunsDialog } = await import("../recorded-runs.tsx");
const { registerBuiltinThemes, ThemeProvider } = await import("../../../theme");
const { TerminalDimensionsProvider } = await import(
  "../../../context/dimensions"
);
const { DialogProvider, useDialog } = await import("../../../context/dialog");
registerBuiltinThemes();
const errors: unknown[][] = [];
const originalError = console.error;
console.error = (...args: unknown[]) => errors.push(args);
const executable = { command: "bun", args: ["/fixture/src/cli.ts"] };
const specDirectory = scenario.startsWith("spec-start")
  ? await mkdtemp(join(tmpdir(), "apex-tui-spec-"))
  : undefined;
const specPath = specDirectory ? join(specDirectory, "run.json") : undefined;
if (specPath)
  await writeFile(
    specPath,
    JSON.stringify(scenario === "spec-start-once" ? spec : startedSpec),
  );
function OpenDialog() {
  const dialog = useDialog();
  const opened = useRef(false);
  useEffect(() => {
    if (opened.current) return;
    opened.current = true;
    dialog.replace(
      <RecordedRunsDialog
        {...(specPath
          ? { specPath }
          : scenario === "list-attach-detach" ||
              scenario.startsWith("list-refresh")
            ? {}
            : { runId: RUN_ID })}
        executable={executable}
      />,
      { size: "xlarge" },
    );
  }, [dialog]);
  return null;
}
const setup = await testRender(
  <ThemeProvider>
    <TerminalDimensionsProvider>
      <DialogProvider>
        <OpenDialog />
      </DialogProvider>
    </TerminalDimensionsProvider>
  </ThemeProvider>,
  {
    width: 120,
    height: scenario === "scroll-transcript" ? 24 : 40,
    exitOnCtrlC: false,
  },
);
const settle = async () => {
  for (let i = 0; i < 6; i++) await act(async () => {});
  if (!setup.renderer.isDestroyed) await act(() => setup.renderOnce());
};
const frame = async () => {
  await settle();
  return setup.captureCharFrame();
};
const press = async (key: string) => {
  await act(async () => {
    setup.mockInput.pressKey(key);
    // A lone escape is buffered to distinguish it from an escape sequence.
    if (key === "ESCAPE") await Bun.sleep(100);
  });
  await settle();
};
const rendered = (text: string, must: string) =>
  assert.ok(
    text.includes(must),
    `Missing ${JSON.stringify(must)} in:\n${text}`,
  );
const push = async (view: RecordedRunView) => {
  await act(async () => {
    nextView = view;
    wake?.();
  });
  await settle();
};
try {
  await settle();
  if (scenario !== "late-open-detach") {
    assert.ok(finishOpen);
    await act(async () => finishOpen?.(client));
    await settle();
  }
  if (scenario === "direct-run-offline") {
    const text = await frame();
    assert.deepEqual(calls, [{ method: "watch", args: [RUN_ID] }]);
    rendered(text, "offline");
    rendered(text, "Saved status: running");
    rendered(text, "following");
    rendered(text, "Context epoch 1 · revision 1 · 1 messages");
    rendered(text, "Pending decisions (2, decided 0)");
    rendered(text, '"url": "http://127.0.0.1:8080/"');
    rendered(text, "Saved transcript (committed)");
    rendered(text, "first");
    assert.ok(!text.includes("live"));
  } else if (scenario === "list-attach-detach") {
    rendered(await frame(), RUN_ID);
    assert.equal(calls.length, 0);
    await press("RETURN");
    rendered(await frame(), "Saved status: running");
    assert.ok(watchSignal);
    await press("ESCAPE");
    assert.ok(watchSignal.aborted);
    assert.equal(closes, 1);
    assert.deepEqual(calls, [{ method: "watch", args: [RUN_ID] }]);
    assert.ok(!(await frame()).includes("Recorded Run"));
  } else if (scenario === "approval-and-control-binding") {
    rendered(await frame(), "Selected input — http_request");
    await press("ARROW_DOWN");
    rendered(await frame(), '"command": "id"');
    await press("n");
    assert.deepEqual(calls.at(-1), {
      method: "resolveApproval",
      args: [RUN_ID, approvals[1]!.approvalId, "denied"],
    });
    rendered(await frame(), "Rejected execute_command");
    await press("ARROW_UP");
    await press("y");
    assert.deepEqual(calls.at(-1), {
      method: "resolveApproval",
      args: [RUN_ID, approvals[0]!.approvalId, "approved"],
    });
    await press("p");
    assert.deepEqual(calls.at(-1), {
      method: "requestControl",
      args: [RUN_ID, "pause", 3],
    });
    rendered(await frame(), "Pause requested");
    await press("r");
    assert.deepEqual(calls.at(-1), {
      method: "resume",
      args: [RUN_ID, EXEC_ID, executable],
    });
    rendered(await frame(), "Resume requested");
    assert.equal(calls.filter((call) => call.method === "watch").length, 1);
  } else if (scenario === "resume-uncertain") {
    await press("r");
    let text = await frame();
    rendered(text, "Resume outcome uncertain:");
    rendered(text, "may have applied and was not retried");
    rendered(text, "Inspect the run before retrying");
    assert.ok(!text.includes("Resume failed"));
    await push({ ...saved, connection: "connected", worker: snapshot });
    text = await frame();
    rendered(text, "Resume outcome uncertain:");
    assert.equal(calls.filter((call) => call.method === "resume").length, 1);
    // Uncertainty does not block an operator's pause or stop request.
    await press("p");
    await press("s");
    assert.deepEqual(
      calls.filter((call) => call.method === "requestControl"),
      [
        { method: "requestControl", args: [RUN_ID, "pause", 3] },
        { method: "requestControl", args: [RUN_ID, "stop", 3] },
      ],
    );
    // Explicit retry uses the inspected attempt; the runtime fences execution.
    await press("r");
    assert.deepEqual(
      calls.filter((call) => call.method === "resume"),
      Array.from({ length: 2 }, () => ({
        method: "resume",
        args: [RUN_ID, EXEC_ID, executable],
      })),
    );
  } else if (scenario === "resume-rejected") {
    await press("r");
    const text = await frame();
    rendered(text, "Resume failed: Recovery attempt changed");
    assert.ok(!text.includes("outcome uncertain"));
    assert.equal(calls.filter((call) => call.method === "resume").length, 1);
  } else if (scenario === "spec-start-uncertain") {
    for (
      let i = 0;
      i < 20 && !calls.some((call) => call.method === "start");
      i++
    )
      await act(async () => {
        await Bun.sleep(10);
      });
    const text = await frame();
    rendered(text, "Start outcome uncertain:");
    rendered(text, "may have applied and was not retried");
    rendered(text, "Inspect the run before retrying");
    rendered(text, STARTED_RUN_ID);
    assert.ok(!text.includes("Start failed"));
    await press("ARROW_DOWN");
    await press("RETURN");
    assert.deepEqual(calls.at(-1), {
      method: "watch",
      args: [STARTED_RUN_ID],
    });
    await press("b");
    assert.equal(calls.filter((call) => call.method === "start").length, 1);
  } else if (scenario === "sticky-worker-error") {
    await push({
      ...saved,
      connection: "connected",
      worker: {
        ...snapshot,
        phase: "settled",
        error: {
          message: "Recovery blocked",
          blockers: ["Unknown tool outcome"],
        },
      },
    });
    rendered(await frame(), "Unknown tool outcome");
    await push(saved);
    const text = await frame();
    rendered(text, "offline");
    rendered(text, "Recovery blocked");
    rendered(text, "Unknown tool outcome");
  } else if (scenario === "late-open-detach") {
    rendered(await frame(), "Opening run store");
    assert.ok(finishOpen);
    await press("ESCAPE");
    await act(async () => finishOpen?.(client));
    await settle();
    assert.equal(closes, 1);
    assert.equal(calls.length, 0);
  } else if (scenario === "spec-start-once") {
    // File IO completes outside React; keep its completion inside act.
    for (let i = 0; i < 20 && !watchSignal; i++)
      await act(async () => {
        await Bun.sleep(10);
      });
    rendered(await frame(), "Started detached run");
    rendered(await frame(), "Saved status: running");
    assert.deepEqual(
      calls.filter((call) => call.method === "start"),
      [{ method: "start", args: [spec, executable] }],
    );
    assert.equal(calls.filter((call) => call.method === "watch").length, 1);
  } else if (scenario === "spec-start-back-to-list") {
    for (let i = 0; i < 20 && !finishStart; i++)
      await act(async () => {
        await Bun.sleep(10);
      });
    assert.ok(finishStart, "the pending start never began");
    // Back to the list while the start is still pending.
    await press("b");
    rendered(await frame(), RUN_ID);
    await act(async () => finishStart?.());
    await settle();
    const text = await frame();
    rendered(text, "Recorded Runs");
    assert.ok(!text.includes(`Recorded Run ${STARTED_RUN_ID}`));
    rendered(text, STARTED_RUN_ID);
    rendered(text, "Started detached run");
    assert.equal(calls.filter((call) => call.method === "watch").length, 0);
    await press("ARROW_DOWN");
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${STARTED_RUN_ID}`);
    assert.deepEqual(
      calls.filter((call) => call.method === "watch"),
      [{ method: "watch", args: [STARTED_RUN_ID] }],
    );
    // The refreshed list keeps the launched run visible after backing out.
    await press("b");
    const listText = await frame();
    rendered(listText, STARTED_RUN_ID);
    rendered(listText, RUN_ID);
  } else if (scenario === "spec-start-viewing-other-run") {
    for (let i = 0; i < 20 && !finishStart; i++)
      await act(async () => {
        await Bun.sleep(10);
      });
    assert.ok(finishStart, "the pending start never began");
    await press("b");
    rendered(await frame(), RUN_ID);
    // Open the pre-existing run; the launched run must not hijack it.
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${RUN_ID}`);
    await act(async () => finishStart?.());
    await settle();
    const text = await frame();
    rendered(text, `Recorded Run ${RUN_ID}`);
    rendered(text, "Started detached run");
    assert.deepEqual(
      calls.filter((call) => call.method === "watch"),
      [{ method: "watch", args: [RUN_ID] }],
    );
  } else if (scenario === "list-refresh-keeps-selection") {
    rendered(await frame(), RUN_ID);
    rendered(await frame(), `› ${RUN_ID}`);
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${RUN_ID}`);
    // A newly admitted run sorting before the selection shifts the rows.
    listedRecords.unshift(earlyRecord);
    await press("b");
    const text = await frame();
    rendered(text, EARLY_RUN_ID);
    rendered(text, `› ${RUN_ID}`);
    // Enter still opens the run the operator selected, not the insert.
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${RUN_ID}`);
  } else if (scenario === "list-refresh-preserves-pending-move") {
    rendered(await frame(), RUN_ID);
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${RUN_ID}`);
    listedRecords.unshift(earlyRecord);
    listGated = true;
    await press("b");
    for (let i = 0; i < 20 && !finishList; i++)
      await act(async () => {
        await Bun.sleep(10);
      });
    assert.ok(finishList, "the pending list request never began");
    // The operator moves the selection while the request is still pending.
    await press("ARROW_DOWN");
    await act(async () => finishList?.());
    await settle();
    const text = await frame();
    rendered(text, `› ${ZULU_RUN_ID}`);
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${ZULU_RUN_ID}`);
  } else if (scenario === "list-refresh-replaces-vanished-selection") {
    rendered(await frame(), RUN_ID);
    await press("ARROW_DOWN");
    rendered(await frame(), `› ${ZULU_RUN_ID}`);
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${ZULU_RUN_ID}`);
    // The selected run disappears from the refreshed list.
    listedRecords.splice(1, 1);
    await press("b");
    const text = await frame();
    rendered(text, `› ${RUN_ID}`);
    await press("RETURN");
    rendered(await frame(), `Recorded Run ${RUN_ID}`);
  } else if (scenario === "scroll-transcript") {
    await press("END");
    rendered(await frame(), "committed-line-59");
    await press("HOME");
    rendered(await frame(), "Saved status: running");
  } else throw new Error(`Unknown scenario: ${scenario}`);
  assert.deepEqual(errors, [], "the dialog must not log errors");
} finally {
  await act(async () => {
    if (!setup.renderer.isDestroyed) setup.renderer.destroy();
  });
  console.error = originalError;
  if (specDirectory) await rm(specDirectory, { recursive: true, force: true });
}
