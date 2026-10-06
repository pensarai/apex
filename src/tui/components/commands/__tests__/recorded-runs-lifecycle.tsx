import { mock } from "bun:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act, useEffect, useRef } from "react";
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
const client: RecordedRunClient = {
  databasePath: "/fake/runs.sqlite",
  list: async () => [record],
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
    assert.equal(
      scenario,
      "spec-start-once",
      "observation must never start execution",
    );
    calls.push({ method: "start", args });
    return { socketPath: "/fake/socket", logPath: "/fake/log", snapshot };
  },
  resume: async (...args) => {
    calls.push({ method: "resume", args });
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
const specDirectory =
  scenario === "spec-start-once"
    ? await mkdtemp(join(tmpdir(), "apex-tui-spec-"))
    : undefined;
const specPath = specDirectory ? join(specDirectory, "run.json") : undefined;
if (specPath) await writeFile(specPath, JSON.stringify(spec));
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
          : scenario === "list-attach-detach"
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
