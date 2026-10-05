import type { ModelMessage } from "ai";
import { describe, expect, it } from "vitest";
import { buildSessionWorkspaceSection } from "../agents/offSecAgent";
import type { SessionInfo } from "../session";
import { restoreRunContext } from "./runRecoveryContext";
import type { RunRecord } from "./runStore";
import { RecordedRunSpecSchema, RunRecordSchema } from "./runStore";

const SESSION_ID = "ses_recorded0000000000000000";
const ATTEMPT_ID = "exec_00000000-0000-4000-8000-000000000001";
const CWD = "/workspace/target";
const BASE_SYSTEM = "You are an expert penetration tester.";

function spec(overrides: Record<string, unknown> = {}) {
  return RecordedRunSpecSchema.parse({
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_recovery",
    prompt: "test the target",
    target: "https://example.com",
    model: "claude-haiku-4-5",
    system: BASE_SYSTEM,
    activeTools: ["read_file", "grep"],
    environment: { kind: "local", cwd: CWD },
    scope: { version: 1, strictScope: true },
    ...overrides,
  });
}

function record(specOverrides: Record<string, unknown> = {}): RunRecord {
  return RunRecordSchema.parse({
    schemaVersion: 1,
    spec: spec(specOverrides),
    sessionId: SESSION_ID,
    attemptId: ATTEMPT_ID,
    runtimeVersion: "0.0.0-test",
    status: "paused",
    admittedAt: "2026-10-05T00:00:00.000Z",
    updatedAt: "2026-10-05T00:00:00.000Z",
  });
}

function session(configOverrides: Record<string, unknown> = {}): SessionInfo {
  return {
    id: SESSION_ID,
    version: "1",
    targets: ["https://example.com"],
    time: { created: 0, updated: 0 },
    rootPath: "/sessions/ses_recorded",
    logsPath: "/sessions/ses_recorded/logs",
    findingsPath: "/sessions/ses_recorded/findings",
    scratchpadPath: "/sessions/ses_recorded/scratchpad",
    pocsPath: "/sessions/ses_recorded/pocs",
    config: {
      agentCwd: CWD,
      scopeConstraints: {
        allowedHosts: [],
        allowedPorts: [],
        strictScope: true,
      },
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
      taskDriven: false,
      disableSubagents: true,
      ...configOverrides,
    },
  } as SessionInfo;
}

function workspaceOf(
  sessionFixture: SessionInfo,
  specFixture: ReturnType<typeof spec>,
): string {
  return buildSessionWorkspaceSection(
    sessionFixture,
    specFixture.environment.cwd,
    specFixture.activeTools,
  );
}

const user = (text: string): ModelMessage => ({
  role: "user",
  content: [{ type: "text", text }],
});

function contextFixture(
  system: string | null,
  messages: ModelMessage[],
): Parameters<typeof restoreRunContext>[0]["context"] {
  return { epoch: 2, revision: 5, system, messages };
}

describe("restoreRunContext", () => {
  it("restores a non-cached system: exact workspace suffix removed, messages untouched", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const conversation: ModelMessage[] = [
      user("original task"),
      {
        role: "assistant",
        content: [{ type: "text", text: "findings so far" }],
      },
    ];

    const restored = restoreRunContext({
      record: rec,
      session: ses,
      context: contextFixture(BASE_SYSTEM + workspace, conversation),
    });

    expect(restored.baseSystem).toBe(BASE_SYSTEM);
    expect(restored.messages).toEqual(conversation);
  });

  it("restores a cached system: peels only the single leading system message", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const conversation: ModelMessage[] = [user("original task")];

    const restored = restoreRunContext({
      record: rec,
      session: ses,
      context: contextFixture(null, [
        { role: "system", content: BASE_SYSTEM + workspace },
        ...conversation,
      ]),
    });

    expect(restored.baseSystem).toBe(BASE_SYSTEM);
    expect(restored.messages).toEqual(conversation);
  });

  it("recomposes to exactly one workspace occurrence and the original effective system", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const effective = BASE_SYSTEM + workspace;

    const restored = restoreRunContext({
      record: rec,
      session: ses,
      context: contextFixture(effective, [user("hi")]),
    });

    expect(restored.baseSystem + workspaceOf(ses, rec.spec)).toBe(effective);
    expect(effective.split(workspace).length - 1).toBe(1);
  });

  it("preserves an evolved default base instead of regenerating one", () => {
    // A run admitted without spec.system may have evolved its default base
    // (e.g. appended operator guidance); recovery must keep the saved bytes.
    const rec = record({ system: undefined });
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const evolvedBase = `${BASE_SYSTEM}\nOperator note: stay in scope.`;

    const restored = restoreRunContext({
      record: rec,
      session: ses,
      context: contextFixture(evolvedBase + workspace, [user("hi")]),
    });

    expect(restored.baseSystem).toBe(evolvedBase);
  });

  it("keeps message metadata untouched", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const conversation: ModelMessage[] = [
      user("probe"),
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "tc_1",
            toolName: "read_file",
            input: { path: "a.txt" },
            providerOptions: { google: { thoughtSignature: "sig-1" } },
          },
        ],
        providerOptions: { anthropic: { signature: "sig-2" } },
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tc_1",
            toolName: "read_file",
            output: { type: "text", value: "file body" },
          },
        ],
      },
    ];

    const restored = restoreRunContext({
      record: rec,
      session: ses,
      context: contextFixture(BASE_SYSTEM + workspace, conversation),
    });

    expect(restored.messages).toEqual(conversation);
  });

  it("detaches the returned messages from the input context", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const conversation: ModelMessage[] = [user("original task")];

    const restored = restoreRunContext({
      record: rec,
      session: ses,
      context: contextFixture(BASE_SYSTEM + workspace, conversation),
    });

    (restored.messages[0].content as Array<{ text: string }>)[0].text =
      "mutated";
    expect((conversation[0].content as Array<{ text: string }>)[0].text).toBe(
      "original task",
    );
  });

  it("blocks when the recovered base does not match the admitted spec system", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: ses,
        // Saved base drifted from the admitted system — environment or
        // runtime mismatch, never silently accepted.
        context: contextFixture(`A different base.${workspace}`, []),
      }),
    ).toThrow(/recovered base system does not match/);
  });

  it("blocks when the saved system does not end with the current workspace section", () => {
    const rec = record();
    // A different session root yields a different current section, so the
    // saved system no longer ends with it — same-session drift blocks.
    const ses = {
      ...session(),
      rootPath: "/elsewhere/session",
      logsPath: "/elsewhere/session/logs",
      findingsPath: "/elsewhere/session/findings",
      scratchpadPath: "/elsewhere/session/scratchpad",
      pocsPath: "/elsewhere/session/pocs",
    };
    const workspace = workspaceOf(session(), rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: ses,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      }),
    ).toThrow(/does not end with the current session workspace section/);
  });

  it("blocks when the workspace section occurs twice in the saved system", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: ses,
        context: contextFixture(BASE_SYSTEM + workspace + workspace, []),
      }),
    ).toThrow(/occurs more than once/);
  });

  it("blocks a cached context without a leading system message", () => {
    const rec = record();
    const ses = session();

    expect(() =>
      restoreRunContext({
        record: rec,
        session: ses,
        context: contextFixture(null, [user("hi")]),
      }),
    ).toThrow(/no leading system message/);
  });

  it("blocks a context carrying both a system field and a leading system message", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: ses,
        context: contextFixture(BASE_SYSTEM + workspace, [
          { role: "system", content: BASE_SYSTEM + workspace },
          user("hi"),
        ]),
      }),
    ).toThrow(/both a system field and a leading system message/);
  });

  it.each([
    {
      name: "session id",
      mutate: (rec: RunRecord, ses: SessionInfo) => ({
        record: rec,
        session: { ...ses, id: "ses_other00000000000000000000" },
      }),
    },
    {
      name: "targets",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: { ...ses, targets: ["https://other.example.com"] },
      }),
    },
    {
      name: "working directory",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: { ...ses.config, agentCwd: "/elsewhere" },
        },
      }),
    },
    {
      name: "scope hosts",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: {
            ...ses.config,
            scopeConstraints: {
              ...ses.config?.scopeConstraints,
              allowedHosts: ["evil.example.com"],
            },
          },
        },
      }),
    },
    {
      name: "strict scope",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: {
            ...ses.config,
            scopeConstraints: {
              ...ses.config?.scopeConstraints,
              strictScope: false,
            },
          },
        },
      }),
    },
    {
      name: "destructive flag",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: { ...ses.config, allowDestructiveActions: true },
        },
      }),
    },
    {
      name: "rate-limit flag",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: { ...ses.config, allowRateLimitTesting: true },
        },
      }),
    },
    {
      name: "subagents enabled",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: { ...ses.config, disableSubagents: false },
        },
      }),
    },
    {
      name: "task-driven flag",
      mutate: (_rec: RunRecord, ses: SessionInfo) => ({
        record: _rec,
        session: {
          ...ses,
          config: { ...ses.config, taskDriven: true },
        },
      }),
    },
  ])("blocks on $name mismatch with the admitted record", ({ mutate }) => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const input = mutate(rec, ses);

    expect(() =>
      restoreRunContext({
        record: input.record,
        session: input.session,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      }),
    ).toThrow(/Run recovery blocked/);
  });

  it.each([
    {
      name: "findings path",
      field: "findingsPath" as const,
      value: "/elsewhere/findings",
    },
    {
      name: "scratchpad path",
      field: "scratchpadPath" as const,
      value: "/elsewhere/scratchpad",
    },
    { name: "logs path", field: "logsPath" as const, value: "/elsewhere/logs" },
    { name: "pocs path", field: "pocsPath" as const, value: "/elsewhere/pocs" },
  ])("blocks a relocated $name", ({ field, value }) => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: { ...ses, [field]: value } as SessionInfo,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      }),
    ).toThrow(/standard .* location under the session root/);
  });

  it("accepts absent or empty headers, blocks custom ones", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const restore = (configHeaders: unknown) =>
      restoreRunContext({
        record: rec,
        session: {
          ...ses,
          config: { ...ses.config, headers: configHeaders },
        } as SessionInfo,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      });

    expect(restore(undefined).baseSystem).toBe(BASE_SYSTEM);
    expect(restore({}).baseSystem).toBe(BASE_SYSTEM);
    expect(() => restore({ authorization: "Bearer secret" })).toThrow(
      /custom HTTP headers/,
    );
  });

  it.each([
    {
      name: "auth credentials",
      config: { authCredentials: { username: "u", password: "p" } },
    },
    {
      name: "SMTP configuration",
      config: { smtpConfig: { host: "smtp.example.com" } },
    },
    {
      name: "email inboxes",
      config: {
        emailIntegration: { inboxes: [{ address: "a@example.com" }] },
      },
    },
  ])("blocks session $name that fresh admission never set", ({ config }) => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: {
          ...ses,
          config: { ...ses.config, ...config },
        } as SessionInfo,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      }),
    ).toThrow(/Run recovery blocked/);
  });

  it("blocks a session holding an in-memory credential manager", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);

    expect(() =>
      restoreRunContext({
        record: rec,
        session: {
          ...ses,
          credentialManager: { add: () => {} } as never,
        } as SessionInfo,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      }),
    ).toThrow(/in-memory credential manager/);
  });

  it("blocks a session without recorded-run configuration", () => {
    const rec = record();
    const ses = session();
    const workspace = workspaceOf(ses, rec.spec);
    const bare = { ...session(), config: undefined } as SessionInfo;

    expect(() =>
      restoreRunContext({
        record: rec,
        session: bare,
        context: contextFixture(BASE_SYSTEM + workspace, []),
      }),
    ).toThrow(/no recorded-run configuration/);
  });
});
