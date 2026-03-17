import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { testRender } from "@opentui/react/test-utils";

const harness = vi.hoisted(() => ({
  keyboardHandler: null as null | ((key: Record<string, unknown>) => void),
  inputAreaProps: null as null | Record<string, unknown>,
  runCalls: [] as Array<Record<string, unknown>>,
  createdSession: {
    id: "ses_created",
    name: "Created Session",
    version: "0.0.0",
    targets: ["https://example.com"],
    time: { created: 1, updated: 1 },
    rootPath: "/tmp/operator-session",
    logsPath: "/tmp/operator-session/logs",
    findingsPath: "/tmp/operator-session/findings",
    scratchpadPath: "/tmp/operator-session/scratchpad",
    pocsPath: "/tmp/operator-session/pocs",
  },
}));

const runOffensiveSecurityAgentMock = vi.hoisted(() => vi.fn());

vi.mock("@opentui/react", async (importActual) => {
  const actual = await importActual<typeof import("@opentui/react")>();
  return {
    ...actual,
    useKeyboard: (handler: (key: Record<string, unknown>) => void) => {
      harness.keyboardHandler = handler;
    },
  };
});

vi.mock("../../../core/api/offesecAgent", () => ({
  runOffensiveSecurityAgent: runOffensiveSecurityAgentMock,
}));

vi.mock("../../../core/session", () => ({
  sessions: {
    get: vi.fn(),
    hasOperatorState: vi.fn(() => false),
    loadOperatorState: vi.fn(),
    getResumeMessages: vi.fn((messages) => messages),
  },
}));

vi.mock("../../context/agent", () => ({
  useAgent: () => ({
    model: { id: "test-model", name: "Test Model" },
    setModel: vi.fn(),
    isModelUserSelected: false,
    setThinking: vi.fn(),
    setIsExecuting: vi.fn(),
    tokenUsage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    addTokenUsage: vi.fn(),
    resetTokenUsage: vi.fn(),
    setSessionCwd: vi.fn(),
  }),
}));

vi.mock("../../context/route", () => ({
  useRoute: () => ({ navigate: vi.fn() }),
}));

vi.mock("../../context/config", () => ({
  useConfig: () => ({ data: {}, update: vi.fn() }),
}));

vi.mock("../../context/command", () => ({
  useCommand: () => ({
    autocompleteOptions: [],
    executeCommand: vi.fn(),
    resolveSkillContent: vi.fn(() => null),
    skills: [],
  }),
}));

vi.mock("../../context/dialog", () => ({
  useDialog: () => ({
    stack: [],
    externalDialogOpen: false,
    replace: vi.fn(),
    clear: vi.fn(),
    setSize: vi.fn(),
  }),
}));

vi.mock("../../theme", () => ({
  useTheme: () => ({
    colors: {
      primary: "cyan",
      text: "white",
      textMuted: "gray",
      error: "red",
      warning: "yellow",
    },
  }),
}));

vi.mock("../chat/message-list", () => ({
  MessageList: () => null,
}));

vi.mock("../chat/input-area", () => ({
  InputArea: (props: Record<string, unknown>) => {
    harness.inputAreaProps = props;
    return null;
  },
}));

vi.mock("./queued-messages", () => ({
  QueuedMessages: () => null,
}));

vi.mock("../model-picker", () => ({
  ModelPicker: () => null,
}));

import OperatorDashboard from "./index";

describe("OperatorDashboard session reuse after cancel", () => {
  beforeEach(() => {
    harness.keyboardHandler = null;
    harness.inputAreaProps = null;
    harness.runCalls = [];
    runOffensiveSecurityAgentMock.mockReset();
    runOffensiveSecurityAgentMock.mockImplementation((input) => {
      harness.runCalls.push(input as Record<string, unknown>);
      const session = (input as { session?: unknown }).session ?? harness.createdSession;
      (input as { onSessionReady?: (session: typeof harness.createdSession) => void })
        .onSessionReady?.(session as typeof harness.createdSession);

      if (harness.runCalls.length === 1) {
        return new Promise((_, reject) => {
          (input as { abortSignal?: AbortSignal }).abortSignal?.addEventListener(
            "abort",
            () => reject(new DOMException("Agent aborted by user", "AbortError")),
            { once: true },
          );
        });
      }

      return Promise.resolve({
        session,
        streamResult: {
          response: Promise.resolve({ messages: [] }),
        },
      });
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("reuses the first created session after the first run is canceled", async () => {
    const view = await testRender(<OperatorDashboard />, {
      width: 100,
      height: 30,
      testing: true,
    });

    await act(async () => {
      await Promise.resolve();
    });
    await view.renderOnce();

    const onSubmit = harness.inputAreaProps?.onSubmit as
      | ((value: string) => void)
      | undefined;
    expect(onSubmit).toBeTypeOf("function");

    await act(async () => {
      onSubmit?.("first prompt");
      await Promise.resolve();
    });
    await view.renderOnce();

    expect(harness.runCalls).toHaveLength(1);
    expect(harness.runCalls[0]?.session).toBeUndefined();

    await act(async () => {
      harness.keyboardHandler?.({
        name: "c",
        ctrl: true,
        preventDefault: vi.fn(),
      });
      await Promise.resolve();
    });
    await view.renderOnce();

    await act(async () => {
      onSubmit?.("second prompt");
      await Promise.resolve();
    });
    await view.renderOnce();

    expect(harness.runCalls).toHaveLength(2);
    expect(harness.runCalls[1]?.session).toMatchObject({
      id: harness.createdSession.id,
    });

    view.renderer.destroy();
  });
});
