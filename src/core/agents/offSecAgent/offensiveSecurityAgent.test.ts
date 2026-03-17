import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import type { ModelMessage } from "ai";

const streamResponseMock = vi.hoisted(() => vi.fn());
const createAllToolsMock = vi.hoisted(() => vi.fn(() => ({})));

vi.mock("../../ai", () => ({
  streamResponse: streamResponseMock,
}));

vi.mock("./tools", () => ({
  createAllTools: createAllToolsMock,
  EMAIL_TOOL_NAMES_ACTIVE: [],
}));

import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
import type { SessionInfo } from "../../session";

function makeSession(rootPath: string): SessionInfo {
  return {
    id: "ses_test",
    name: "test session",
    version: "0.0.0",
    targets: ["https://example.com"],
    time: { created: Date.now(), updated: Date.now() },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
  } as SessionInfo;
}

describe("OffensiveSecurityAgent canceled-run persistence", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    vi.clearAllMocks();
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("persists the user turn and partial stream state on abort before step finish", async () => {
    const rootPath = join(
      tmpdir(),
      `offsec-abort-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    );
    mkdirSync(rootPath, { recursive: true });
    tempDirs.push(rootPath);

    const controller = new AbortController();
    streamResponseMock.mockImplementationOnce((opts: { abortSignal?: AbortSignal }) => ({
      fullStream: (async function* () {
        yield { type: "text-delta", text: "Investigating target..." };
        yield {
          type: "tool-call",
          toolCallId: "tool-1",
          toolName: "execute_command",
          input: { command: "pwd" },
        };
        yield {
          type: "tool-result",
          toolCallId: "tool-1",
          toolName: "execute_command",
          output: { stdout: "/tmp/session\n" },
        };
        await new Promise<void>((resolve) => {
          opts.abortSignal?.addEventListener("abort", () => resolve(), {
            once: true,
          });
        });
      })(),
      response: Promise.resolve({ messages: [] as ModelMessage[] }),
    }));

    const agent = new OffensiveSecurityAgent({
      prompt: "Enumerate the target",
      model: "test-model",
      session: makeSession(rootPath),
      activeTools: [],
      abortSignal: controller.signal,
      sandbox: {} as never,
    });

    const consumePromise = agent.consume();
    await Promise.resolve();
    controller.abort();

    await expect(consumePromise).rejects.toMatchObject({ name: "AbortError" });

    const messagesPath = join(rootPath, "messages.json");
    expect(existsSync(messagesPath)).toBe(true);

    const persisted = JSON.parse(readFileSync(messagesPath, "utf-8"));
    expect(persisted).toEqual([
      {
        role: "user",
        content: [{ type: "text", text: "Enumerate the target" }],
      },
      {
        role: "assistant",
        content: [
          { type: "text", text: "Investigating target..." },
          {
            type: "tool-call",
            toolCallId: "tool-1",
            toolName: "execute_command",
            input: { command: "pwd" },
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tool-1",
            toolName: "execute_command",
            output: { stdout: "/tmp/session\n" },
          },
        ],
      },
    ]);
  });
});
