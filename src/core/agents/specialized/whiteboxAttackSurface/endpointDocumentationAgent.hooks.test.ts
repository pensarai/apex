import { AsyncLocalStorage } from "node:async_hooks";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import type { ToolBackends } from "../../../tools/backends/types";
import type { ToolExecutionContext } from "../../offSecAgent/types";
import { runAppEndpointDocumentation } from "./endpointDocumentationAgent";

vi.mock("../../../ai", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    streamResponse: (opts: {
      tools: Record<
        string,
        {
          execute: (input: unknown, options: unknown) => AsyncIterable<unknown>;
        }
      >;
    }) => ({
      fullStream: (async function* () {
        yield { type: "start-step" };
        for await (const output of opts.tools.read_file.execute(
          { path: "/repo/handler.ts", toolCallDescription: "Read handler" },
          { toolCallId: "child-read", messages: [] },
        )) {
          yield { type: "tool-result", output };
        }
      })(),
      response: Promise.resolve({ messages: [] }),
    }),
  };
});

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function documentEndpoint(
  toolExecutionContext: ToolExecutionContext,
  read: ReturnType<typeof vi.fn>,
) {
  const root = mkdtempSync(join(tmpdir(), "apex-child-context-"));
  roots.push(root);
  const session = {
    id: "ses-child-context",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath: root,
    logsPath: join(root, "logs"),
    findingsPath: join(root, "findings"),
    scratchpadPath: join(root, "scratchpad"),
    pocsPath: join(root, "pocs"),
    config: {},
  } as unknown as SessionInfo;
  const backends = {
    fs: { read },
    command: {
      async *run() {
        yield { type: "end", exitCode: 0, timedOut: false };
      },
    },
  } as unknown as ToolBackends;
  return runAppEndpointDocumentation({
    codebasePath: "/repo",
    app: {
      name: "api",
      framework: "express",
      description: "API",
      location: "/repo",
      type: "api",
    },
    endpoints: [
      {
        method: ["GET"],
        kind: "api",
        path: "/hello",
        handler: "handler",
        file: "handler.ts",
        line: 1,
        framework: "express",
        auth: [],
        internal: false,
      },
    ],
    frameworks: ["express"],
    model: "test-model",
    session,
    hooks: { backends, toolExecutionContext },
  });
}

describe("endpoint child tool execution context", () => {
  it("keeps the host context active across an awaited child backend call", async () => {
    const scope = new AsyncLocalStorage<string>();
    const read = vi.fn(async () => {
      expect(scope.getStore()).toBe("child-read");
      await Promise.resolve();
      expect(scope.getStore()).toBe("child-read");
      return { success: true, content: "handler", path: "/repo/handler.ts" };
    });
    await documentEndpoint(
      { run: (call, execute) => scope.run(call.toolCallId, execute) },
      read,
    );
    expect(read).toHaveBeenCalledOnce();
    expect(scope.getStore()).toBeUndefined();
  });

  it("lets the host reject a child tool before its backend executes", async () => {
    const read = vi.fn();
    const run = vi.fn(async () => {
      throw new Error("host rejected tool");
    });
    await expect(documentEndpoint({ run }, read)).rejects.toThrow();
    expect(run).toHaveBeenCalledWith(
      { toolCallId: "child-read", toolName: "read_file" },
      expect.any(Function),
    );
    expect(read).not.toHaveBeenCalled();
  });
});
