import { describe, expect, it, vi } from "vitest";
import { CanonicalCapabilityInvoker } from "./agents/offSecAgent/codeMode/capabilityInvoker";
import { CodeModeRuntime } from "./agents/offSecAgent/codeMode/runtime";
import { resolveCodeModeToolPresentation } from "./agents/offSecAgent/codeMode/tools";
import { AgentEventBus } from "./eventBus";
import {
  createSourceTools,
  SOURCE_TOOL_NAMES,
  type SourceProvider,
} from "./source";

function remoteProvider(): SourceProvider {
  return {
    describe: vi.fn(async () => ({
      kind: "remote" as const,
      name: "api",
      revision: "snapshot-1",
    })),
    listTree: vi.fn(async () => ({
      entries: [{ path: "route.ts", kind: "file" as const }],
      nextOffset: null,
    })),
    search: vi.fn(async () => ({
      matches: [{ path: "route.ts", line: 1, text: "authorize(actor)" }],
      truncated: false,
      skippedFiles: 0,
    })),
    readFile: vi.fn(async () => ({
      path: "route.ts",
      content: "authorize(actor)",
      version: "snapshot-1",
      offset: 0,
      nextOffset: null,
      firstLine: 1,
    })),
  };
}

function runtimeFor(provider?: SourceProvider) {
  const tools = provider ? createSourceTools(provider) : {};
  const names = Object.keys(tools);
  const invoker = new CanonicalCapabilityInvoker({
    tools,
    allowedTools: names,
    eventBus: new AgentEventBus(),
    sessionId: "source-test",
    getMessageId: () => "message",
  });
  return new CodeModeRuntime(invoker, names);
}

describe("source capability bridge", () => {
  it("uses the same four-method namespace for remote source without a checkout", async () => {
    const provider = remoteProvider();
    const runtime = runtimeFor(provider);
    try {
      const result = await runtime.execute(
        `
        const description = await tools.source.describe();
        const tree = await tools.source.listTree();
        const matches = await tools.source.search({query: "authorize"});
        const file = await tools.source.readFile({path: matches.matches[0].path});
        text({revision: description.revision, entries: tree.entries.length, snippet: file.content});
      `,
        { parentToolCallId: "cell", messages: [] },
        5000,
      );
      expect(result.status).toBe("completed");
      expect(JSON.parse(result.output)).toEqual({
        revision: "snapshot-1",
        entries: 1,
        snippet: "authorize(actor)",
      });
      expect(result.evidence?.map((item) => item.toolName)).toEqual([
        ...SOURCE_TOOL_NAMES,
      ]);
      expect(provider.search).toHaveBeenCalledWith(
        { query: "authorize", path: ".", limit: 40 },
        expect.any(Object),
      );
    } finally {
      await runtime.dispose();
    }
  });

  it("rejects invalid paths and oversized reads before invoking the provider", async () => {
    const provider = remoteProvider();
    const runtime = runtimeFor(provider);
    try {
      const result = await runtime.execute(
        `
        for (const input of [{path: "../secret"}, {path: "/etc/passwd"}, {path: "route.ts", limit: 1000000}]) {
          try { await tools.source.readFile(input); text("unexpected"); }
          catch { text("rejected"); }
        }
      `,
        { parentToolCallId: "cell", messages: [] },
        5000,
      );
      expect(result.output).not.toContain("unexpected");
      expect(result.output.match(/rejected/g)).toHaveLength(3);
      expect(provider.readFile).not.toHaveBeenCalled();
    } finally {
      await runtime.dispose();
    }
  });

  it("does not grant source access when no provider is configured", async () => {
    const runtime = runtimeFor();
    try {
      const result = await runtime.execute(
        "await tools.source.describe();",
        { parentToolCallId: "cell", messages: [] },
        5000,
      );
      expect(result.status).toBe("failed");
    } finally {
      await runtime.dispose();
    }
  });

  it("keeps source schemas nested in code mode", () => {
    const presentation = resolveCodeModeToolPresentation({
      activeTools: ["response", ...SOURCE_TOOL_NAMES],
      extraTools: [...SOURCE_TOOL_NAMES],
      nestedTools: [...SOURCE_TOOL_NAMES],
    });
    expect(presentation.direct).toEqual(["response"]);
    expect(presentation.nested).toEqual([...SOURCE_TOOL_NAMES]);
  });
});
