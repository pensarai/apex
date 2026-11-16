import {
  ArrowRightLeft,
  Camera,
  FilePen,
  FileText,
  Folder,
  GitBranch,
  Search,
  Terminal,
  Wrench,
} from "lucide-react";
import { describe, expect, it } from "vitest";
import type { OperatorMessage } from "./contract";
import { toolIcon } from "./tool-icons";
import {
  asRecord,
  describeTool,
  formatToolData,
  groupTranscript,
  segmentTools,
  toolGroupDetail,
  toolGroupLabel,
  toolMessageKey,
} from "./tool-presentation";

function tool(overrides: Partial<OperatorMessage> = {}): OperatorMessage {
  return {
    role: "tool",
    content: "",
    createdAt: "2026-11-16",
    toolCallId: "call-1",
    toolName: "execute_command",
    status: "completed",
    ...overrides,
  };
}

describe("desktop tool presentation", () => {
  it("preserves domain payloads that resemble envelopes and prototype-named tools", () => {
    const payload = { type: "json", value: 42, custom: "preserve me" };
    expect(describeTool(tool({ result: payload })).output).toEqual(payload);
    const input = { type: "text", value: "literal tool argument" };
    expect(describeTool(tool({ args: input })).input).toEqual(input);
    expect(describeTool(tool({ toolName: "constructor" })).kind).toBe(
      "generic",
    );
    expect(toolIcon("__proto__")).toBe(Wrench);
  });

  it("uses descriptive command labels without losing the exact command or output", () => {
    const command = "printf 'hello'\nprintf 'world'";
    const output = {
      success: true,
      exitCode: 0,
      stdout: "hello\nworld",
      stderr: "",
    };
    expect(
      describeTool(
        tool({
          args: { command, toolCallDescription: "Inspect the application" },
          result: output,
        }),
      ),
    ).toMatchObject({
      kind: "command",
      name: "Run command",
      headline: "Inspect the application",
      description: command,
      summary: "Exit 0",
      status: "completed",
      output,
    });
  });
  it("decodes JSON inputs and SDK output wrappers without double-decoding string literals", () => {
    const result = describeTool(
      tool({
        args: '{"command":"pwd"}',
        result: {
          type: "json",
          value: '{"success":true,"stdout":"/workspace","exitCode":0}',
        },
      }),
    );
    expect(result.input).toEqual({ command: "pwd" });
    expect(result.output).toEqual({
      success: true,
      stdout: "/workspace",
      exitCode: 0,
    });
    expect(result.headline).toBe("pwd");
    expect(describeTool(tool({ result: '"false"' })).output).toBe('"false"');
    expect(
      describeTool(
        tool({ result: { type: "error-text", value: "Connection refused" } }),
      ),
    ).toMatchObject({
      status: "error",
      summary: "Connection refused",
      output: "Connection refused",
    });
  });
  it("keeps malformed, partial, oversized, and deeply nested payloads inspectable", () => {
    const partial = '{"command":"npm';
    expect(
      describeTool(tool({ status: "streaming", args: partial })).input,
    ).toBe(partial);
    const large = `["${"x".repeat(1_000_001)}"]`;
    expect(describeTool(tool({ result: large })).output).toBe(large);
    let nested: unknown = { success: false };
    for (let i = 0; i < 10; i++) nested = { type: "json", value: nested };
    expect(asRecord(describeTool(tool({ result: nested })).output)?.type).toBe(
      "json",
    );
  });
  it.each([
    [{ success: false }, "Tool failed"],
    [{ isError: true, message: "Permission denied" }, "Permission denied"],
    [
      { success: true, exitCode: 2, stderr: "Invalid option" },
      "Invalid option",
    ],
    [{ success: true, error: "Timeout" }, "Timeout"],
    [{ errorMessage: "Failed to connect" }, "Failed to connect"],
    [{ blocked: true }, "Tool failed"],
  ])("surfaces result failures even when the stream reports completed: %j", (result, summary) => {
    expect(describeTool(tool({ result }))).toMatchObject({
      status: "error",
      summary,
    });
  });
  it("preserves zero, false, null, and unknown tool data instead of treating them as absent", () => {
    for (const value of [0, false, null, ""]) {
      const parsed = describeTool(
        tool({ toolName: "external_tool", args: value, result: value }),
      );
      expect(parsed.input).toBe(value);
      expect(parsed.output).toBe(value);
      expect(parsed.status).toBe("completed");
      expect(formatToolData(value)).toBe(value === "" ? "" : String(value));
    }
    expect(
      describeTool(tool({ result: { success: true, error: "", exitCode: 0 } }))
        .status,
    ).toBe("completed");
    expect(
      describeTool(tool({ toolName: "externalTool", status: "future-state" }))
        .status,
    ).toBe("unknown");
    expect(asRecord([])).toBeUndefined();
  });
  it("summarizes HTTP responses without interpreting arbitrary status fields as HTTP", () => {
    expect(
      describeTool(
        tool({
          toolName: "http_request",
          args: { method: "post", url: "https://example.test/login" },
          result: {
            status: 401,
            statusText: "Unauthorized",
            headers: {},
            body: "denied",
          },
        }),
      ),
    ).toMatchObject({
      kind: "http",
      headline: "POST https://example.test/login",
      status: "completed",
      summary: "HTTP 401 Unauthorized",
    });
    expect(
      describeTool(tool({ toolName: "external_tool", result: { status: 404 } }))
        .status,
    ).toBe("completed");
  });
  it("uses real file counters including zero and lower-bound directory counts", () => {
    expect(
      describeTool(
        tool({
          toolName: "read_file",
          args: { path: "src/app.ts" },
          result: { content: "", totalLines: 0 },
        }),
      ),
    ).toMatchObject({
      kind: "file",
      headline: "src/app.ts",
      summary: "0 lines",
    });
    expect(
      describeTool(
        tool({ toolName: "update_file", result: { replacements: 0 } }),
      ).summary,
    ).toBe("0 replacements");
    expect(
      describeTool(
        tool({
          toolName: "list_files",
          result: {
            totalFound: 200,
            totalFoundLowerBound: true,
            truncated: true,
          },
        }),
      ).summary,
    ).toBe("At least 200 files (truncated)");
    expect(
      describeTool(
        tool({
          toolName: "Read",
          args: { file_path: "README.md" },
          result: "one\ntwo",
        }),
      ).summary,
    ).toBe("2 lines");
  });
  it("presents search targets, browser navigation, and findings with their useful metadata", () => {
    expect(
      describeTool(
        tool({
          toolName: "grep",
          args: { pattern: "auth", directory: "src" },
          result: { matchCount: 3 },
        }),
      ),
    ).toMatchObject({
      headline: "auth in src",
      summary: "3 matches",
      kind: "search",
    });
    expect(
      describeTool(
        tool({
          toolName: "web_search",
          args: { query: "CVE" },
          result: { results: [] },
        }),
      ).summary,
    ).toBe("No results");
    expect(
      describeTool(
        tool({
          toolName: "browser_navigate",
          args: { url: "https://example.test" },
          result: { title: "Example" },
        }),
      ),
    ).toMatchObject({
      kind: "browser",
      headline: "https://example.test",
      summary: "Example",
    });
    expect(
      describeTool(
        tool({
          toolName: "document_vulnerability",
          args: { title: "Unsafe query" },
          result: { finding: { title: "SQL injection", severity: "high" } },
        }),
      ),
    ).toMatchObject({ kind: "finding", summary: "HIGH · SQL injection" });
    expect(
      describeTool(
        tool({
          toolName: "document_vulnerability",
          result: { success: false, duplicate: true },
        }),
      ),
    ).toMatchObject({ status: "completed", summary: "Already documented" });
  });
  it("distinguishes streaming, waiting, cancellation, and rejected findings", () => {
    expect(describeTool(tool({ status: "pending" })).status).toBe("pending");
    expect(describeTool(tool({ status: "streaming" })).status).toBe("running");
    expect(
      describeTool(tool({ status: "cancelled", result: { error: "Aborted" } }))
        .status,
    ).toBe("cancelled");
    expect(
      describeTool(
        tool({
          toolName: "document_vulnerability",
          result: { judgeRejected: true, judgeReasoning: "Not reproducible" },
        }),
      ),
    ).toMatchObject({ status: "error", summary: "Not reproducible" });
  });
  it("groups all contiguous tools into one rail and preserves keys as calls stream and rails grow", () => {
    const first = tool({
      toolName: "read_file",
      toolCallId: "read-1",
      status: "streaming",
    });
    const second = tool({ toolName: "read_file", toolCallId: "read-2" });
    const text: OperatorMessage = {
      role: "assistant",
      content: "",
      createdAt: "later",
    };
    const messages = [
      first,
      second,
      text,
      tool({ toolName: "read_file", toolCallId: "read-3" }),
      tool({ toolName: "grep", toolCallId: "grep-1" }),
    ];
    const before = groupTranscript(messages);
    expect(before.map((row) => row.kind)).toEqual([
      "tools",
      "message",
      "tools",
    ]);
    expect(before[0].kind === "tools" && before[0].items).toHaveLength(2);
    first.status = "completed";
    first.result = "new output";
    text.content = "Now streaming text";
    expect(groupTranscript(messages).map((row) => row.key)).toEqual(
      before.map((row) => row.key),
    );
    expect(groupTranscript([first, second])[0].key).toBe(
      groupTranscript([first])[0].key,
    );
    expect(messages).toHaveLength(5);
  });
  it("folds adjacent file work into one repository group with Console phrases", () => {
    const names = ["Read", "read_file", "grep", "Glob", "listFilesTool"];
    const items = names.map((toolName, index) =>
      tool({ toolName, toolCallId: `call-${index}` }),
    );
    expect(segmentTools(items)).toEqual([
      { key: "tool:call-0", family: "repository", items },
    ]);
    expect(toolGroupLabel("repository", 5)).toBe("Worked in the repository");
    expect(toolGroupDetail(items)).toBe(
      "read 2 files, searched 1 pattern, searched 1 file pattern, listed 1 directory",
    );
  });

  it("groups browser actions together but keeps screenshots and unknown calls standalone", () => {
    const names = [
      "browser_navigate",
      "browser_click",
      "browser_fill",
      "browser_screenshot",
      "browser_screenshot",
      "browser_snapshot",
      "external_tool",
      "external_tool",
    ];
    const items = names.map((toolName, index) =>
      tool({ toolName, toolCallId: `call-${index}` }),
    );
    expect(
      segmentTools(items).map(({ family, items }) => [family, items.length]),
    ).toEqual([
      ["browser", 3],
      [null, 1],
      [null, 1],
      [null, 1],
      [null, 1],
      [null, 1],
    ]);
    expect(toolGroupLabel("browser", 3)).toBe("Took 3 browser actions");
  });

  it("keeps commands and requests in separate groups from file work", () => {
    const names = [
      "read_file",
      "execute_command",
      "execute_command",
      "http_request",
      "http_request",
      "grep",
    ];
    const items = names.map((toolName, index) =>
      tool({ toolName, toolCallId: `call-${index}` }),
    );
    expect(
      segmentTools(items).map(({ family, items }) => [family, items.length]),
    ).toEqual([
      [null, 1],
      ["command", 2],
      ["request", 2],
      [null, 1],
    ]);
    expect(toolGroupLabel("command", 2)).toBe("Ran 2 commands");
    expect(toolGroupLabel("request", 2)).toBe("Made 2 requests");
  });

  it("keeps segment keys stable when singleton calls gain children or change streamed content", () => {
    const first = tool({
      toolName: "read_file",
      toolCallId: "read-1",
      status: "streaming",
    });
    const second = tool({ toolName: "grep", toolCallId: "grep-1" });
    const initial = segmentTools([first]);
    const grouped = segmentTools([first, second]);
    expect(initial[0].family).toBeNull();
    expect(grouped[0].family).toBe("repository");
    expect(grouped[0].key).toBe(initial[0].key);
    first.content = "streamed output";
    first.status = "completed";
    expect(segmentTools([first, second])[0].key).toBe(initial[0].key);
    expect(toolMessageKey(tool({ toolCallId: undefined }), 3)).toBe(
      "tool:2026-11-16:3",
    );
  });

  it("does not fold through user, system, or empty assistant messages", () => {
    for (const role of ["user", "system", "assistant"] as const) {
      const rows = groupTranscript([
        tool({ toolCallId: "first" }),
        { role, content: "", createdAt: "boundary" },
        tool({ toolCallId: "last" }),
      ]);
      expect(rows.map((row) => row.kind)).toEqual([
        "tools",
        "message",
        "tools",
      ]);
      expect(
        rows
          .filter((row) => row.kind === "tools")
          .map((row) => segmentTools(row.items)[0].family),
      ).toEqual([null, null]);
    }
  });

  it.each([
    ["execute_command", Terminal],
    ["http_request", ArrowRightLeft],
    ["Read", FileText],
    ["readFileTool", FileText],
    ["Edit", FilePen],
    ["glob", Folder],
    ["grep", Search],
    ["browser_screenshot", Camera],
    ["spawn_pentest_agent", GitBranch],
    ["Task", GitBranch],
    ["unknown_tool", Wrench],
    ["constructor", Wrench],
  ])("matches Console's icon for %s", (name, icon) => {
    expect(toolIcon(name)).toBe(icon);
  });
});
