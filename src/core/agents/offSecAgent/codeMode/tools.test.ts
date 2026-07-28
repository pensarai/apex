import { type ToolSet, tool } from "ai";
import { describe, expect, test } from "vitest";
import { z } from "zod";
import { buildCodeModeInstructions, createCodeModeTools } from "./tools";

const runtime = {
  execute: async () => ({
    cellId: "cell_1",
    status: "completed",
    output: "ok",
  }),
  wait: async () => ({ cellId: "cell_1", status: "completed", output: "ok" }),
} as never;

const canonicalTools: ToolSet = {
  response: tool({ inputSchema: z.object({ result: z.string() }) }),
  document_vulnerability: tool({
    inputSchema: z.object({ title: z.string() }),
  }),
  checkpoint_state: tool({ inputSchema: z.object({ assessment: z.string() }) }),
  execute_command: tool({ inputSchema: z.object({ command: z.string() }) }),
};

describe("createCodeModeTools", () => {
  test("native mode uses freeform exec and preserves Console contract tools", () => {
    const tools = createCodeModeTools("native-code", runtime, canonicalTools);
    expect(Object.keys(tools)).toEqual([
      "exec",
      "wait",
      "response",
      "document_vulnerability",
      "checkpoint_state",
    ]);
    expect(tools.exec.type).toBe("provider");
  });

  test("schema mode preserves top-level Console contract tools", () => {
    const tools = createCodeModeTools("schema-code", runtime, canonicalTools);
    expect(Object.keys(tools)).toEqual([
      "exec",
      "wait",
      "response",
      "document_vulnerability",
      "checkpoint_state",
    ]);
    expect(tools.response).toBe(canonicalTools.response);
  });

  test("instructions teach bounded program-first composition", () => {
    const instructions = buildCodeModeInstructions("schema-code");
    expect(instructions).toContain("mapLimitSettled");
    expect(instructions).toContain("Do not split them across outer tool calls");
    expect(instructions).toContain("persistent session workspace");
    expect(instructions).toContain("Guidance is process feedback");
  });
});
