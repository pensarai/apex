import { type ToolSet, tool } from "ai";
import { describe, expect, test } from "vitest";
import { z } from "zod";
import {
  buildCodeModeInstructions,
  createCodeModeTools,
  resolveCodeModeToolPresentation,
} from "./tools";

describe("workflow tool presentation", () => {
  test("preserves injected tools as direct by default", () => {
    expect(
      resolveCodeModeToolPresentation({
        activeTools: ["response", "read_context", "execute_command"],
        extraTools: ["read_context"],
      }),
    ).toEqual({
      direct: ["response", "read_context"],
      nested: ["execute_command"],
    });
  });

  test("explicit nested reads do not activate unavailable capabilities", () => {
    expect(
      resolveCodeModeToolPresentation({
        activeTools: ["response", "read_context"],
        extraTools: ["read_context", "unavailable"],
        nestedTools: ["read_context", "unavailable"],
      }),
    ).toEqual({ direct: ["response"], nested: ["read_context"] });
  });

  test("cannot move lifecycle contracts or non-injected capabilities", () => {
    for (const name of ["response", "execute_command"]) {
      expect(() =>
        resolveCodeModeToolPresentation({
          activeTools: [name],
          extraTools: ["response"],
          nestedTools: [name],
        }),
      ).toThrow("Cannot present");
    }
  });
});

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
  browser_screenshot: tool({ inputSchema: z.object({ filename: z.string() }) }),
  execute_command: tool({ inputSchema: z.object({ command: z.string() }) }),
};

describe("createCodeModeTools", () => {
  test("native mode uses freeform exec and preserves Console contract tools", () => {
    const tools = createCodeModeTools("native-code", runtime, canonicalTools, [
      "response",
      "document_vulnerability",
      "checkpoint_state",
      "browser_screenshot",
    ]);
    expect(Object.keys(tools)).toEqual([
      "exec",
      "wait",
      "response",
      "document_vulnerability",
      "checkpoint_state",
      "browser_screenshot",
    ]);
    expect(tools.exec.type).toBe("provider");
  });

  test("schema mode preserves top-level Console contract tools", () => {
    const tools = createCodeModeTools("schema-code", runtime, canonicalTools, [
      "response",
      "document_vulnerability",
      "checkpoint_state",
      "browser_screenshot",
    ]);
    expect(Object.keys(tools)).toEqual([
      "exec",
      "wait",
      "response",
      "document_vulnerability",
      "checkpoint_state",
      "browser_screenshot",
    ]);
    expect(tools.response).toBe(canonicalTools.response);
  });

  test("instructions teach bounded program-first composition", () => {
    const instructions = buildCodeModeInstructions("schema-code");
    expect(instructions).toContain("mapLimitSettled");
    expect(instructions).toContain("declare const ALL_TOOLS");
    expect(instructions).toContain("do not guess or probe capability names");
    expect(instructions).toContain("single-lane shell");
    expect(instructions).toContain("never wrap them in Promise.all");
    expect(instructions).toContain("python3 probe.py");
    expect(instructions).toContain("persistent session workspace");
    expect(instructions).toContain("exact nested toolCallId");
    expect(instructions).toContain("Guidance is process feedback");
  });
});
