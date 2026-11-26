import { describe, expect, it } from "vitest";
import type { OperatorMessage } from "./contract";
import {
  groupSubagents,
  type OperatorSubagent,
  subagentActivity,
  subagentLabel,
} from "./subagent-presentation";
import { toolIcon } from "./tool-icons";
import { describeTool } from "./tool-presentation";

const tool = (id: string, name = "spawn_recon_agent"): OperatorMessage => ({
  role: "tool",
  toolCallId: id,
  toolName: name,
  content: "",
  createdAt: "now",
  status: "streaming",
});
const agent = (
  id: string,
  patch: Partial<OperatorSubagent> = {},
): OperatorSubagent => ({
  id,
  name: id,
  status: "running",
  input: null,
  messages: [],
  ...patch,
});

describe("desktop subagent presentation", () => {
  it("nests children by exact parent call ID rather than repeated names", () => {
    const first = agent("a", { name: "Recon", parentToolCallId: "first" });
    const second = agent("b", { name: "Recon", parentToolCallId: "second" });
    const grouped = groupSubagents(
      [tool("first"), tool("second")],
      [first, second],
    );
    expect(grouped.byTool.get("first")).toEqual([first]);
    expect(grouped.byTool.get("second")).toEqual([second]);
  });
  it("keeps grandchildren inline and ignores workers without matching parent calls", () => {
    const parent = agent("parent", {
      parentToolCallId: "root-call",
      messages: [tool("nested-call")],
    });
    const nested = agent("nested", { parentToolCallId: "nested-call" });
    const legacy = agent("legacy");
    const missing = agent("missing", { parentToolCallId: "unavailable-call" });
    const grouped = groupSubagents(
      [tool("root-call")],
      [parent, nested, legacy, missing],
    );
    expect(grouped.byTool.get("nested-call")).toEqual([nested]);
    expect([...grouped.byTool.keys()]).toEqual(["root-call", "nested-call"]);
    expect(subagentLabel(legacy, 2)).toBe("Subagent 3");
  });
  it("shows activity only for running workers and preserves failed/cancelled states", () => {
    expect(subagentActivity(agent("a", { modelLoading: "model" }))).toBe(
      "waiting",
    );
    expect(
      subagentActivity(
        agent("a", { messages: [tool("tool", "execute_command")] }),
      ),
    ).toBe("working");
    expect(subagentActivity(agent("a"))).toBe("thinking");
    for (const status of ["completed", "failed", "cancelled"] as const)
      expect(subagentActivity(agent("a", { status }))).toBeUndefined();
  });
  it("recognizes recon spawning with the same icon family as other subagent tools", () => {
    expect(describeTool(tool("spawn")).kind).toBe("agent");
    expect(toolIcon("spawn_recon_agent")).toBe(toolIcon("spawn_pentest_agent"));
  });
});
