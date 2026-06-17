import { describe, expect, it } from "vitest";
import { threatModelExcludeTools } from "../../offSecAgent/tools/threatModelGenerator";
import { CODE_AGENT_DEFAULT_TOOLS, resolveCodeAgentTools } from "./agent";

// Proves the full chain a blackbox threat-model agent is built through:
//   sourceAvailable=false → threatModelExcludeTools → resolveCodeAgentTools →
//   the agent's actual active tool set. Issue #842: that set must contain no
//   source-reading tools, so the agent physically cannot try to read missing
//   source and loop on its `response` tool.
describe("resolveCodeAgentTools", () => {
  it("appends `response` only when a schema is present", () => {
    expect(resolveCodeAgentTools([], false)).not.toContain("response");
    expect(resolveCodeAgentTools([], true)).toContain("response");
  });

  it("a blackbox threat-model agent gets NO source-reading tools", () => {
    const tools = resolveCodeAgentTools(threatModelExcludeTools(false), true);
    for (const t of ["read_file", "list_files", "grep", "execute_command"]) {
      expect(tools).not.toContain(t);
    }
    // It can still observe the live target and capture structured output.
    expect(tools).toContain("http_request");
    expect(tools).toContain("response");
  });

  it("a whitebox threat-model agent keeps source-reading tools", () => {
    const tools = resolveCodeAgentTools(threatModelExcludeTools(true), true);
    expect(tools).toContain("read_file");
    expect(tools).toContain("grep");
    // document tools are always excluded (the agent analyzes, doesn't document).
    expect(tools).not.toContain("document_endpoint");
  });

  it("only ever excludes tools that exist in the default set", () => {
    for (const t of threatModelExcludeTools(false)) {
      if (t === "document_endpoint" || t === "document_app") continue;
      expect(CODE_AGENT_DEFAULT_TOOLS).toContain(t);
    }
  });
});
