import { beforeEach, describe, expect, it, vi } from "vitest";

const { superInputs } = vi.hoisted(() => ({
  superInputs: [] as Array<Record<string, unknown>>,
}));

// Capture the input CodeAgent hands to the harness constructor so the
// read-focused tool wiring is asserted without standing up a real agent.
vi.mock("../../offSecAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(input: Record<string, unknown>) {
      superInputs.push(input);
    }
  },
}));

import { CodeAgent } from "./agent";

function makeAgent(overrides: Record<string, unknown> = {}) {
  new CodeAgent({
    codebasePath: "/tmp/target-project",
    objective: "find missing auth middleware",
    model: "claude-sonnet-4-20250514" as never,
    session: { rootPath: "/tmp/apex-session" } as never,
    ...overrides,
  });
  return superInputs[superInputs.length - 1] as {
    activeTools: string[];
    fileWorkspaceRoot?: string;
  };
}

describe("CodeAgent stays a read-focused analysis agent", () => {
  beforeEach(() => {
    superInputs.length = 0;
  });

  it("wires the analysis toolset: read, list, grep, execute, whitebox, workspace doc", () => {
    const { activeTools } = makeAgent();
    for (const tool of [
      "read_file",
      "list_files",
      "grep",
      "execute_command",
      "profile_codebase",
      "query_whitebox_catalog",
      "run_code_query",
      "document_app",
      "document_endpoint",
      "web_search",
      "get_page",
    ]) {
      expect(activeTools).toContain(tool);
    }
  });

  it("wires no file-mutation, pentest-mutation, or orchestration tools", () => {
    const { activeTools } = makeAgent();
    for (const tool of [
      "create_file",
      "update_file",
      "delete_file",
      "apply_patch",
      "document_vulnerability",
      "spawn_pentest_agent",
      "spawn_coding_agent",
    ]) {
      expect(activeTools).not.toContain(tool);
    }
  });

  it("does not claim a helper file workspace — analysis only", () => {
    const input = makeAgent();
    expect(input.fileWorkspaceRoot).toBeUndefined();
  });

  it("honors excludeTools and adds the response tool only with a schema", () => {
    const input = makeAgent({
      excludeTools: ["document_app", "document_endpoint"],
      responseSchema: {
        safeParse: () => ({ success: true, data: undefined }),
      } as never,
    });
    expect(input.activeTools).not.toContain("document_app");
    expect(input.activeTools).not.toContain("document_endpoint");
    expect(input.activeTools).toContain("response");
    expect(input.activeTools).toContain("read_file");
  });
});
