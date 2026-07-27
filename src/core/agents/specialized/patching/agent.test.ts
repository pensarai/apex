import { describe, expect, it } from "vitest";
import { PATCHING_ACTIVE_TOOLS } from "./agent";
import { buildPatchingPrompt, buildSystemPrompt } from "./prompts";

describe("PatchingAgent toolset", () => {
  it("exposes a Cursor/Claude-Code-like autonomous coding toolset", () => {
    expect(PATCHING_ACTIVE_TOOLS).toEqual(
      expect.arrayContaining([
        "read_file",
        "list_files",
        "glob",
        "grep",
        "profile_codebase",
        "run_code_query",
        "web_search",
        "get_page",
        "create_task",
        "update_task",
        "list_tasks",
        "create_file",
        "update_file",
        "delete_file",
        "apply_patch",
        "git_status",
        "git_diff",
        "execute_command",
        "response",
      ]),
    );
    expect(PATCHING_ACTIVE_TOOLS).not.toContain("ask_user_questions");
    expect(PATCHING_ACTIVE_TOOLS).not.toContain("spawn_coding_agent");
    expect(PATCHING_ACTIVE_TOOLS).not.toContain("browser_navigate");
  });
});

describe("patching prompts", () => {
  it("prescribes the autonomous coding-agent workflow and new tools", () => {
    const system = buildSystemPrompt();
    expect(system).toContain("Track Work with Tasks");
    expect(system).toContain("apply_patch");
    expect(system).toContain("git_status");
    expect(system).toContain("web_search");
    expect(system).toContain("Stay Autonomous");
    expect(system).toContain("Do not commit, push, or open a pull request");
  });

  it("includes vulnerability details and the numbered workflow in the user prompt", () => {
    const prompt = buildPatchingPrompt(
      {
        name: "SQL Injection",
        severity: "critical",
        description: "Unparameterized query",
        location: "src/auth.ts",
      },
      "/tmp/repo",
    );
    expect(prompt).toContain("SQL Injection");
    expect(prompt).toContain("src/auth.ts");
    expect(prompt).toContain("Self-Check with Git");
    expect(prompt).toContain("create_task");
  });
});
