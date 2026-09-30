import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PROJECT_INSTRUCTIONS_TAG } from "./prompts";

const { superInputs } = vi.hoisted(() => ({
  superInputs: [] as Array<Record<string, unknown>>,
}));

// Capture the input PatchingAgent hands to the harness constructor so the
// cwd / sandbox plumbing is asserted without standing up a real agent.
vi.mock("../../offSecAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(input: Record<string, unknown>) {
      superInputs.push(input);
    }
  },
}));

import {
  PATCHING_ACTIVE_TOOLS,
  PatchingAgent,
  resolvePatchingAgentsMd,
} from "./agent";
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

describe("PatchingAgent runtime plumbing", () => {
  let repo: string;

  beforeEach(() => {
    superInputs.length = 0;
    repo = mkdtempSync(join(tmpdir(), "apex-patching-plumbing-"));
  });

  afterEach(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  function lastSuperInput(): Record<string, unknown> {
    const input = superInputs[superInputs.length - 1];
    expect(input).toBeDefined();
    return input as Record<string, unknown>;
  }

  it("runs with the repository as its working directory, not the session root", () => {
    new PatchingAgent({
      cwd: repo,
      vulnerability: {
        name: "XSS",
        severity: "high",
        description: "reflected",
      },
      model: "claude-sonnet-4-20250514" as never,
      session: { rootPath: "/tmp/apex-session-root" } as never,
    });

    const input = lastSuperInput();
    expect(input.agentCwd).toBe(repo);
    // The repo itself is the file-tool scope; no narrower helper root —
    // patching legitimately edits the repository.
    expect(input.fileWorkspaceRoot).toBeUndefined();
  });

  it("does not inline host-read instructions in sandbox mode and points the agent at runtime read_file", () => {
    writeFileSync(join(repo, "AGENTS.md"), "host-only project rules");

    new PatchingAgent({
      cwd: repo,
      vulnerability: {
        name: "XSS",
        severity: "high",
        description: "reflected",
      },
      sandbox: {
        type: "linux",
        execute: async () => ({
          stdout: "",
          stderr: "",
          exitCode: 0,
          success: true,
        }),
      },
      model: "claude-sonnet-4-20250514" as never,
      session: { rootPath: "/tmp/apex-session-root" } as never,
    });

    const input = lastSuperInput();
    expect(input.sandbox).toBeDefined();
    const prompt = input.prompt as string;
    expect(prompt).toContain("## Project Instructions");
    expect(prompt).toContain("sandboxed runtime");
    expect(prompt).toContain("read_file");
    // The host file's content must not be inlined into the sandbox prompt.
    expect(prompt).not.toContain("host-only project rules");
    expect(prompt).not.toContain(`<${PROJECT_INSTRUCTIONS_TAG}>`);
  });

  it("keeps host-read instructions for local runs", () => {
    writeFileSync(join(repo, "AGENTS.md"), "local project rules");

    new PatchingAgent({
      cwd: repo,
      vulnerability: {
        name: "XSS",
        severity: "high",
        description: "reflected",
      },
      model: "claude-sonnet-4-20250514" as never,
      session: { rootPath: "/tmp/apex-session-root" } as never,
    });

    const prompt = lastSuperInput().prompt as string;
    expect(prompt).toContain(`<${PROJECT_INSTRUCTIONS_TAG}>`);
    expect(prompt).toContain("local project rules");
  });
});

describe("resolvePatchingAgentsMd", () => {
  let repo: string;

  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), "apex-patching-agentsmd-"));
  });

  afterEach(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("reads the repo instructions on the host for local runs", () => {
    writeFileSync(join(repo, "AGENTS.md"), "project rules");
    expect(resolvePatchingAgentsMd(repo, false)).toBe("project rules");
  });

  it("never reads host instructions for sandbox runs, even when the file exists", () => {
    writeFileSync(join(repo, "AGENTS.md"), "project rules");
    expect(resolvePatchingAgentsMd(repo, true)).toBeUndefined();
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
