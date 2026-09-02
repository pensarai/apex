import { describe, expect, it } from "vitest";
import {
  BASE_SYSTEM_PROMPT,
  buildBaseSystemPrompt,
  buildSessionWorkspaceSection,
} from "../core/agents/offSecAgent";
import { PATCHING_ACTIVE_TOOLS } from "../core/agents/specialized/patching";
import { parseWebFlags } from "../tui/utils/command-flags";

// =============================================================================
// Flag Parsing
// =============================================================================

describe("parseWebFlags", () => {
  it("parses --sandbox as a boolean flag", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com",
      "--sandbox",
    ]);
    expect(flags.sandbox).toBe(true);
  });

  it("does not set sandbox when flag is absent", () => {
    const flags = parseWebFlags(["--target", "https://example.com"]);
    expect(flags.sandbox).toBeUndefined();
  });

  it("parses --sandbox alongside other flags", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com",
      "--sandbox",
      "--mode",
      "auto",
      "--no-approval",
    ]);
    expect(flags.sandbox).toBe(true);
    expect(flags.target).toBe("https://example.com");
    expect(flags.mode).toBe("auto");
    expect(flags.requireApproval).toBe(false);
  });
});

// =============================================================================
// Prompt Generation
// =============================================================================

const mockSession = {
  rootPath: "/home/user/.pensar/sessions/abc123",
  findingsPath: "/home/user/.pensar/sessions/abc123/findings",
  pocsPath: "/home/user/.pensar/sessions/abc123/pocs",
  scratchpadPath: "/home/user/.pensar/sessions/abc123/scratchpad",
  logsPath: "/home/user/.pensar/sessions/abc123/logs",
};

describe("buildSessionWorkspaceSection", () => {
  it("renders sandbox-mode prompt when agentCwd equals rootPath", () => {
    const result = buildSessionWorkspaceSection(
      mockSession,
      mockSession.rootPath,
    );
    expect(result).toContain("Session Workspace");
    expect(result).toContain(
      "Your shell is already set to the session directory",
    );
    expect(result).toContain(mockSession.rootPath);
    expect(result).not.toContain("Working Directory");
  });

  it("renders CWD-mode prompt when agentCwd differs from rootPath", () => {
    const projectDir = "/home/user/Projects/my-app";
    const result = buildSessionWorkspaceSection(mockSession, projectDir);
    expect(result).toContain("Working Directory");
    expect(result).toContain(projectDir);
    expect(result).toContain("Session artifacts are stored separately");
    expect(result).toContain(mockSession.rootPath);
    expect(result).not.toContain("Session Workspace");
  });

  it("includes session artifact paths in CWD mode", () => {
    const projectDir = "/home/user/Projects/my-app";
    const result = buildSessionWorkspaceSection(mockSession, projectDir);
    expect(result).toContain("findings/");
    expect(result).toContain("pocs/");
    expect(result).toContain("scratchpad/");
    expect(result).toContain("logs/");
  });

  it("keeps the read-only repo default for assessment agents", () => {
    const result = buildSessionWorkspaceSection(
      mockSession,
      "/home/user/Projects/my-app",
      ["read_file", "grep", "profile_codebase", "run_code_query"],
    );
    expect(result).toContain("Source Code Assessment");
    expect(result).toContain("Do not modify the target repo by default");
  });

  it("drops the read-only repo default for agents dispatched to edit the repo", () => {
    // The patching agent holds the whitebox tools AND the mutation tools; it
    // exists to rewrite the repo, so telling it not to contradicts its task.
    const result = buildSessionWorkspaceSection(
      mockSession,
      "/home/user/Projects/my-app",
      [...PATCHING_ACTIVE_TOOLS],
    );
    expect(result).toContain("Source Code Assessment");
    expect(result).not.toContain("Do not modify the target repo by default");
    expect(result).toContain(
      "Limit repo edits to the change you were dispatched to make",
    );
  });

  it("omits source-assessment guidance for agents without the whitebox tools", () => {
    const result = buildSessionWorkspaceSection(
      mockSession,
      "/home/user/Projects/my-app",
      ["read_file", "list_files", "grep", "execute_command", "response"],
    );
    expect(result).toContain("Working Directory");
    expect(result).not.toContain("Source Code Assessment");
  });

  it("keeps source-assessment guidance when tools are unknown", () => {
    const result = buildSessionWorkspaceSection(
      mockSession,
      "/home/user/Projects/my-app",
    );
    expect(result).toContain("Source Code Assessment");
    expect(result).toContain("Do not modify the target repo by default");
  });
});

describe("buildBaseSystemPrompt", () => {
  it("includes 'Stay in the session folder' in sandbox mode", () => {
    const prompt = buildBaseSystemPrompt({ sandboxMode: true });
    expect(prompt).toContain("Stay in the session folder");
  });

  it("excludes 'Stay in the session folder' in CWD mode", () => {
    const prompt = buildBaseSystemPrompt({ sandboxMode: false });
    expect(prompt).not.toContain("Stay in the session folder");
  });

  it("defaults to sandbox mode when no options provided", () => {
    const prompt = buildBaseSystemPrompt();
    expect(prompt).toContain("Stay in the session folder");
  });

  it("BASE_SYSTEM_PROMPT const equals default buildBaseSystemPrompt()", () => {
    expect(BASE_SYSTEM_PROMPT).toBe(buildBaseSystemPrompt());
  });

  it("always includes core identity regardless of mode", () => {
    const cwdPrompt = buildBaseSystemPrompt({ sandboxMode: false });
    const sandboxPrompt = buildBaseSystemPrompt({ sandboxMode: true });
    const corePhrase = "expert offensive security engineer";
    expect(cwdPrompt).toContain(corePhrase);
    expect(sandboxPrompt).toContain(corePhrase);
  });
});
