import { describe, it, expect } from "vitest";
import {
  parseWebFlags,
  buildOperatorSessionConfig,
} from "../tui/utils/command-flags";
import {
  buildSessionWorkspaceSection,
  buildBaseSystemPrompt,
  BASE_SYSTEM_PROMPT,
} from "../core/agents/offSecAgent/prompt";

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
// Session Config
// =============================================================================

describe("buildOperatorSessionConfig", () => {
  it("sets agentCwd to process.cwd() by default", () => {
    const result = buildOperatorSessionConfig({
      target: "https://example.com",
    });
    expect(result.config.agentCwd).toBe(process.cwd());
  });

  it("sets agentCwd to undefined when sandbox is true", () => {
    const result = buildOperatorSessionConfig({
      target: "https://example.com",
      sandbox: true,
    });
    expect(result.config.agentCwd).toBeUndefined();
  });

  it("sets operator mode and target correctly alongside sandbox", () => {
    const result = buildOperatorSessionConfig({
      target: "https://example.com",
      sandbox: true,
      mode: "auto",
    });
    expect(result.config.mode).toBe("operator");
    expect(result.config.agentCwd).toBeUndefined();
    expect(result.targets).toEqual(["https://example.com"]);
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
