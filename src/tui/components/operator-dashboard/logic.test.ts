import { describe, expect, it, vi } from "vitest";
import {
  filterOperatorAutocomplete,
  resolveSubmit,
  routeCommand,
  resolveKeyboardShortcut,
  resolveAbortAction,
  buildOperatorSystemPrompt,
  resolveInputFocused,
  accumulateTokenUsage,
  type DashboardStatus,
} from "./logic";
import type { AutocompleteOption } from "../shared/prompt-input";
import type { OperatorSessionState } from "../../../core/operator";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const allOptions: AutocompleteOption[] = [
  { value: "/scan", label: "/scan", description: "Run a scan" },
  { value: "/pentest", label: "/pentest", description: "Run a pentest" },
  { value: "/help", label: "/help", description: "Show help" },
  { value: "/models", label: "/models", description: "Switch model" },
  { value: "/skills", label: "/skills", description: "View skills" },
];

// ---------------------------------------------------------------------------
// filterOperatorAutocomplete
// ---------------------------------------------------------------------------

describe("filterOperatorAutocomplete", () => {
  it("includes allowed commands (/models, /skills)", () => {
    const result = filterOperatorAutocomplete(allOptions);
    const values = result.map((o) => o.value);
    expect(values).toContain("/models");
    expect(values).toContain("/skills");
  });

  it("excludes commands that are not in the allowed set", () => {
    const result = filterOperatorAutocomplete(allOptions);
    const values = result.map((o) => o.value);
    expect(values).not.toContain("/scan");
  });

  it("returns only allowed commands", () => {
    const result = filterOperatorAutocomplete(allOptions);
    expect(result).toHaveLength(4);
  });

  it("preserves description on allowed commands", () => {
    const result = filterOperatorAutocomplete(allOptions);
    const modelsOpt = result.find((o) => o.value === "/models");
    expect(modelsOpt?.description).toBe("Switch model");
  });

  it("returns empty for empty input", () => {
    expect(filterOperatorAutocomplete([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// resolveSubmit
// ---------------------------------------------------------------------------

describe("resolveSubmit", () => {
  it("returns 'run' with trimmed prompt for valid input when idle", () => {
    const result = resolveSubmit("  hello world  ", "idle", false);
    expect(result).toEqual({
      action: "run",
      prompt: "hello world",
      denyPending: false,
    });
  });

  it("returns 'empty' for whitespace-only input", () => {
    const result = resolveSubmit("   ", "idle", false);
    expect(result).toEqual({ action: "empty", denyPending: false });
  });

  it("returns 'blocked' when status is running", () => {
    const result = resolveSubmit("hello", "running", false);
    expect(result.action).toBe("blocked");
  });

  it("allows submit when status is waiting", () => {
    const result = resolveSubmit("redirect", "waiting", true);
    expect(result.action).toBe("run");
    expect(result.prompt).toBe("redirect");
  });

  it("sets denyPending when there are pending approvals", () => {
    const result = resolveSubmit("redirect", "waiting", true);
    expect(result.denyPending).toBe(true);
  });

  it("does not set denyPending when no pending approvals", () => {
    const result = resolveSubmit("hello", "idle", false);
    expect(result.denyPending).toBe(false);
  });

  it("sets denyPending even when blocked", () => {
    const result = resolveSubmit("hello", "running", true);
    expect(result.denyPending).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// routeCommand
// ---------------------------------------------------------------------------

describe("routeCommand", () => {
  const noSkill = () => null;

  it("routes /models to show-models", () => {
    expect(routeCommand("/models", noSkill)).toEqual({ type: "show-models" });
  });

  it("routes /model (singular) to show-models", () => {
    expect(routeCommand("/model", noSkill)).toEqual({ type: "show-models" });
  });

  it("routes /MODELS (case-insensitive) to show-models", () => {
    expect(routeCommand("/MODELS", noSkill)).toEqual({ type: "show-models" });
  });

  it("routes a skill command to run-skill with slug", () => {
    const resolveSkill = (cmd: string) =>
      cmd === "/sql-injection" ? "Perform SQL injection testing" : null;
    const result = routeCommand("/sql-injection", resolveSkill);
    expect(result).toEqual({
      type: "run-skill",
      slug: "sql-injection",
      autopilot: false,
    });
  });

  it("detects --autopilot flag on skill commands", () => {
    const resolveSkill = (cmd: string) =>
      cmd === "/sql-injection" ? "SQL injection" : null;
    const result = routeCommand("/sql-injection --autopilot", resolveSkill);
    expect(result).toEqual({
      type: "run-skill",
      slug: "sql-injection",
      autopilot: true,
    });
  });

  it("strips --autopilot before resolving skill", () => {
    const resolveSkill = vi.fn().mockReturnValue("content");
    routeCommand("/my-skill --autopilot", resolveSkill);
    expect(resolveSkill).toHaveBeenCalledWith("/my-skill");
  });

  it("routes /plan to show-plan", () => {
    expect(routeCommand("/plan", noSkill)).toEqual({ type: "show-plan" });
  });

  it("routes /plan with args to show-plan", () => {
    expect(routeCommand("/plan open", noSkill)).toEqual({ type: "show-plan" });
  });

  it("falls back to execute-command for unknown commands", () => {
    const result = routeCommand("/unknown-cmd", noSkill);
    expect(result).toEqual({
      type: "execute-command",
      command: "/unknown-cmd",
    });
  });

  it("routes /threat-model to run-skill when skill is registered", () => {
    const resolveSkill = (cmd: string) =>
      cmd === "/threat-model"
        ? "Generate application-centric threat model"
        : null;
    const result = routeCommand("/threat-model", resolveSkill);
    expect(result).toEqual({
      type: "run-skill",
      slug: "threat-model",
      autopilot: false,
    });
  });

  it("routes /threat-model --autopilot with autopilot flag", () => {
    const resolveSkill = (cmd: string) =>
      cmd === "/threat-model"
        ? "Generate application-centric threat model"
        : null;
    const result = routeCommand("/threat-model --autopilot", resolveSkill);
    expect(result).toEqual({
      type: "run-skill",
      slug: "threat-model",
      autopilot: true,
    });
  });

  it("falls back to execute-command for /threat-model when skill is not registered", () => {
    const result = routeCommand("/threat-model", noSkill);
    expect(result).toEqual({
      type: "execute-command",
      command: "/threat-model",
    });
  });
});

// ---------------------------------------------------------------------------
// resolveKeyboardShortcut
// ---------------------------------------------------------------------------

describe("resolveKeyboardShortcut", () => {
  const idle: DashboardStatus = "idle";
  const running: DashboardStatus = "running";
  const waiting: DashboardStatus = "waiting";

  it("returns skip when dialog is open", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "c", ctrl: true },
        running,
        "",
        true,
        true,
      ),
    ).toEqual({ type: "skip" });
  });

  it("passes through Cmd+C (terminal copy)", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "c", meta: true },
        running,
        "text",
        false,
        false,
      ),
    ).toEqual({ type: "skip" });
  });

  it("passes through Super+C (terminal copy)", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "c", super: true },
        running,
        "text",
        false,
        false,
      ),
    ).toEqual({ type: "skip" });
  });

  describe("Ctrl+C", () => {
    it("returns ctrl-c-abort when running", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "c", ctrl: true },
          running,
          "",
          false,
          false,
        ),
      ).toEqual({ type: "ctrl-c-abort" });
    });

    it("returns ctrl-c-abort when waiting", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "c", ctrl: true },
          waiting,
          "",
          false,
          false,
        ),
      ).toEqual({ type: "ctrl-c-abort" });
    });

    it("returns ctrl-c-clear when idle with input", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "c", ctrl: true },
          idle,
          "text",
          false,
          false,
        ),
      ).toEqual({ type: "ctrl-c-clear" });
    });

    it("returns skip when idle with empty input", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "c", ctrl: true },
          idle,
          "",
          false,
          false,
        ),
      ).toEqual({ type: "skip" });
    });

    it("returns skip when idle with whitespace-only input", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "c", ctrl: true },
          idle,
          "   ",
          false,
          false,
        ),
      ).toEqual({ type: "skip" });
    });
  });

  describe("Escape", () => {
    it("returns escape when idle", () => {
      expect(
        resolveKeyboardShortcut({ name: "escape" }, idle, "", false, false),
      ).toEqual({ type: "escape" });
    });

    it("returns skip when running", () => {
      expect(
        resolveKeyboardShortcut({ name: "escape" }, running, "", false, false),
      ).toEqual({ type: "skip" });
    });

    it("returns skip when waiting", () => {
      expect(
        resolveKeyboardShortcut({ name: "escape" }, waiting, "", false, false),
      ).toEqual({ type: "skip" });
    });
  });

  it("Ctrl+V returns toggle-verbose", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "v", ctrl: true },
        idle,
        "",
        false,
        false,
      ),
    ).toEqual({ type: "toggle-verbose" });
  });

  it("Ctrl+L returns toggle-expanded-logs", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "l", ctrl: true },
        idle,
        "",
        false,
        false,
      ),
    ).toEqual({ type: "toggle-expanded-logs" });
  });

  it("Shift+Tab returns cycle-mode", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "tab", shift: true },
        idle,
        "",
        false,
        false,
      ),
    ).toEqual({ type: "cycle-mode" });
  });

  it("Option+Shift+Tab also returns cycle-mode", () => {
    expect(
      resolveKeyboardShortcut(
        { name: "tab", shift: true, meta: true },
        idle,
        "",
        false,
        false,
      ),
    ).toEqual({ type: "cycle-mode" });
  });

  describe("Approval shortcuts", () => {
    it("Y approves when waiting with pending approvals", () => {
      expect(
        resolveKeyboardShortcut({ name: "y" }, waiting, "", true, false),
      ).toEqual({ type: "approve" });
    });

    it("Y (raw) approves when waiting with pending approvals", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "Y", raw: "Y" },
          waiting,
          "",
          true,
          false,
        ),
      ).toEqual({ type: "approve" });
    });

    it("Y does nothing when not waiting", () => {
      expect(
        resolveKeyboardShortcut({ name: "y" }, idle, "", true, false),
      ).toEqual({ type: "skip" });
    });

    it("Y does nothing when no pending approvals", () => {
      expect(
        resolveKeyboardShortcut({ name: "y" }, waiting, "", false, false),
      ).toEqual({ type: "skip" });
    });

    it("A auto-approves when waiting with pending approvals", () => {
      expect(
        resolveKeyboardShortcut({ name: "a" }, waiting, "", true, false),
      ).toEqual({ type: "auto-approve" });
    });

    it("A (raw) auto-approves when waiting with pending approvals", () => {
      expect(
        resolveKeyboardShortcut(
          { name: "A", raw: "A" },
          waiting,
          "",
          true,
          false,
        ),
      ).toEqual({ type: "auto-approve" });
    });

    it("A does nothing when not waiting", () => {
      expect(
        resolveKeyboardShortcut({ name: "a" }, idle, "", true, false),
      ).toEqual({ type: "skip" });
    });
  });
});

// ---------------------------------------------------------------------------
// resolveAbortAction
// ---------------------------------------------------------------------------

describe("resolveAbortAction", () => {
  it("returns cancel-command when command not yet cancelled and cancel succeeds", () => {
    const result = resolveAbortAction(false, () => true);
    expect(result).toEqual({ type: "cancel-command" });
  });

  it("returns kill-agent when command already cancelled", () => {
    const result = resolveAbortAction(true, () => true);
    expect(result).toEqual({ type: "kill-agent" });
  });

  it("returns kill-agent when cancel returns false (no command running)", () => {
    const result = resolveAbortAction(false, () => false);
    expect(result).toEqual({ type: "kill-agent" });
  });
});

// ---------------------------------------------------------------------------
// buildOperatorSystemPrompt
// ---------------------------------------------------------------------------

describe("buildOperatorSystemPrompt", () => {
  const target = "https://example.com";

  const state = {
    mode: "auto",
    requireApproval: true,
    currentStage: "recon",
    pendingApprovals: [],
    actionHistory: [],
    stageProgress: {},
  } as unknown as OperatorSessionState;

  it("includes the target", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).toContain("Target: https://example.com");
  });

  it("includes the stage", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).toContain("Stage: recon");
  });

  it("shows approval enabled when requireApproval is true", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).toContain("Command approval: enabled");
  });

  it("shows approval disabled when requireApproval is false", () => {
    const prompt = buildOperatorSystemPrompt(target, {
      ...state,
      requireApproval: false,
    });
    expect(prompt).toContain("Command approval: disabled");
  });

  it("falls back to 'unknown' when no target", () => {
    const prompt = buildOperatorSystemPrompt(undefined, state);
    expect(prompt).toContain("Target: unknown");
  });

  it("includes the base system prompt", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).toContain("# Command Execution");
    expect(prompt).toContain("# Tool Reference");
  });

  // Regression guard: operator mode passes its own `system:` to the agent,
  // which short-circuits the constructor's default `detectOSAndEnhancePrompt`
  // call. Without wrapping here, the operator prompt loses [ENV CONTEXT] and
  // [BUNDLED ASSETS] entirely — the model has no idea what wordlists or tools
  // are available. See the discussion around the wordlist bundling work.
  it("includes the [ENV CONTEXT] block from detectOSAndEnhancePrompt", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).toContain("[ENV CONTEXT]");
    expect(prompt).toContain("[/ENV CONTEXT]");
  });

  it("includes the [BUNDLED ASSETS] inventory so the agent can answer capability questions", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).toContain("[BUNDLED ASSETS]");
    expect(prompt).toMatch(/TINY_WORDLIST=\S+tiny\.txt/);
    expect(prompt).toMatch(/DEFAULT_WORDLIST=\S+common\.txt/);
    expect(prompt).toMatch(/LARGE_WORDLIST=\S+large\.txt/);
  });

  it("includes plan mode prompt when agentMode is plan", () => {
    const prompt = buildOperatorSystemPrompt(target, state, "plan");
    expect(prompt).toContain("PLAN MODE");
    expect(prompt).toContain("write_plan");
    expect(prompt).toContain("submit_plan");
  });

  it("does not include plan mode prompt when agentMode is default", () => {
    const prompt = buildOperatorSystemPrompt(target, state, "default");
    expect(prompt).not.toContain("PLAN MODE");
  });

  it("includes approved plan content when provided outside plan mode", () => {
    const prompt = buildOperatorSystemPrompt(target, state, "default", {
      approvedPlanContent: "Test plan content",
    });
    expect(prompt).toContain("Approved Plan");
    expect(prompt).toContain("Test plan content");
  });

  it("includes refinement block when existingPlanContent provided in plan mode", () => {
    const prompt = buildOperatorSystemPrompt(target, state, "plan", {
      existingPlanContent: "Old plan content",
    });
    expect(prompt).toContain("Do NOT Rewrite");
    expect(prompt).toContain("Old plan content");
  });

  it("does not include plan mode note when agentMode is omitted", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).not.toContain("Agent mode: PLAN");
  });

  it("appends skills catalog when provided", () => {
    const catalog =
      "<available_skills>\n\n- **sqli** (web) — SQL injection testing\n\n</available_skills>";
    const prompt = buildOperatorSystemPrompt(target, state, undefined, {
      skillsCatalog: catalog,
    });
    expect(prompt).toContain("# Skills");
    expect(prompt).toContain("<available_skills>");
    expect(prompt).toContain("sqli");
  });

  it("does not include skills catalog section when catalog is undefined", () => {
    const prompt = buildOperatorSystemPrompt(target, state);
    expect(prompt).not.toContain("<available_skills>");
  });

  it("appends active skill instructions", () => {
    const activeSkills = [
      { name: "SQL Injection", instructions: "Step 1: Find params..." },
      { name: "XSS", instructions: "Step 1: Inject payload..." },
    ];
    const prompt = buildOperatorSystemPrompt(target, state, undefined, {
      activeSkillInstructions: activeSkills,
    });
    expect(prompt).toContain("# Active Skill: SQL Injection");
    expect(prompt).toContain("Step 1: Find params...");
    expect(prompt).toContain("# Active Skill: XSS");
    expect(prompt).toContain("Step 1: Inject payload...");
  });

  it("does not include active skills section when array is empty", () => {
    const prompt = buildOperatorSystemPrompt(target, state, undefined, {
      activeSkillInstructions: [],
    });
    expect(prompt).not.toContain("# Active Skill:");
  });
});

// ---------------------------------------------------------------------------
// resolveInputFocused
// ---------------------------------------------------------------------------

describe("resolveInputFocused", () => {
  it("returns true when idle and no dialogs", () => {
    expect(resolveInputFocused("idle", 0, false)).toBe(true);
  });

  it("returns false when running", () => {
    expect(resolveInputFocused("running", 0, false)).toBe(false);
  });

  it("returns false when dialog stack is non-empty", () => {
    expect(resolveInputFocused("idle", 1, false)).toBe(false);
  });

  it("returns false when external dialog is open", () => {
    expect(resolveInputFocused("idle", 0, true)).toBe(false);
  });

  it("returns true when waiting (input is active for redirects)", () => {
    expect(resolveInputFocused("waiting", 0, false)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// accumulateTokenUsage
// ---------------------------------------------------------------------------

describe("accumulateTokenUsage", () => {
  const base = {
    inputTokens: 100,
    outputTokens: 50,
    totalTokens: 150,
    cachedTokens: 10,
    cacheWriteTokens: 5,
  };

  it("accumulates input and output tokens", () => {
    const result = accumulateTokenUsage(base, 20, 10);
    expect(result).toEqual({
      inputTokens: 120,
      outputTokens: 60,
      totalTokens: 180,
      cachedTokens: 10,
      cacheWriteTokens: 5,
    });
  });

  it("uses reported total tokens when provided", () => {
    const result = accumulateTokenUsage(base, 20, 10, 45);
    expect(result).toEqual({
      inputTokens: 120,
      outputTokens: 60,
      totalTokens: 195,
      cachedTokens: 10,
      cacheWriteTokens: 5,
    });
  });

  it("returns null when both step values are zero", () => {
    expect(accumulateTokenUsage(base, 0, 0)).toBeNull();
  });

  it("returns null when both step values are negative", () => {
    expect(accumulateTokenUsage(base, -1, -1)).toBeNull();
  });

  it("accumulates when only input tokens are provided", () => {
    const result = accumulateTokenUsage(base, 10, 0);
    expect(result).not.toBeNull();
    expect(result!.inputTokens).toBe(110);
    expect(result!.outputTokens).toBe(50);
  });

  it("accumulates when only output tokens are provided", () => {
    const result = accumulateTokenUsage(base, 0, 5);
    expect(result).not.toBeNull();
    expect(result!.outputTokens).toBe(55);
    expect(result!.inputTokens).toBe(100);
  });

  it("handles zero base", () => {
    const zero = {
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      cachedTokens: 0,
      cacheWriteTokens: 0,
    };
    const result = accumulateTokenUsage(zero, 10, 5);
    expect(result).toEqual({
      inputTokens: 10,
      outputTokens: 5,
      totalTokens: 15,
      cachedTokens: 0,
      cacheWriteTokens: 0,
    });
  });
});
