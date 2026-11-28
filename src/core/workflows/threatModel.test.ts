import { beforeEach, describe, expect, it, vi } from "vitest";
import { ANTHROPIC_MODELS } from "../ai/models/anthropic";
import type { SessionInfo } from "../session";

const mocks = vi.hoisted(() => ({
  runOffensiveSecurityAgent: vi.fn(
    async (_input: Record<string, unknown>) => ({}),
  ),
}));

vi.mock("../api", () => ({
  runOffensiveSecurityAgent: mocks.runOffensiveSecurityAgent,
}));

vi.mock("../agents/offSecAgent", () => ({
  ALL_TOOL_NAMES: [],
  ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
  SKILL_TOOL_NAMES: [],
  buildBaseSystemPrompt: () => "test system prompt",
}));

vi.mock("../skills", () => ({
  createSkillsRegistry: () => ({
    load: vi.fn(async () => {}),
    readSkillContent: vi.fn(async () => ({ content: "skill content" })),
  }),
}));

vi.mock("../skills/builtins", () => ({
  buildThreatModelPrompt: () => "test prompt",
}));

vi.mock("../session", () => ({
  sessions: { create: vi.fn() },
}));

import { runThreatModelWorkflow } from "./threatModel";

const session = { id: "session-1" } as SessionInfo;

describe("runThreatModelWorkflow", () => {
  beforeEach(() => {
    mocks.runOffensiveSecurityAgent.mockClear();
  });

  it("defaults to a Claude Sonnet model that is not being retired", async () => {
    await runThreatModelWorkflow({
      codebasePath: "/repo",
      outputPath: "/repo/threat-model.md",
      session,
    });

    const model = mocks.runOffensiveSecurityAgent.mock.calls[0]?.[0].model;
    expect(model).toBe("claude-sonnet-5-5");
    expect(ANTHROPIC_MODELS.some((m) => m.id === model)).toBe(true);
  });

  it("passes an explicit model through unchanged", async () => {
    await runThreatModelWorkflow({
      codebasePath: "/repo",
      outputPath: "/repo/threat-model.md",
      model: "claude-opus-5-5",
      session,
    });

    expect(mocks.runOffensiveSecurityAgent.mock.calls[0]?.[0].model).toBe(
      "claude-opus-5-5",
    );
  });
});
