// Tool definitions are resent on every model call and count against the context window,
// so each agent's set has a budget. Raise a budget here when the growth is intended.
import { describe, expect, it } from "vitest";
import { estimateToolsOverheadTokens } from "../../../ai/contextManagement";
import { blackboxAttackSurfaceDefinition } from "../../specialized/attackSurface/blackboxAgent";
import { authenticationAgentDefinition } from "../../specialized/authenticationAgent/agent";
import { codeAgentDefinition } from "../../specialized/codeAgent/agent";
import { environmentAgentDefinition } from "../../specialized/environment/agent";
import { findingJudgeDefinition } from "../../specialized/findingJudge/agent";
import { patchingAgentDefinition } from "../../specialized/patching/agent";
import { targetedPentestWorker } from "../../specialized/pentest/agent";
import { siemTriageDefinition } from "../../specialized/siemTriage/agent";
import { vulnerabilityReproductionDefinition } from "../../specialized/vulnerabilityReproduction/agent";
import { whiteboxAttackSurfaceDefinition } from "../../specialized/whiteboxAttackSurface/agent";
import { createAllTools, createToolsForNames, type ToolContext } from "./index";

const DESCRIPTION_CHAR_LIMIT = 4_500;
const TOOL_TOKEN_LIMIT = 2_000;

const ctx = {
  session: { id: "ses_budget", rootPath: "/tmp/apex-budget", config: {} },
  agentCwd: "/tmp/apex-budget",
  sandbox: {
    type: "linux",
    execute: async () => {
      throw new Error("no execution while measuring tool definitions");
    },
  },
  traceWriter: { record: () => {} },
} as unknown as ToolContext;

const opts = { session: { config: {} }, findingPolicy: "native" } as never;
const none = undefined as never;

// Estimated tokens (Apex's context-fitting estimate) with about 10% headroom.
const AGENTS: Record<string, { tools: () => string[]; budget: number }> = {
  "pentest orchestrator": {
    tools: () =>
      targetedPentestWorker.activeTools(opts, {
        effectiveRole: "orchestrator",
      } as never),
    budget: 11_200,
  },
  "pentest worker": {
    tools: () =>
      targetedPentestWorker.activeTools(opts, {
        effectiveRole: "worker",
      } as never),
    budget: 15_000,
  },
  "blackbox attack surface": {
    tools: () => blackboxAttackSurfaceDefinition.activeTools(opts, none),
    budget: 9_900,
  },
  "whitebox attack surface": {
    tools: () => whiteboxAttackSurfaceDefinition.activeTools(opts, none),
    budget: 4_800,
  },
  "code agent": {
    tools: () => codeAgentDefinition().activeTools(opts, none),
    budget: 14_700,
  },
  patching: {
    tools: () => patchingAgentDefinition.activeTools(opts, none),
    budget: 6_400,
  },
  "finding judge": {
    tools: () => findingJudgeDefinition.activeTools(opts, none),
    budget: 5_700,
  },
  authentication: {
    tools: () => authenticationAgentDefinition.activeTools(opts, none),
    budget: 7_300,
  },
  "vulnerability reproduction": {
    tools: () => vulnerabilityReproductionDefinition.activeTools(opts, none),
    budget: 7_000,
  },
  "siem triage": {
    tools: () =>
      siemTriageDefinition.activeTools({ logSearch: {} } as never, none),
    budget: 400,
  },
  environment: {
    tools: () => environmentAgentDefinition.activeTools(opts, none),
    budget: 4_500,
  },
};

const REGISTRY_BUDGET = 43_100;

describe("tool definition budget", () => {
  it.each(
    Object.entries(AGENTS),
  )("keeps the %s tool definitions within budget", (_agent, {
    tools,
    budget,
  }) => {
    const built = createToolsForNames(ctx, tools());
    expect(Object.keys(built).length).toBeGreaterThan(0);
    expect(estimateToolsOverheadTokens(built)).toBeLessThanOrEqual(budget);
  });

  it("keeps the whole registry within budget", () => {
    expect(
      estimateToolsOverheadTokens(createAllTools(ctx)),
    ).toBeLessThanOrEqual(REGISTRY_BUDGET);
  });

  it("caps every tool's description and total definition size", () => {
    const oversized = Object.entries(createAllTools(ctx)).flatMap(
      ([name, tool]) => {
        const description =
          (tool as { description?: string }).description ?? "";
        const tokens = estimateToolsOverheadTokens({ [name]: tool });
        return description.length > DESCRIPTION_CHAR_LIMIT ||
          tokens > TOOL_TOKEN_LIMIT
          ? [{ name, descriptionChars: description.length, tokens }]
          : [];
      },
    );
    expect(oversized).toEqual([]);
  });
});
