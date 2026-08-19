import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { StaticPromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import { runAgentRedTeamWorkflow } from "./runAgentRedTeamWorkflow";
import type { ToolContext } from "./types";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tempSessionRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), "apex-agent-redteam-tool-"));
  tempDirs.push(dir);
  return dir;
}

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  const rootPath = tempSessionRoot();
  return {
    session: {
      id: "ses_agent_redteam",
      version: "1.0.0",
      targets: ["https://agent.example.test"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath,
      logsPath: join(rootPath, "logs"),
      findingsPath: join(rootPath, "findings"),
      scratchpadPath: join(rootPath, "scratchpad"),
      pocsPath: join(rootPath, "pocs"),
    } as SessionInfo,
    agentCwd: rootPath,
    ...overrides,
  };
}

describe("runAgentRedTeamWorkflow tool", () => {
  it("returns built-in carrier attempts plus metadata-only jailbreak library seeds", async () => {
    const rawPayload = "RAW TOOL HIJACK PAYLOAD";
    const library = new StaticPromptInjectionLibrary([
      {
        id: "pi.tool.hijack",
        name: "Tool Hijack Seed",
        category: "tool-misuse",
        description: "Safe metadata for a tool misuse seed.",
        tags: ["tool"],
        deliveryHints: ["tool-return-value"],
        expectedObservation: "The agent should not follow tool output.",
        payload: rawPayload,
      },
    ]);
    const tool = runAgentRedTeamWorkflow(
      makeCtx({ promptInjectionLibrary: library }),
    );

    const result = (await tool.execute?.(
      {
        target: "https://agent.example.test",
        techniques: ["tool-surface-indirect"],
        maxAttempts: 20,
        usePromptInjectionLibrarySeeds: true,
        maxPromptInjectionSeeds: 1,
        toolCallDescription: "Generate agent red-team workflow",
      },
      { toolCallId: "tc_agent_redteam", messages: [], abortSignal: undefined },
    )) as {
      success: boolean;
      totalAttempts: number;
      ledgerPath?: string;
      campaignId: string;
      attempts: Array<{
        carrierLabel: string;
        variant: string;
        status: string;
        primitiveStack: string[];
        expectedDetectorBlindSpot?: string;
        renderedPrompt: string;
        seed?: { id: string; source: string };
      }>;
      seedProviders: Array<{ status: string; seedCount: number }>;
    };

    expect(result.success).toBe(true);
    expect(result.totalAttempts).toBeGreaterThan(0);
    expect(result.campaignId).toMatch(/^campaign_/);
    expect(result.ledgerPath).toContain(
      `agent-redteam/campaigns/${result.campaignId}/attempts.jsonl`,
    );
    expect(result.seedProviders).toContainEqual({
      status: "loaded",
      seedCount: 1,
      source: "prompt-injection-library",
    });

    const seeded = result.attempts.find(
      (attempt) => attempt.seed?.id === "pi.tool.hijack",
    );

    expect(seeded?.carrierLabel).toBe("tool-output-authority");
    expect(seeded?.variant).toBe("external-seed");
    expect(seeded?.status).toBe("planned");
    expect(seeded?.primitiveStack).toEqual([
      "tool-output-authority-probe",
      "format-contract",
    ]);
    expect(seeded?.expectedDetectorBlindSpot).toContain(
      "tool-output instruction/data confusion",
    );
    expect(seeded?.renderedPrompt).toContain("Tool result:");
    expect(seeded?.renderedPrompt).toContain(
      'PromptInjectionRef: {"kind":"prompt_injection_ref","id":"pi.tool.hijack"}',
    );
    expect(JSON.stringify(result)).not.toContain(rawPayload);
  });
});
