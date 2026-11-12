import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { createAttackSurfaceReport } from "./createAttackSurfaceReport";
import {
  documentBoundary,
  documentComponent,
  documentFlow,
} from "./documentTopology";
import type { ToolContext } from "./types";

function makeCtx(): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "apex-report-"));
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      targets: ["https://console.example"],
      rootPath: root,
    } as unknown as SessionInfo,
    agentCwd: root,
    target: "https://console.example",
  };
}

async function run(t: Tool, input: Record<string, unknown>) {
  return (await t.execute?.(
    { toolCallDescription: "test", ...input },
    { toolCallId: "tc", messages: [] },
  )) as Record<string, unknown>;
}

const report = {
  summary: { totalAssets: 2, totalDomains: 1, analysisComplete: true },
  discoveredAssets: ["console.example"],
  targets: [],
  keyFindings: [],
};
const evidence = [{ source: "source", detail: "IaC", ref: "infra/vpc.ts" }];
const component = {
  exposure: "public",
  atStake: "Tenant data.",
  trustAssumptions: [],
  evidence,
};

describe("create_attack_surface_report", () => {
  it("writes topology.mmd rendered from the documented records", async () => {
    const ctx = makeCtx();
    await run(documentBoundary(ctx), {
      name: "Private",
      kind: "subnet",
      evidence,
    });
    await run(documentComponent(ctx), {
      ...component,
      name: "Console Web",
      kind: "application",
      boundary: "Private",
    });
    await run(documentComponent(ctx), {
      ...component,
      name: "Aurora",
      kind: "database",
      boundary: "Private",
      exposure: "private",
      usedBy: ["Console Web"],
    });
    await run(documentFlow(ctx), {
      from: "Console Web",
      to: "Aurora",
      label: "SQL",
      evidence,
    });

    const result = await run(createAttackSurfaceReport(ctx), report);

    expect(result.diagramPath).toBe(join(ctx.session.rootPath, "topology.mmd"));
    const diagram = readFileSync(result.diagramPath as string, "utf8");
    expect(diagram).toMatch(/^flowchart LR\n/);
    expect(diagram).toContain('subgraph b_private["Private (subnet)"]');
    expect(diagram).toContain('c_console_web -->|"SQL"| c_aurora');
  });

  it("writes no diagram for an agent that documented no topology", async () => {
    const ctx = makeCtx();
    const result = await run(createAttackSurfaceReport(ctx), report);
    expect(result.diagramPath).toBeUndefined();
    expect(existsSync(join(ctx.session.rootPath, "topology.mmd"))).toBe(false);
  });
});
