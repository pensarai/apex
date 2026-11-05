import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../../offSecAgent/subagentSpawner";
import {
  documentBoundary,
  documentComponent,
  documentControl,
  documentFlow,
} from "../../offSecAgent/tools/documentTopology";
import { loadTopology } from "../../offSecAgent/tools/topologyRecords";
import type { ToolContext } from "../../offSecAgent/tools/types";
import {
  type GeneralizedAttackSurfaceAgentInput,
  type GeneralizedAttackSurfaceResult,
  runGeneralizedReconToReport,
} from "./generalizedAgent";
import { isSurfaceIrrelevant, refCitesFile, scopeCommit } from "./reconUpdate";

function makeCtx(id: string): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "apex-update-"));
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id,
      targets: ["https://shop.example"],
      rootPath: root,
    } as unknown as SessionInfo,
    agentCwd: root,
    target: "https://shop.example",
  };
}

async function run(t: Tool, input: Record<string, unknown>) {
  return (await t.execute?.(
    { toolCallDescription: "test", ...input },
    { toolCallId: "tc", messages: [] },
  )) as Record<string, unknown>;
}

const src = (ref: string) => [{ source: "source", detail: "read", ref }];

/** A baseline map: an API on a public host, its database, and a control. */
async function baseline(): Promise<ToolContext> {
  const ctx = makeCtx("ses_base");
  await run(documentBoundary(ctx), {
    name: "Private",
    kind: "subnet",
    evidence: src("docker-compose.yml"),
  });
  await run(documentComponent(ctx), {
    name: "Shop API",
    kind: "application",
    boundary: "Private",
    exposure: "public",
    endpoints: ["https://api.shop.example"],
    atStake: "Orders.",
    trustAssumptions: [],
    evidence: src("./apps/api/app.py:12"),
  });
  await run(documentComponent(ctx), {
    name: "Postgres",
    kind: "database",
    boundary: "Private",
    exposure: "private",
    atStake: "Rows.",
    trustAssumptions: [],
    evidence: src("docker-compose.yml"),
  });
  await run(documentFlow(ctx), {
    from: "Shop API",
    to: "Postgres",
    label: "SQL",
    evidence: src("apps/api/db.py"),
  });
  await run(documentControl(ctx), {
    name: "API token auth",
    kind: "authentication",
    appliesTo: ["Shop API"],
    protects: "Orders need a token.",
    evidence: src("apps/api/auth/"),
  });
  return ctx;
}

const reported = {
  results: {},
  targets: [],
} as unknown as GeneralizedAttackSurfaceResult;

function updateInput(
  base: ToolContext,
  trigger: NonNullable<GeneralizedAttackSurfaceAgentInput["update"]>["trigger"],
) {
  const next = makeCtx("ses_update");
  const input = {
    target: "https://shop.example",
    session: next.session,
    update: { baselineSessionRoot: base.session.rootPath, trigger },
  } as GeneralizedAttackSurfaceAgentInput;
  return { next, input };
}

describe("refCitesFile", () => {
  it.each([
    ["apps/api/app.py", "apps/api/app.py", true],
    ["./apps/api/app.py:12", "apps/api/app.py", true],
    ["repos/backend/apps/api/app.py", "apps/api/app.py", true],
    ["app.py", "apps/api/app.py", true],
    ["apps/api/auth/", "apps/api/auth/tokens.py", true],
    ["infra", "infra/queues.ts", true],
    ["apps/api/app.py", "apps/web/app.py", false],
    ["https://api.shop.example/health", "health", false],
    ["myapp.py", "app.py", false],
  ])("ref %s cites %s: %s", (ref, file, expected) => {
    expect(refCitesFile(ref, file)).toBe(expected);
  });
});

describe("scopeCommit", () => {
  it("maps changed files to the records whose evidence cites them, and lists the rest", async () => {
    const base = await baseline();
    const scope = scopeCommit(loadTopology(base.session.rootPath), [
      "apps/api/app.py",
      "apps/api/auth/tokens.py",
      "infra/queues.ts",
      "README.md",
    ]);
    expect(scope.components).toEqual(["Shop API"]);
    expect(scope.controls).toEqual(["API token auth"]);
    expect(scope.flows).toEqual([]);
    expect(scope.unmapped).toEqual(["infra/queues.ts"]);
    expect(scope.ignored).toEqual(["README.md"]);
  });

  it("treats documentation, images, and licenses as unable to change the surface", () => {
    expect(
      ["docs/setup.md", "README.md", "LICENSE", "assets/logo.png"].every(
        isSurfaceIrrelevant,
      ),
    ).toBe(true);
    expect(
      [
        "apps/api/app.py",
        "infra/vpc.ts",
        "docker-compose.yml",
        "bun.lock",
      ].some(isSurfaceIrrelevant),
    ).toBe(false);
  });
});

describe("runGeneralizedReconToReport with an update", () => {
  it("skips the agent for a commit that cannot change the surface, and writes an empty change set", async () => {
    const base = await baseline();
    const { next, input } = updateInput(base, {
      kind: "commit",
      repository: "shop",
      range: "a1..b2",
      changedFiles: ["README.md", "docs/deploy.md"],
    });
    let ran = false;
    const result = await runGeneralizedReconToReport(input, () => {
      ran = true;
      return { consume: async () => reported };
    });
    expect(ran).toBe(false);
    expect(result.skipped).toMatch(/No surface-relevant change in a1\.\.b2/);
    expect(result.changeSet?.added).toEqual([]);
    expect(result.changeSet?.changed).toEqual([]);
    expect(result.changeSet?.retired).toEqual([]);
    expect(result.changeSet?.unverified).toHaveLength(5);
    expect(existsSync(join(next.session.rootPath, "topology.mmd"))).toBe(true);
  });

  it("seeds the baseline, briefs the agent on what to re-verify, and reports what it changed", async () => {
    const base = await baseline();
    const { next, input } = updateInput(base, {
      kind: "commit",
      repository: "shop",
      range: "a1..b2",
      changedFiles: ["apps/api/app.py", "infra/queues.ts"],
    });
    const seen: GeneralizedAttackSurfaceAgentInput[] = [];
    const result = await runGeneralizedReconToReport(input, (i) => {
      seen.push(i);
      return {
        consume: async () => {
          // The agent sees the baseline already in its session…
          expect(loadTopology(next.session.rootPath).components).toHaveLength(
            2,
          );
          // …and makes the change the commit introduced.
          await run(documentComponent(next), {
            name: "Jobs",
            kind: "queue",
            boundary: "Private",
            exposure: "private",
            atStake: "Job payloads.",
            trustAssumptions: [],
            evidence: src("infra/queues.ts"),
          });
          await run(documentFlow(next), {
            from: "Shop API",
            to: "Jobs",
            label: "enqueue",
            evidence: src("apps/api/app.py"),
          });
          return reported;
        },
      };
    });
    expect(seen).toHaveLength(1);
    const brief = seen[0]?.updateBrief ?? "";
    expect(brief).toContain("## Update run");
    expect(brief).toContain("git diff a1..b2");
    expect(brief).toMatch(/Components:\n- Shop API/);
    expect(brief).toMatch(
      /read each for components[^\n]*\n- infra\/queues\.ts/,
    );
    expect(brief).toContain("```mermaid\nflowchart LR");
    expect(brief).toContain("retire_record");
    expect(brief).toContain("renameFrom");
    expect(brief).toContain(
      "call update_record with only the fields that changed",
    );
    expect(brief).toContain("most will be unaffected");
    expect(result.changeSet?.added.map((a) => a.name).sort()).toEqual([
      "Jobs",
      "Shop API → Jobs (enqueue)",
    ]);
    expect(result.changeSet?.retired).toEqual([]);
    expect(
      JSON.parse(readFileSync(result.changesPath as string, "utf8")).added,
    ).toHaveLength(2);
  });

  it("briefs a scheduled run to re-probe public endpoints and read cloud changes", async () => {
    const base = await baseline();
    const { input } = updateInput(base, {
      kind: "schedule",
      cloudChanges: "- new bucket shop-exports (public)",
    });
    const seen: GeneralizedAttackSurfaceAgentInput[] = [];
    await runGeneralizedReconToReport(input, (i) => {
      seen.push(i);
      return { consume: async () => reported };
    });
    const brief = seen[0]?.updateBrief ?? "";
    expect(brief).toContain("scheduled re-check");
    expect(brief).toContain("- Shop API: https://api.shop.example");
    expect(brief).not.toContain("Postgres:");
    expect(brief).toContain("new bucket shop-exports (public)");
  });

  it("briefs a scope run to map the added origins and repositories into the existing map", async () => {
    const base = await baseline();
    const { input } = updateInput(base, {
      kind: "scope",
      addedOrigins: ["https://admin.shop.example"],
      addedRepositories: ["admin-portal"],
    });
    const seen: GeneralizedAttackSurfaceAgentInput[] = [];
    const result = await runGeneralizedReconToReport(input, (i) => {
      seen.push(i);
      return { consume: async () => reported };
    });
    const brief = seen[0]?.updateBrief ?? "";
    expect(result.skipped).toBeUndefined();
    expect(brief).toContain("scope grew");
    expect(brief).toContain("- https://admin.shop.example");
    expect(brief).toContain("- admin-portal");
    expect(brief).not.toContain("scheduled re-check");
  });

  it("keeps the update brief on continuation passes", async () => {
    const base = await baseline();
    const { input } = updateInput(base, { kind: "schedule" });
    const seen: GeneralizedAttackSurfaceAgentInput[] = [];
    const unreported = {
      results: null,
      targets: [],
    } as unknown as GeneralizedAttackSurfaceResult;
    await runGeneralizedReconToReport(input, (i) => {
      seen.push(i);
      return {
        consume: async () => (seen.length === 1 ? unreported : reported),
      };
    });
    expect(seen).toHaveLength(2);
    expect(seen[1]?.continuation).toMatch(/## Continue/);
    expect(seen[1]?.updateBrief).toBe(seen[0]?.updateBrief);
  });
});
