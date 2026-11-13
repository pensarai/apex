import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  documentBoundary,
  documentComponent,
  documentControl,
  documentThreat,
  mergeRecords,
  retireRecord,
  reviewTopologyRecords,
  updateRecord,
} from "./documentTopology";
import {
  diffTopology,
  loadTopology,
  seedFromBaseline,
} from "./topologyRecords";
import type { ToolContext } from "./types";

function makeCtx(id = "ses_base"): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "apex-threats-"));
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id,
      targets: ["https://pay.example"],
      rootPath: root,
    } as unknown as SessionInfo,
    agentCwd: root,
    target: "https://pay.example",
  };
}

async function run(t: Tool, input: Record<string, unknown>) {
  return (await t.execute?.(
    { toolCallDescription: "test", ...input },
    { toolCallId: "tc", messages: [] },
  )) as Record<string, unknown>;
}

const evidence = [
  { source: "source", detail: "read", ref: "services/legacy.py" },
];
const component = (name: string, extra: Record<string, unknown> = {}) => ({
  name,
  kind: "application",
  boundary: "App zone",
  exposure: "public",
  endpoints: [`https://${name.toLowerCase().replace(/\W+/g, "-")}.pay.example`],
  atStake: "Accounts.",
  trustAssumptions: [],
  evidence,
  ...extra,
});
const idor = {
  component: "Legacy API",
  title: "Read any account by id",
  category: "information-disclosure",
  scenario:
    "An anonymous caller walks /v1/accounts/<id> through the gateway and reads every account.",
  preconditions: [],
  impact: "Every user's name, phone, and balance.",
  likelihood: "high",
  likelihoodRationale: "Public, unauthenticated, sequential ids.",
  controls: ["Legacy auth"],
  evidence,
};

async function seed(ctx: ToolContext) {
  await run(documentBoundary(ctx), {
    name: "App zone",
    kind: "subnet",
    evidence,
  });
  await run(documentComponent(ctx), component("Legacy API"));
  await run(
    documentComponent(ctx),
    component("Card vault", {
      kind: "saas",
      exposure: "private",
      endpoints: undefined,
    }),
  );
  await run(documentControl(ctx), {
    name: "Legacy auth",
    kind: "authentication",
    appliesTo: ["Legacy API"],
    protects: "Nothing.",
    gaps: "No auth.",
    evidence,
  });
}

describe("document_threat", () => {
  it("attaches a threat to its component and the controls it gets past, by id", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    expect((await run(documentThreat(ctx), idor)).success).toBe(true);
    const t = loadTopology(ctx.session.rootPath);
    const [threat] = t.threats;
    expect(threat).toMatchObject({
      component: "Legacy API",
      controls: ["Legacy auth"],
      likelihood: "high",
    });
    expect(threat?.componentId).toBe(
      t.components.find((c) => c.name === "Legacy API")?.id,
    );
    expect(threat?.controlIds).toEqual([t.controls[0]?.id]);
  });

  it("updates in place for the same title on the same component", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentThreat(ctx), idor);
    await run(documentThreat(ctx), {
      ...idor,
      title: "read ANY account by id",
      likelihood: "medium",
    });
    const threats = loadTopology(ctx.session.rootPath).threats;
    expect(threats).toHaveLength(1);
    expect(threats[0]?.likelihood).toBe("medium");
  });

  it("refuses an unknown component or control", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    expect(
      await run(documentThreat(ctx), { ...idor, component: "Admin API" }),
    ).toMatchObject({ error: "unknown_component" });
    expect(
      await run(documentThreat(ctx), { ...idor, controls: ["WAF"] }),
    ).toMatchObject({ error: "unknown_control" });
  });

  it("follows its component through a rename", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentThreat(ctx), idor);
    await run(
      documentComponent(ctx),
      component("Legacy API v1", { renameFrom: "Legacy API" }),
    );
    expect(loadTopology(ctx.session.rootPath).threats[0]?.component).toBe(
      "Legacy API v1",
    );
  });
});

describe("threats in update_record, retire_record, and merge_records", () => {
  it("updates only the given threat fields", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentThreat(ctx), idor);
    const result = await run(updateRecord(ctx), {
      kind: "threat",
      component: "Legacy API",
      name: "Read any account by id",
      changes: { likelihood: "low", likelihoodRationale: "Now behind auth." },
      evidence,
    });
    expect(result).toMatchObject({
      success: true,
      changed: ["likelihood", "likelihoodRationale"],
    });
    const [threat] = loadTopology(ctx.session.rootPath).threats;
    expect(threat).toMatchObject({
      likelihood: "low",
      scenario: idor.scenario,
    });
  });

  it("retires a threat by component and title", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentThreat(ctx), idor);
    await run(retireRecord(ctx), {
      kind: "threat",
      component: "Legacy API",
      name: "Read any account by id",
      reason: "v1 removed.",
      evidence,
    });
    const t = loadTopology(ctx.session.rootPath);
    expect(t.threats).toEqual([]);
    expect(t.retired.map((r) => r.kind)).toEqual(["threat"]);
  });

  it("moves a duplicate component's threats to the kept one, retiring a title it already has", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(
      documentComponent(ctx),
      component("Legacy API v1", { distinctFrom: ["Legacy API"] }),
    );
    await run(documentThreat(ctx), idor);
    await run(documentThreat(ctx), {
      ...idor,
      component: "Legacy API v1",
      controls: [],
    });
    await run(documentThreat(ctx), {
      ...idor,
      component: "Legacy API v1",
      title: "Enumerate transfers",
      controls: [],
    });
    await run(mergeRecords(ctx), {
      kind: "component",
      keep: "Legacy API",
      duplicate: "Legacy API v1",
    });
    const threats = loadTopology(ctx.session.rootPath).threats;
    expect(threats.map((t) => `${t.component}: ${t.title}`).sort()).toEqual([
      "Legacy API: Enumerate transfers",
      "Legacy API: Read any account by id",
    ]);
  });
});

describe("review_topology threat checks", () => {
  it("flags unreviewed customer and third-party components without requiring invented threats", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const flagged = reviewTopologyRecords(ctx)
      .filter((i) => i.check === "no-threats")
      .map((i) => i.subject);
    expect(flagged.sort()).toEqual(["Card vault", "Legacy API"]);
    await run(documentThreat(ctx), idor);
    expect(
      reviewTopologyRecords(ctx)
        .filter((i) => i.check === "no-threats")
        .map((i) => i.subject),
    ).toEqual(["Card vault"]);
  });

  it("flags a threat left on a retired component", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentThreat(ctx), idor);
    await run(retireRecord(ctx), {
      kind: "component",
      name: "Legacy API",
      reason: "Removed.",
      evidence,
    });
    expect(
      reviewTopologyRecords(ctx).find(
        (i) => i.subject === "Legacy API: Read any account by id",
      )?.check,
    ).toBe("references-retired");
  });
});

describe("threats in the change set", () => {
  it("reports an added threat and a changed one under 'component: title'", async () => {
    const base = makeCtx();
    await seed(base);
    await run(documentThreat(base), idor);
    const next = makeCtx("ses_update");
    seedFromBaseline(next.session.rootPath, base.session.rootPath);
    await run(updateRecord(next), {
      kind: "threat",
      component: "Legacy API",
      name: "Read any account by id",
      changes: { likelihood: "low" },
      evidence,
    });
    await run(documentThreat(next), { ...idor, title: "Enumerate transfers" });
    const change = diffTopology(
      base.session.rootPath,
      next.session.rootPath,
      "ses_update",
    );
    expect(change.added.map((a) => `${a.kind}:${a.name}`)).toEqual([
      "threat:Legacy API: Enumerate transfers",
    ]);
    expect(change.changed.map((c) => [c.name, Object.keys(c.fields)])).toEqual([
      ["Legacy API: Read any account by id", ["likelihood"]],
    ]);
  });
});
