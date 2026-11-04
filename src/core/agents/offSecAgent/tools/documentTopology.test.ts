import { mkdtempSync, readdirSync } from "node:fs";
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
  documentFlow,
  reviewTopologyRecords,
} from "./documentTopology";
import type { ToolContext } from "./types";

function makeCtx(): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "apex-topology-"));
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

async function run(
  t: Tool,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return (await t.execute?.(
    { toolCallDescription: "test", ...input },
    { toolCallId: "tc", messages: [] },
  )) as Record<string, unknown>;
}

function parses(t: Tool, input: Record<string, unknown>): boolean {
  return (
    t.inputSchema as { safeParse: (v: unknown) => { success: boolean } }
  ).safeParse({ toolCallDescription: "x", ...input }).success;
}

const fromSource = [{ source: "source", detail: "IaC", ref: "infra/vpc.ts" }];

const web = {
  name: "Console Web",
  kind: "application",
  boundary: "Private subnets",
  exposure: "public",
  atStake: "Every tenant's findings through server actions.",
  trustAssumptions: ["The AuthKit session cookie identifies the user."],
  evidence: fromSource,
};

const aurora = {
  name: "Aurora PostgreSQL",
  kind: "database",
  boundary: "Private subnets",
  exposure: "private",
  usedBy: ["console web"],
  atStake: "All tenants' data and encrypted credentials.",
  trustAssumptions: ["Any caller holding the proxy IAM role."],
  evidence: fromSource,
};

async function seed(ctx: ToolContext) {
  await run(documentBoundary(ctx), {
    name: "AWS account",
    kind: "cloud-account",
    evidence: fromSource,
  });
  await run(documentBoundary(ctx), {
    name: "Private subnets",
    kind: "subnet",
    parent: "AWS account",
    evidence: fromSource,
  });
  await run(documentComponent(ctx), web);
}

describe("document_boundary", () => {
  it("requires the parent boundary to be documented first", async () => {
    const res = await run(documentBoundary(makeCtx()), {
      name: "Private subnets",
      kind: "subnet",
      parent: "Console VPC",
      evidence: fromSource,
    });
    expect(res.error).toBe("unknown_boundary");
  });

  it("rejects a record without evidence", () => {
    expect(
      parses(documentBoundary(makeCtx()), {
        name: "VPC",
        kind: "vpc",
        evidence: [],
      }),
    ).toBe(false);
  });
});

describe("document_component", () => {
  it("requires what is at stake and what the component trusts", () => {
    const { atStake: _, trustAssumptions: __, ...withoutThreatModel } = aurora;
    expect(parses(documentComponent(makeCtx()), withoutThreatModel)).toBe(
      false,
    );
    expect(parses(documentComponent(makeCtx()), aurora)).toBe(true);
  });

  it("places a private datastore in a boundary used by an application", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const res = await run(documentComponent(ctx), aurora);
    expect(res.success).toBe(true);
    expect(
      readdirSync(join(ctx.session.rootPath, "topology")).filter((f) =>
        f.startsWith("component_aurora_postgresql_"),
      ),
    ).toHaveLength(1);
  });

  it("refuses an undocumented boundary", async () => {
    const res = await run(documentComponent(makeCtx()), web);
    expect(res.error).toBe("unknown_boundary");
  });

  it("only accepts applications in usedBy", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentComponent(ctx), aurora);
    const res = await run(documentComponent(ctx), {
      ...aurora,
      name: "Redis",
      kind: "cache",
      usedBy: ["Aurora PostgreSQL"],
    });
    expect(res.error).toBe("unknown_application");
    expect(res.message).toContain("console web");
  });
});

describe("document_flow", () => {
  it("connects documented components and refuses unknown ones", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentComponent(ctx), aurora);
    const ok = await run(documentFlow(ctx), {
      from: "Console Web",
      to: "Aurora PostgreSQL",
      label: "RDS Proxy",
      evidence: fromSource,
    });
    expect(ok.success).toBe(true);
    const bad = await run(documentFlow(ctx), {
      from: "Console Web",
      to: "Redis",
      label: "cache",
      evidence: fromSource,
    });
    expect(bad.error).toBe("unknown_component");
  });
});

describe("document_control", () => {
  const control = {
    name: "Workspace authorization",
    kind: "tenant-isolation",
    protects:
      "Every server action checks the caller belongs to the workspace it names.",
    gaps: "Enforced per handler in application code; the database has no row-level policy.",
    evidence: fromSource,
  };

  it("attaches to boundaries and components", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const res = await run(documentControl(ctx), {
      ...control,
      appliesTo: ["Private subnets", "Console Web"],
    });
    expect(res.success).toBe(true);
  });

  it("refuses a layer that was never documented", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const res = await run(documentControl(ctx), {
      ...control,
      appliesTo: ["Console Web", "Admin API"],
    });
    expect(res.error).toBe("unknown_layer");
  });
});

describe("review_topology", () => {
  async function vpcSeed(ctx: ToolContext) {
    for (const b of [
      { name: "Account", kind: "cloud-account" },
      { name: "VPC", kind: "vpc", parent: "Account" },
      { name: "Private", kind: "subnet", parent: "VPC" },
    ])
      await run(documentBoundary(ctx), { ...b, evidence: fromSource });
  }

  it("flags VPC-level placement, two-part names, missing hosts, and unconnected components", async () => {
    const ctx = makeCtx();
    await vpcSeed(ctx);
    await run(documentComponent(ctx), {
      ...web,
      name: "Gateway (Worker + Lambda)",
      boundary: "VPC",
    });
    const checks = reviewTopologyRecords(ctx)
      .map((i) => i.check)
      .sort();
    expect(checks).toEqual([
      "names-two-parts",
      "placed-at-vpc-level",
      "public-without-host",
      "unconnected",
    ]);
  });

  it("flags a VPC with no subnet tiers", async () => {
    const ctx = makeCtx();
    await run(documentBoundary(ctx), {
      name: "Account",
      kind: "cloud-account",
      evidence: fromSource,
    });
    await run(documentBoundary(ctx), {
      name: "VPC",
      kind: "vpc",
      parent: "Account",
      evidence: fromSource,
    });
    expect(reviewTopologyRecords(ctx).map((i) => i.check)).toEqual([
      "vpc-without-subnets",
    ]);
  });

  it("passes a placed, hosted, connected topology", async () => {
    const ctx = makeCtx();
    await vpcSeed(ctx);
    await run(documentComponent(ctx), {
      ...web,
      boundary: "Private",
      endpoints: ["https://console.example"],
    });
    await run(documentComponent(ctx), { ...aurora, boundary: "Private" });
    await run(documentFlow(ctx), {
      from: "Console Web",
      to: "Aurora PostgreSQL",
      label: "SQL",
      evidence: fromSource,
    });
    expect(reviewTopologyRecords(ctx)).toEqual([]);
  });
});
