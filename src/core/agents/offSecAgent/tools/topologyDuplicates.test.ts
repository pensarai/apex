import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  describeMapForWorker,
  documentBoundary,
  documentComponent,
  documentControl,
  documentFlow,
  mergeRecords,
  reviewTopologyRecords,
} from "./documentTopology";
import { duplicateReason, namesOverlap } from "./topologyDuplicates";
import { loadTopology, type TopologyRecord } from "./topologyRecords";
import type { ToolContext } from "./types";

const rec = (r: Record<string, unknown>): TopologyRecord => ({
  id: String(r.name),
  ...r,
});

describe("duplicate signals", () => {
  // Pairs a parallel worker produced in a real run of console.pensar.dev.
  it.each([
    ["Aurora PostgreSQL (console production)", "Console Aurora PostgreSQL"],
    ["ElastiCache Redis (console production)", "Console Redis"],
    ["Console S3 buckets (production)", "Console S3 buckets"],
    ["Pensar Console web app (production)", "Pensar Console (web)"],
    [
      "pentest agent sandboxes (daytona, production)",
      "Pentest agent sandbox (Daytona)",
    ],
    ["WorkOS AuthKit (console IdP)", "WorkOS AuthKit"],
  ])("%s and %s describe one thing", (a, b) => {
    expect(namesOverlap(a, b)).toBe(true);
  });

  it("does not match different things, single words, or plain prefixes", () => {
    expect(
      namesOverlap(
        "Internal VPC private subnets",
        "Internal VPC public subnets",
      ),
    ).toBe(false);
    expect(namesOverlap("API", "Shop API gateway")).toBe(false);
    expect(
      namesOverlap(
        "Console frontend CloudFront distribution",
        "API router CloudFront distribution",
      ),
    ).toBe(false);
  });

  it("matches components on a shared host, and keeps apart components on different known hosts", () => {
    const egress = rec({
      name: "Agent egress gateway",
      kind: "proxy",
      endpoints: ["prod-agent-egress.pensar.dev:3128"],
    });
    expect(
      duplicateReason(
        "component",
        egress,
        rec({
          name: "Sandbox proxy",
          kind: "proxy",
          endpoints: ["http://prod-agent-egress.pensar.dev:3128"],
        }),
      ),
    ).toMatch(/both answer on/);
    expect(
      duplicateReason(
        "component",
        rec({
          name: "Internal VPN gateway (vpn.pensar.dev)",
          kind: "entrypoint",
          endpoints: ["vpn.pensar.dev"],
        }),
        rec({
          name: "Prod VPN gateway (prod-vpn.pensar.dev)",
          kind: "entrypoint",
          endpoints: ["prod-vpn.pensar.dev"],
        }),
      ),
    ).toBeUndefined();
  });

  it("ignores app-link schemes, and keeps apart paths one host routes to different services", () => {
    // Two clients handling the same deep link are not one component.
    expect(
      duplicateReason(
        "component",
        rec({
          name: "PocketPay for Android",
          kind: "client",
          endpoints: ["pocketpay://transfer?to=1"],
        }),
        rec({
          name: "PocketPay for iOS",
          kind: "client",
          endpoints: ["pocketpay://transfer?to=1"],
        }),
      ),
    ).toBeUndefined();
    // /v1 and /v2 on one gateway host are different services.
    expect(
      duplicateReason(
        "component",
        rec({
          name: "PocketPay API v2",
          kind: "application",
          endpoints: ["http://api.pocketpay.example:20080/v2/"],
        }),
        rec({
          name: "Legacy API v1",
          kind: "application",
          endpoints: ["http://api.pocketpay.example:20080/v1/"],
        }),
      ),
    ).toBeUndefined();
  });

  it("keeps apart same-named boundaries under different parents, and accounts with different ids", () => {
    expect(
      duplicateReason(
        "boundary",
        rec({
          name: "us-east-1 (internal account)",
          kind: "region",
          parent: "Internal",
        }),
        rec({
          name: "us-east-1 (production account)",
          kind: "region",
          parent: "Production",
        }),
      ),
    ).toBeUndefined();
    expect(
      duplicateReason(
        "boundary",
        rec({
          name: "Pensar internal AWS account (182719847421)",
          kind: "cloud-account",
          provider: "aws",
        }),
        rec({
          name: "Pensar production AWS account (327070112015)",
          kind: "cloud-account",
          provider: "aws",
        }),
      ),
    ).toBeUndefined();
    expect(
      duplicateReason(
        "boundary",
        rec({
          name: "Console AWS account",
          kind: "cloud-account",
          provider: "aws",
        }),
        rec({
          name: "Pensar production AWS account (327070112015)",
          kind: "cloud-account",
          provider: "aws",
        }),
      ),
    ).toMatch(/no account id/);
  });

  it("respects distinctFrom on either record", () => {
    const a = rec({
      name: "Console Redis",
      kind: "cache",
      distinctFrom: ["ElastiCache Redis (console production)"],
    });
    expect(
      duplicateReason(
        "component",
        a,
        rec({ name: "ElastiCache Redis (console production)", kind: "cache" }),
      ),
    ).toBeUndefined();
  });
});

function makeCtx(): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "apex-dupes-"));
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

const evidence = [{ source: "source", detail: "IaC", ref: "infra/db.ts" }];
const component = (name: string, extra: Record<string, unknown> = {}) => ({
  name,
  kind: "database",
  boundary: "Private",
  exposure: "private",
  atStake: "Tenant data.",
  trustAssumptions: [],
  evidence,
  ...extra,
});

async function seed(ctx: ToolContext) {
  await run(documentBoundary(ctx), {
    name: "Account",
    kind: "cloud-account",
    provider: "aws",
    evidence,
  });
  await run(documentBoundary(ctx), {
    name: "Private",
    kind: "subnet",
    parent: "Account",
    evidence,
  });
  await run(
    documentComponent(ctx),
    component("Console Web", {
      kind: "application",
      exposure: "public",
      endpoints: ["https://console.example"],
    }),
  );
  await run(
    documentComponent(ctx),
    component("Aurora PostgreSQL (console production)", {
      usedBy: ["Console Web"],
    }),
  );
  await run(documentFlow(ctx), {
    from: "Console Web",
    to: "Aurora PostgreSQL (console production)",
    label: "SQL",
    evidence,
  });
}

describe("the duplicate guard on new records", () => {
  it("refuses a new component that looks like a documented one, naming it", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const result = await run(
      documentComponent(ctx),
      component("Console Aurora PostgreSQL"),
    );
    expect(result).toMatchObject({
      success: false,
      error: "possible_duplicate",
      existing: ["Aurora PostgreSQL (console production)"],
    });
    expect(loadTopology(ctx.session.rootPath).components).toHaveLength(2);
  });

  it("accepts it with distinctFrom, and the review then leaves the pair alone", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const result = await run(
      documentComponent(ctx),
      component("Console Aurora PostgreSQL", {
        distinctFrom: ["Aurora PostgreSQL (console production)"],
      }),
    );
    expect(result.success).toBe(true);
    expect(reviewTopologyRecords(ctx).map((i) => i.check)).not.toContain(
      "possible-duplicate",
    );
  });

  it("never blocks updating or renaming an existing record", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    expect(
      (
        await run(
          documentComponent(ctx),
          component("Aurora PostgreSQL (console production)", {
            tech: "Aurora 16",
          }),
        )
      ).success,
    ).toBe(true);
    expect(
      (
        await run(
          documentComponent(ctx),
          component("Console Aurora PostgreSQL", {
            renameFrom: "Aurora PostgreSQL (console production)",
          }),
        )
      ).success,
    ).toBe(true);
  });
});

describe("merge_records", () => {
  /** Two records for one database, each with its own flow and control — what a parallel worker leaves behind. */
  async function duplicated(ctx: ToolContext) {
    await seed(ctx);
    await run(
      documentComponent(ctx),
      component("Console Aurora PostgreSQL", {
        distinctFrom: ["Aurora PostgreSQL (console production)"],
      }),
    );
    await run(documentFlow(ctx), {
      from: "Console Web",
      to: "Console Aurora PostgreSQL",
      label: "SQL",
      evidence,
    });
    await run(documentFlow(ctx), {
      from: "Console Web",
      to: "Console Aurora PostgreSQL",
      label: "migrations",
      evidence,
    });
    await run(documentControl(ctx), {
      name: "DB IAM auth",
      kind: "authentication",
      appliesTo: ["Console Aurora PostgreSQL"],
      protects: "IAM-only logins.",
      evidence,
    });
  }

  it("moves flows and controls to the kept component, drops the flow that became a copy, and retires the duplicate", async () => {
    const ctx = makeCtx();
    await duplicated(ctx);
    const keep = "Aurora PostgreSQL (console production)";
    const result = await run(mergeRecords(ctx), {
      kind: "component",
      keep,
      duplicate: "Console Aurora PostgreSQL",
    });
    expect(result).toMatchObject({ success: true, flowsRetired: 1 });
    const t = loadTopology(ctx.session.rootPath);
    expect(t.components.map((c) => c.name).sort()).toEqual([
      keep,
      "Console Web",
    ]);
    expect(
      t.flows.map((f) => `${f.from} → ${f.to} (${f.label})`).sort(),
    ).toEqual([
      `Console Web → ${keep} (SQL)`,
      `Console Web → ${keep} (migrations)`,
    ]);
    expect(t.controls[0]?.appliesTo).toEqual([keep]);
    expect(
      t.retired.map((r) => [r.kind, r.record.name, r.record.retiredReason]),
    ).toContainEqual([
      "component",
      "Console Aurora PostgreSQL",
      `Merged into "${keep}"`,
    ]);
    expect(
      reviewTopologyRecords(ctx).filter(
        (i) => i.check === "references-retired",
      ),
    ).toEqual([]);
  });

  it("moves a duplicate boundary's components and child boundaries to the kept one", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentBoundary(ctx), {
      name: "AWS production account",
      kind: "cloud-account",
      provider: "aws",
      distinctFrom: ["Account"],
      evidence,
    });
    await run(documentBoundary(ctx), {
      name: "Public",
      kind: "subnet",
      parent: "AWS production account",
      evidence,
    });
    await run(
      documentComponent(ctx),
      component("Load balancer", {
        kind: "entrypoint",
        boundary: "AWS production account",
        exposure: "public",
        endpoints: ["https://lb.console.example"],
      }),
    );
    await run(mergeRecords(ctx), {
      kind: "boundary",
      keep: "Account",
      duplicate: "AWS production account",
    });
    const t = loadTopology(ctx.session.rootPath);
    expect(t.boundaries.map((b) => b.name).sort()).toEqual([
      "Account",
      "Private",
      "Public",
    ]);
    expect(t.boundaries.find((b) => b.name === "Public")?.parent).toBe(
      "Account",
    );
    expect(t.components.find((c) => c.name === "Load balancer")?.boundary).toBe(
      "Account",
    );
  });

  it("refuses unknown names and merging a record into itself", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    expect(
      await run(mergeRecords(ctx), {
        kind: "component",
        keep: "Console Web",
        duplicate: "Redis",
      }),
    ).toMatchObject({ success: false });
    expect(
      await run(mergeRecords(ctx), {
        kind: "component",
        keep: "Console Web",
        duplicate: "console web",
      }),
    ).toMatchObject({ error: "same_record" });
  });
});

describe("review_topology possible-duplicate", () => {
  it("flags a pair that slipped past the guard (written before it existed)", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(
      documentComponent(ctx),
      component("Console Aurora PostgreSQL", {
        distinctFrom: ["Aurora PostgreSQL (console production)"],
      }),
    );
    // Clear the acknowledgement, as a record written by an older run would lack it.
    await run(
      documentComponent(ctx),
      component("Console Aurora PostgreSQL", { distinctFrom: [] }),
    );
    const dup = reviewTopologyRecords(ctx).find(
      (i) => i.check === "possible-duplicate",
    );
    expect(dup?.subject).toBe(
      "Aurora PostgreSQL (console production) / Console Aurora PostgreSQL",
    );
    expect(dup?.fix).toContain("merge_records");
  });
});

describe("describeMapForWorker", () => {
  it("lists what exists with where it is, and tells the worker to reuse those names", async () => {
    const ctx = makeCtx();
    expect(describeMapForWorker(ctx.session.rootPath)).toBe("");
    await seed(ctx);
    const brief = describeMapForWorker(ctx.session.rootPath);
    expect(brief).toContain("Reuse their exact names");
    expect(brief).toContain("- Private (subnet, in Account)");
    expect(brief).toContain(
      "- Aurora PostgreSQL (console production) (database, in Private)",
    );
  });
});
