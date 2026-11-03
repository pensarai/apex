import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  documentAttackVector,
  documentBoundary,
  documentComponent,
  documentControl,
  documentFlow,
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

describe("document_attack_vector", () => {
  const vector = {
    title: "Tenant isolation rests on every handler",
    risk: "One handler that skips the check exposes another tenant.",
    rationale: "Isolation is enforced per handler, not by the database.",
    impact: "Cross-tenant disclosure.",
    pattern: "missing-control",
    priority: "high",
    evidence: fromSource,
  };

  it("spans components and links documented controls", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentComponent(ctx), aurora);
    await run(documentControl(ctx), {
      name: "Workspace authorization",
      kind: "tenant-isolation",
      appliesTo: ["Console Web"],
      protects: "Handler checks.",
      evidence: fromSource,
    });
    const res = await run(documentAttackVector(ctx), {
      ...vector,
      components: ["Console Web", "aurora postgresql"],
      controls: ["workspace authorization"],
    });
    expect(res.success).toBe(true);
  });

  it("refuses unknown components and controls", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    expect(
      (
        await run(documentAttackVector(ctx), {
          ...vector,
          components: ["Console Web", "Redis"],
        })
      ).error,
    ).toBe("unknown_component");
    expect(
      (
        await run(documentAttackVector(ctx), {
          ...vector,
          components: ["Console Web"],
          controls: ["API WAF"],
        })
      ).error,
    ).toBe("unknown_control");
  });

  it("requires at least one component", () => {
    expect(
      parses(documentAttackVector(makeCtx()), { ...vector, components: [] }),
    ).toBe(false);
  });
});
