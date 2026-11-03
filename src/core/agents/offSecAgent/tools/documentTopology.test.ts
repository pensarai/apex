import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { documentApp } from "./documentApp";
import {
  documentAttackVector,
  documentBoundary,
  documentControl,
  documentFlow,
  documentService,
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

const fromSource = [{ source: "source", detail: "IaC", ref: "infra/vpc.ts" }];

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
  await run(documentApp(ctx), {
    appName: "Console Web",
    appType: "web_application",
    description: "UI",
    boundary: "Private subnets",
  });
}

describe("document_boundary", () => {
  it("requires the parent boundary to be documented first", async () => {
    const ctx = makeCtx();
    const res = await run(documentBoundary(ctx), {
      name: "Private subnets",
      kind: "subnet",
      parent: "Console VPC",
      evidence: fromSource,
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("unknown_boundary");
  });

  it("rejects a record without evidence", () => {
    const schema = documentBoundary(makeCtx()).inputSchema as {
      safeParse: (v: unknown) => { success: boolean };
    };
    expect(
      schema.safeParse({
        name: "VPC",
        kind: "vpc",
        evidence: [],
        toolCallDescription: "x",
      }).success,
    ).toBe(false);
  });
});

describe("document_app boundary", () => {
  it("rejects a boundary that was never documented", async () => {
    const ctx = makeCtx();
    const res = await run(documentApp(ctx), {
      appName: "Console Web",
      appType: "web_application",
      description: "UI",
      boundary: "Nowhere",
    });
    expect(res.error).toBe("unknown_boundary");
  });
});

describe("document_service", () => {
  it("attaches a private datastore to a boundary and its applications", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const res = await run(documentService(ctx), {
      name: "Aurora PostgreSQL",
      kind: "database",
      boundary: "private subnets",
      exposure: "private",
      applications: ["console web"],
      evidence: fromSource,
    });
    expect(res.success).toBe(true);
    expect(
      readdirSync(join(ctx.session.rootPath, "topology")).filter((f) =>
        f.startsWith("service_aurora_postgresql_"),
      ),
    ).toHaveLength(1);
  });

  it("names the documented applications when one is unknown", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const res = await run(documentService(ctx), {
      name: "Redis",
      kind: "cache",
      boundary: "Private subnets",
      exposure: "private",
      applications: ["Admin API"],
      evidence: fromSource,
    });
    expect(res.error).toBe("unknown_application");
    expect(res.message).toContain("console web");
  });
});

describe("document_flow", () => {
  it("connects documented nodes and refuses unknown ones", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentService(ctx), {
      name: "Aurora PostgreSQL",
      kind: "database",
      boundary: "Private subnets",
      exposure: "private",
      applications: ["Console Web"],
      evidence: fromSource,
    });
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
    expect(bad.error).toBe("unknown_node");
  });
});

describe("document_attack_vector", () => {
  const vector = {
    title: "Shared database tenant isolation",
    risk: "Every application reads Aurora; a missing workspace filter in any one exposes other tenants.",
    rationale:
      "All tables key on a workspace FK enforced in application code, not in the database.",
    impact: "Cross-tenant disclosure of findings and stored credentials.",
    pattern: "shared-resource",
    priority: "high",
    evidence: fromSource,
  };

  it("spans an application and a service", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentService(ctx), {
      name: "Aurora PostgreSQL",
      kind: "database",
      boundary: "Private subnets",
      exposure: "private",
      applications: ["Console Web"],
      evidence: fromSource,
    });
    const res = await run(documentAttackVector(ctx), {
      ...vector,
      surfaces: ["Console Web", "aurora postgresql"],
    });
    expect(res.success).toBe(true);
  });

  it("refuses a surface that was never documented", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    const res = await run(documentAttackVector(ctx), {
      ...vector,
      surfaces: ["Console Web", "Redis"],
    });
    expect(res.error).toBe("unknown_surface");
  });

  it("requires at least one surface", () => {
    const schema = documentAttackVector(makeCtx()).inputSchema as {
      safeParse: (v: unknown) => { success: boolean };
    };
    expect(
      schema.safeParse({ ...vector, surfaces: [], toolCallDescription: "x" })
        .success,
    ).toBe(false);
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

  it("attaches to boundaries, applications, and services", async () => {
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

  it("links a vector to a documented control and refuses an unknown one", async () => {
    const ctx = makeCtx();
    await seed(ctx);
    await run(documentControl(ctx), { ...control, appliesTo: ["Console Web"] });
    const vector = {
      title: "Tenant isolation rests on handler checks",
      risk: "One handler that skips the check exposes another tenant.",
      surfaces: ["Console Web"],
      rationale: "Isolation is enforced per handler.",
      impact: "Cross-tenant disclosure.",
      pattern: "missing-control",
      priority: "high",
      evidence: fromSource,
    };
    const linked = await run(documentAttackVector(ctx), {
      ...vector,
      controls: ["workspace authorization"],
    });
    expect(linked.success).toBe(true);
    const unknown = await run(documentAttackVector(ctx), {
      ...vector,
      controls: ["API WAF"],
    });
    expect(unknown.error).toBe("unknown_control");
  });
});
