import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { documentApp } from "./documentApp";
import {
  documentBoundary,
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
