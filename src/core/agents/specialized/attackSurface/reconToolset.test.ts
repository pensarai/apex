import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../../offSecAgent/subagentSpawner";
import { listToolRegistryNames } from "../../offSecAgent/tools";
import type { ToolContext } from "../../offSecAgent/tools/types";
import { reconWorkerDefinition } from "../reconWorker/agent";
import { generalizedAttackSurfaceDefinition } from "./generalizedAgent";
import { buildGeneralizedAttackSurfacePrompt } from "./generalizedPrompts";
import {
  GENERALIZED_ATTACK_SURFACE_TOOLS,
  RECON_WORKER_TOOLS,
} from "./reconToolset";

describe("recon toolsets", () => {
  it("shares the primitive toolset between orchestrator and worker", () => {
    for (const t of RECON_WORKER_TOOLS) {
      expect(GENERALIZED_ATTACK_SURFACE_TOOLS).toContain(t);
    }
    for (const t of [
      "execute_command",
      "http_request",
      "grep",
      "read_file",
      "web_search",
      "clone_repository",
      "document_app",
    ]) {
      expect(RECON_WORKER_TOOLS).toContain(t);
    }
  });

  it("gives spawn + finalize only to the orchestrator", () => {
    expect(GENERALIZED_ATTACK_SURFACE_TOOLS).toContain("spawn_recon_agent");
    expect(GENERALIZED_ATTACK_SURFACE_TOOLS).toContain(
      "create_attack_surface_report",
    );
    expect(RECON_WORKER_TOOLS).not.toContain("spawn_recon_agent");
    expect(RECON_WORKER_TOOLS).not.toContain("create_attack_surface_report");
  });

  it("does not enumerate endpoints (no document_endpoint)", () => {
    expect(GENERALIZED_ATTACK_SURFACE_TOOLS).not.toContain("document_endpoint");
    expect(RECON_WORKER_TOOLS).not.toContain("document_endpoint");
  });

  it("registers the new tools in the canonical registry", () => {
    const ctx = {
      subagentSpawner: inProcessSubagentSpawner,
      session: { id: "s", rootPath: "/tmp" } as SessionInfo,
      agentCwd: "/tmp",
    } as ToolContext;
    const names = listToolRegistryNames(ctx);
    expect(names).toContain("clone_repository");
    expect(names).toContain("spawn_recon_agent");
  });
});

describe("generalized attack-surface agent definition", () => {
  it("is an origin-driven orchestrator with the shared toolset", () => {
    expect(generalizedAttackSurfaceDefinition.name).toBe(
      "generalized-attack-surface",
    );
    expect(generalizedAttackSurfaceDefinition.role).toBe("orchestrator");
    const tools = generalizedAttackSurfaceDefinition.activeTools(
      {} as never,
      {} as never,
    );
    expect(tools).toEqual(GENERALIZED_ATTACK_SURFACE_TOOLS);
  });

  it("drops excluded tools (host without durable clone/fan-out)", () => {
    const tools = generalizedAttackSurfaceDefinition.activeTools(
      { excludeTools: ["spawn_recon_agent", "clone_repository"] } as never,
      {} as never,
    );
    expect(tools).not.toContain("spawn_recon_agent");
    expect(tools).not.toContain("clone_repository");
    expect(tools).toContain("document_app");
    expect(tools).toContain("execute_command");
  });

  it("builds a prompt that names the origin and connected repos", () => {
    const prompt = buildGeneralizedAttackSurfacePrompt(
      "https://app.example.com",
      [{ name: "acme-api", url: "https://github.com/acme/acme-api.git" }],
      undefined,
    );
    expect(prompt).toContain("https://app.example.com");
    expect(prompt).toContain("acme-api");
  });
});

describe("recon worker definition", () => {
  it("is a worker that cannot spawn or finalize", () => {
    const def = reconWorkerDefinition();
    expect(def.role).toBe("worker");
    const tools = def.activeTools({ goal: "g" } as never, undefined as never);
    expect(tools).toEqual(RECON_WORKER_TOOLS);
    expect(tools).not.toContain("spawn_recon_agent");
  });

  it("honors excludeTools", () => {
    const def = reconWorkerDefinition();
    const tools = def.activeTools(
      { goal: "g", excludeTools: ["browser_navigate"] } as never,
      undefined as never,
    );
    expect(tools).not.toContain("browser_navigate");
    expect(tools).toContain("grep");
  });
});
