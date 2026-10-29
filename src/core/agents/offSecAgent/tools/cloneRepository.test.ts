import { describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import type { ToolBackends } from "../../../tools/backends/types";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { cloneRepository } from "./cloneRepository";
import type { ToolContext } from "./types";

type CloneInput = Parameters<
  NonNullable<ReturnType<typeof cloneRepository>["execute"]>
>[0];

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
      config: {
        connectedRepositories: [
          {
            id: "repo_1",
            name: "acme-api",
            url: "https://github.com/acme/acme-api.git",
            defaultBranch: "main",
          },
        ],
      },
    } as unknown as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
    ...overrides,
  };
}

async function runClone(
  ctx: ToolContext,
  input: CloneInput,
): Promise<Record<string, unknown>> {
  return (await cloneRepository(ctx).execute?.(input, {
    toolCallId: "tc_test",
    messages: [],
    abortSignal: ctx.abortSignal,
  })) as Record<string, unknown>;
}

describe("clone_repository", () => {
  it("refuses when the workspace has no connected repositories", async () => {
    const ctx = makeCtx({
      session: { id: "s", rootPath: "/tmp", config: {} } as SessionInfo,
    });
    const res = await runClone(ctx, {
      repository: "anything",
      toolCallDescription: "x",
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("no_connected_repositories");
  });

  it("refuses a repository that is not connected", async () => {
    const ctx = makeCtx();
    const res = await runClone(ctx, {
      repository: "https://github.com/evil/not-ours.git",
      toolCallDescription: "x",
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("repository_not_connected");
  });

  it("reports clone unavailable when no clone backend is present", async () => {
    const ctx = makeCtx();
    const res = await runClone(ctx, {
      repository: "acme-api",
      toolCallDescription: "x",
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("clone_unavailable");
  });

  it("clones a connected repo matched by name, id, or url", async () => {
    const clone = vi
      .fn()
      .mockResolvedValue({ success: true, path: "/ws/repos/acme-api" });
    const ctx = makeCtx({
      backends: { repoClone: { clone } } as unknown as ToolBackends,
    });

    for (const ref of [
      "acme-api",
      "repo_1",
      "https://github.com/acme/acme-api.git",
    ]) {
      const res = await runClone(ctx, {
        repository: ref,
        toolCallDescription: "x",
      });
      expect(res.success).toBe(true);
      expect(res.path).toBe("/ws/repos/acme-api");
    }
    expect(clone).toHaveBeenCalledWith({
      repoUrl: "https://github.com/acme/acme-api.git",
      ref: "main",
      dest: "repos/acme-api",
    });
  });

  it("surfaces a clone backend failure", async () => {
    const clone = vi
      .fn()
      .mockResolvedValue({ success: false, path: "", error: "boom" });
    const ctx = makeCtx({
      backends: { repoClone: { clone } } as unknown as ToolBackends,
    });
    const res = await runClone(ctx, {
      repository: "acme-api",
      ref: "dev",
      toolCallDescription: "x",
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("clone_failed");
    expect(clone).toHaveBeenCalledWith({
      repoUrl: "https://github.com/acme/acme-api.git",
      ref: "dev",
      dest: "repos/acme-api",
    });
  });
});
