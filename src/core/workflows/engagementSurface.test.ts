import { describe, expect, it, vi } from "vitest";
import {
  createEngagementSurfaceTools,
  EngagementContext,
  type EngagementSurfaceProvider,
} from "./engagementSurface";

const options = { toolCallId: "call-1", messages: [], abortSignal: undefined };

function context(provider: EngagementSurfaceProvider, ids = ["target-1"]) {
  return new EngagementContext({ provider, targetIds: ids });
}

describe("engagement surface tools", () => {
  it("forwards bounded search filters to the host provider", async () => {
    const provider: EngagementSurfaceProvider = {
      search: vi.fn().mockResolvedValue({ targets: [], total: 0 }),
      getTarget: vi.fn(),
    };
    const tools = createEngagementSurfaceTools(context(provider));

    await tools.search_engagement_surface?.execute?.(
      {
        query: "admin",
        applicationId: "app-1",
        limit: 25,
        offset: 0,
        toolCallDescription: "Search scoped targets",
      },
      options,
    );

    expect(provider.search).toHaveBeenCalledWith({
      query: "admin",
      applicationId: "app-1",
      limit: 25,
      offset: 0,
    });
  });

  it("returns an explicit miss for an unknown target", async () => {
    const provider: EngagementSurfaceProvider = {
      search: vi.fn(),
      getTarget: vi.fn().mockResolvedValue(null),
    };
    const tools = createEngagementSurfaceTools(
      context(provider, ["outside-scope"]),
    );

    const result = await tools.get_engagement_target?.execute?.(
      { targetId: "outside-scope", toolCallDescription: "Read target" },
      options,
    );

    expect(result).toEqual({
      success: false,
      reason: "unavailable",
      targetId: "outside-scope",
    });
  });

  it("rejects an unauthorized target before consulting the provider", async () => {
    const provider: EngagementSurfaceProvider = {
      search: vi.fn(),
      getTarget: vi.fn(),
    };
    const tools = createEngagementSurfaceTools(context(provider));

    await expect(
      tools.get_engagement_target?.execute?.(
        { targetId: "target-2", toolCallDescription: "Read target" },
        options,
      ),
    ).rejects.toThrow("authorized read scope");
    expect(provider.getTarget).not.toHaveBeenCalled();
  });

  it("bounds target reads, redacts secrets, and records complete versioned receipts", async () => {
    const provider: EngagementSurfaceProvider = {
      search: vi.fn(),
      getTarget: vi.fn().mockResolvedValue({
        id: "target-1",
        applicationId: "app-1",
        applicationName: "Example",
        target: "https://example.test",
        objectives: ["Review access control"],
        businessLogic:
          "Customers may read their own records using secret-token.",
        threatModel: "Cross-tenant access is prohibited.",
        contextSources: {
          businessLogic: "product-documentation",
          threatModel: "generated",
        },
      }),
    };
    const versions: string[] = [];
    const scoped = new EngagementContext({
      provider,
      targetIds: ["target-1"],
      secretValues: ["secret-token"],
      onRead: (receipt) => {
        if (receipt.version) versions.push(receipt.version);
      },
    });

    const first = await scoped.read("target-1", 0, 40);
    expect(first.success).toBe(true);
    if (!first.success) throw new Error("Expected context");
    let content = first.contextJson;
    let next = first.nextOffset;
    while (next !== null) {
      const page = await scoped.read("target-1", next, 40);
      if (!page.success) throw new Error("Expected context page");
      content += page.contextJson;
      next = page.nextOffset;
    }

    expect(content).toContain("[REDACTED]");
    expect(content).not.toContain("secret-token");
    expect(new Set(versions).size).toBe(1);
    expect(scoped.receipts()).toEqual([
      expect.objectContaining({
        targetId: "target-1",
        status: "read",
        complete: true,
        hasProductContext: true,
      }),
    ]);
    expect(() => scoped.scope(["target-2"])).toThrow("authorized read scope");
  });
});
