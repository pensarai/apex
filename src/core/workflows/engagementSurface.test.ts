import { describe, expect, it, vi } from "vitest";
import {
  createEngagementSurfaceTools,
  type EngagementSurfaceProvider,
} from "./engagementSurface";

const options = { toolCallId: "call-1", messages: [], abortSignal: undefined };

describe("engagement surface tools", () => {
  it("forwards bounded search filters to the host provider", async () => {
    const provider: EngagementSurfaceProvider = {
      search: vi.fn().mockResolvedValue({ targets: [], total: 0 }),
      getTarget: vi.fn(),
    };
    const tools = createEngagementSurfaceTools(provider);

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
    const tools = createEngagementSurfaceTools(provider);

    const result = await tools.get_engagement_target?.execute?.(
      { targetId: "outside-scope", toolCallDescription: "Read target" },
      options,
    );

    expect(result).toEqual({
      success: false,
      message: "Unknown engagement target: outside-scope",
    });
  });
});
