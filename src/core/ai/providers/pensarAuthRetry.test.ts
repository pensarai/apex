import type { LanguageModelV3CallOptions } from "@ai-sdk/provider";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createPensarModel } from "./pensar";

const options = {
  prompt: [{ role: "user", content: [{ type: "text", text: "test" }] }],
} as unknown as LanguageModelV3CallOptions;

describe("Pensar model authentication", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("refreshes and retries a rejected WorkOS token once", async () => {
    const getToken = vi
      .fn()
      .mockResolvedValueOnce({ token: "rejected-token", type: "workos" })
      .mockResolvedValueOnce({ token: "fresh-token", type: "workos" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("unauthorized", { status: 401 }))
      .mockResolvedValueOnce(
        new Response("", {
          headers: { "Content-Type": "text/event-stream" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const model = createPensarModel("anthropic.claude-test", {
      apiKey: "",
      baseUrl: "https://gateway.example.com",
      getToken,
      signingKey: "signing-key",
      workspaceId: "workspace-1",
    });
    const result = await model.doStream(options);
    const reader = result.stream.getReader();
    while (!(await reader.read()).done) {}
    reader.releaseLock();

    expect(getToken).toHaveBeenNthCalledWith(1, undefined);
    expect(getToken).toHaveBeenNthCalledWith(2, {
      forceRefresh: true,
      rejectedToken: "rejected-token",
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({
      Authorization: "Bearer rejected-token",
      "X-Workspace-Id": "workspace-1",
    });
    expect(fetchMock.mock.calls[1]?.[1]?.headers).toMatchObject({
      Authorization: "Bearer fresh-token",
      "X-Workspace-Id": "workspace-1",
    });
    expect(fetchMock.mock.calls[1]?.[1]?.headers["X-Pensar-Nonce"]).not.toBe(
      fetchMock.mock.calls[0]?.[1]?.headers["X-Pensar-Nonce"],
    );
  });

  it("does not make a third request when the retry is also rejected", async () => {
    const getToken = vi
      .fn()
      .mockResolvedValueOnce({ token: "rejected-token", type: "workos" })
      .mockResolvedValueOnce({ token: "still-rejected", type: "workos" });
    const fetchMock = vi.fn(
      async () => new Response("unauthorized", { status: 401 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const model = createPensarModel("anthropic.claude-test", {
      apiKey: "",
      baseUrl: "https://gateway.example.com",
      getToken,
    });

    await expect(model.doStream(options)).rejects.toThrow(
      "Pensar streaming error (401)",
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(getToken).toHaveBeenCalledTimes(2);
  });
});
