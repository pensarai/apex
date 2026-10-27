import { afterEach, describe, expect, it, vi } from "vitest";
import { config } from "../../../config";
import { verifyLocalResearchFetchToken } from "../../../http/researchFetchToken";
import type { ToolContext } from "./types";
import { type WebSearchResponse, webSearch } from "./webSearch";

function makeCtx(): ToolContext {
  return {
    agentCwd: "/tmp",
    session: { id: "ses_test", rootPath: "/tmp" },
  } as ToolContext;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env.PENSAR_API_URL;
});

describe("webSearch broker capabilities", () => {
  it("preserves direct Brave mode with a URL-bound local fetch capability", async () => {
    vi.spyOn(config, "get").mockResolvedValue({
      responsibleUseAccepted: true,
      strikeMode: false,
      pensarAPIKey: "service-key",
      braveAPIKey: "brave-key",
    });
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            web: {
              results: [
                {
                  title: "Advisory",
                  url: "https://research.example/advisory",
                  description: "Patch now",
                },
              ],
            },
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = (await webSearch(makeCtx()).execute?.(
      {
        query: "security advisory",
        toolCallDescription: "Search for an advisory",
      },
      { messages: [], toolCallId: "tc_search" },
    )) as WebSearchResponse;

    expect(result.success).toBe(true);
    expect(result.results).toHaveLength(1);
    expect(
      verifyLocalResearchFetchToken(
        result.results[0]?.fetchToken ?? "",
        "https://research.example/advisory",
      ),
    ).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[0]).toContain(
      "https://api.search.brave.com/",
    );
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      headers: {
        "X-Subscription-Token": "brave-key",
      },
    });
  });

  it("does not mint a capability for a malformed Brave result URL", async () => {
    vi.spyOn(config, "get").mockResolvedValue({
      responsibleUseAccepted: true,
      strikeMode: false,
      braveAPIKey: "brave-key",
    });
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            web: {
              results: [
                {
                  title: "Malformed",
                  url: "file:///etc/passwd",
                  description: "ignored",
                },
              ],
            },
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = (await webSearch(makeCtx()).execute?.(
      {
        query: "security advisory",
        toolCallDescription: "Search for an advisory",
      },
      { messages: [], toolCallId: "tc_search" },
    )) as WebSearchResponse;

    expect(result).toMatchObject({
      success: true,
      results: [],
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rejects a broker response that omits fetch capabilities", async () => {
    process.env.PENSAR_API_URL = "https://api.pensar.test";
    vi.spyOn(config, "get").mockResolvedValue({
      responsibleUseAccepted: true,
      strikeMode: false,
      pensarAPIKey: "service-key",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              results: [
                {
                  title: "Advisory",
                  url: "https://research.example/advisory",
                  snippet: "Patch now",
                },
              ],
            }),
            { status: 200 },
          ),
      ),
    );

    const result = (await webSearch(makeCtx()).execute?.(
      {
        query: "security advisory",
        toolCallDescription: "Search for an advisory",
      },
      { messages: [], toolCallId: "tc_search" },
    )) as WebSearchResponse;

    expect(result).toMatchObject({
      success: false,
      results: [],
      error: expect.stringMatching(/without a fetch capability/),
    });
  });
});
