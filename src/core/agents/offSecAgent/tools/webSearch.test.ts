import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
      exaAPIKey: "exa-key",
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
      {
        context: {},
        messages: [],
        toolCallId: "tc_search",
      },
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
      {
        context: {},
        messages: [],
        toolCallId: "tc_search",
      },
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
      {
        context: {},
        messages: [],
        toolCallId: "tc_search",
      },
    )) as WebSearchResponse;

    expect(result).toMatchObject({
      success: false,
      results: [],
      error: expect.stringMatching(/without a fetch capability/),
    });
  });
});

describe("webSearch Exa BYOK", () => {
  beforeEach(() => {
    vi.spyOn(config, "get").mockResolvedValue({
      responsibleUseAccepted: true,
      exaAPIKey: "exa-key",
    });
  });

  async function search(abortSignal?: AbortSignal, ctx = makeCtx()) {
    return (await webSearch(ctx).execute?.(
      {
        query: "security advisory",
        toolCallDescription: "Search for an advisory",
      },
      {
        context: {},
        messages: [],
        toolCallId: "tc_exa",
        abortSignal,
      },
    )) as WebSearchResponse;
  }

  it.each([
    undefined,
    "service-key",
  ])("searches directly with Pensar key %s and returns URL-bound fetch capabilities", async (pensarAPIKey) => {
    vi.mocked(config.get).mockResolvedValue({
      responsibleUseAccepted: true,
      exaAPIKey: "exa-key",
      pensarAPIKey,
    });
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) =>
        Response.json({
          results: [
            {
              title: "Advisory",
              url: "https://research.example/advisory",
              highlights: ["Affected versions", "Patch now"],
            },
          ],
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await search();

    expect(result).toEqual({
      success: true,
      results: [
        {
          title: "Advisory",
          url: "https://research.example/advisory",
          snippet: "Affected versions\nPatch now",
          fetchToken: expect.any(String),
        },
      ],
    });
    const fetchToken = result.results[0].fetchToken;
    expect(
      verifyLocalResearchFetchToken(
        fetchToken,
        "https://research.example/advisory",
      ),
    ).toBe(true);
    expect(
      verifyLocalResearchFetchToken(fetchToken, "https://other.example/"),
    ).toBe(false);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.exa.ai/search");
    const request = fetchMock.mock.calls[0][1];
    expect(request).toMatchObject({
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "exa-key",
      },
      signal: expect.any(AbortSignal),
    });
    expect(JSON.parse(request?.body as string)).toEqual({
      query: "security advisory",
      type: "auto",
      numResults: 10,
      contents: { highlights: { maxCharacters: 2000 } },
    });
  });

  it("drops invalid research URLs and tolerates missing optional metadata", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          results: [
            { url: "file:///etc/passwd" },
            { url: "not a URL" },
            { url: "https://research.example/", title: null, highlights: null },
          ],
        }),
      ),
    );

    const result = await search();

    expect(result).toEqual({
      success: true,
      results: [
        {
          url: "https://research.example/",
          title: "",
          snippet: "",
          fetchToken: expect.any(String),
        },
      ],
    });
  });

  it("accepts an empty search result without switching providers", async () => {
    const fetchMock = vi.fn(async () => Response.json({ results: [] }));
    vi.stubGlobal("fetch", fetchMock);

    expect(await search()).toEqual({ success: true, results: [] });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    [401, "authentication failed"],
    [402, "credits or spending budget exhausted"],
    [403, "access denied"],
    [429, "rate limit exceeded"],
    [500, "Exa search failed: 500"],
  ])("reports HTTP %i without exposing the body or switching providers", async (status, message) => {
    const fetchMock = vi.fn(
      async () => new Response("private upstream body: exa-key", { status }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await search();

    expect(result).toMatchObject({
      success: false,
      results: [],
      error: expect.stringContaining(message),
    });
    expect(result.error).not.toContain("exa-key");
    expect(result.error).not.toContain("private upstream body");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    {},
    { results: null },
    { results: [{ url: 123 }] },
  ])("rejects a malformed Exa response: %j", async (body) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json(body)),
    );

    expect(await search()).toEqual({
      success: false,
      results: [],
      error: "Exa search returned an invalid response.",
    });
  });

  it("rejects a non-JSON Exa response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("not JSON")),
    );

    expect(await search()).toMatchObject({
      success: false,
      results: [],
      error: "Exa search returned an invalid response.",
    });
  });

  it.each([
    "tool",
    "agent",
  ])("honors cancellation from the %s signal", async (source) => {
    const controller = new AbortController();
    const fetchMock = vi.fn(async (_input: unknown, init?: RequestInit) => {
      controller.abort(new Error("search cancelled"));
      expect(init?.signal?.aborted).toBe(true);
      throw init?.signal?.reason;
    });
    vi.stubGlobal("fetch", fetchMock);
    const ctx = makeCtx();
    if (source === "agent") ctx.abortSignal = controller.signal;

    const result = await search(
      source === "tool" ? controller.signal : undefined,
      ctx,
    );

    expect(result).toMatchObject({
      success: false,
      results: [],
      error: expect.stringContaining("search cancelled"),
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
