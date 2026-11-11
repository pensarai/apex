import { describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import type {
  CallbackBackend,
  CallbackHit,
  ToolBackends,
} from "../../../tools/backends/types";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { readCallbackHits } from "./callbackHits";
import { listToolRegistryNames } from "./index";
import type { ToolContext } from "./types";

const CB = "3f2b8c1e.cb.example.net";
const options = {
  context: {},
  toolCallId: "tc_1",
  messages: [],
};

type Result = {
  success: boolean;
  summary: string;
  data?: {
    matchingHits: number;
    totalHits: number;
    recentHits: Array<Record<string, unknown>>;
  };
  truncated?: boolean;
};

const session = {
  id: "ses_cb",
  rootPath: "/nonexistent",
  targets: ["https://target.example"],
  config: {},
} as unknown as SessionInfo;

function backend(
  readHits: CallbackBackend["readHits"],
  domains: string[] = [CB],
): CallbackBackend {
  return { domains, readHits };
}

function ctx(callbacks?: CallbackBackend): ToolContext {
  return {
    ...(callbacks ? { backends: { callbacks } as ToolBackends } : {}),
    subagentSpawner: inProcessSubagentSpawner,
    session,
    agentCwd: "/nonexistent",
  };
}

const LISTENER_TOOLS = [
  "start_callback_listener",
  "poll_callback_listener",
  "stop_callback_listener",
];

function hit(n: number, path = `/ssrf-${n}`): CallbackHit {
  return {
    id: `hit-${n}`,
    receivedAt: "2026-11-05T12:00:00.000Z",
    method: "GET",
    path,
    headers: { "user-agent": "Java/17" },
    sourceIp: "203.0.113.7",
    bodyPreview: "",
    bodyTruncated: false,
    late: false,
  };
}

function read(
  callbacks: CallbackBackend,
  input: { marker?: string } = {},
): Promise<Result> {
  return readCallbackHits(ctx(callbacks)).execute?.(
    { toolCallDescription: "read", ...input },
    options,
  ) as unknown as Promise<Result>;
}

const noHits = backend(async () => ({ hits: [], totalHits: 0 }));

describe("read_callback_hits", () => {
  it("replaces the local listener tools when the host supplies callback domains", () => {
    const withDomains = listToolRegistryNames(ctx(noHits));
    expect(withDomains).toContain("read_callback_hits");
    for (const name of LISTENER_TOOLS) expect(withDomains).not.toContain(name);

    for (const without of [ctx(), ctx(backend(noHits.readHits, []))]) {
      const names = listToolRegistryNames(without);
      expect(names).not.toContain("read_callback_hits");
      for (const name of LISTENER_TOOLS) expect(names).toContain(name);
    }
  });

  it("lists the callback domains in the tool description", () => {
    expect(readCallbackHits(ctx(noHits)).description).toContain(CB);
  });

  it.each([
    ["a URL", "https://cb.example.net"],
    ["a port", "cb.example.net:8443"],
    ["a path", "cb.example.net/x"],
    ["a wildcard", "*.cb.example.net"],
    ["an IP address", "203.0.113.7"],
    ["a target host", "target.example"],
  ])("refuses %s as a callback domain", (_case, domain) => {
    expect(() =>
      listToolRegistryNames(ctx(backend(noHits.readHits, [domain]))),
    ).toThrow();
  });

  it("checks a shared backend's domains against every caller's own target", () => {
    const shared = backend(noHits.readHits, ["api.target.example"]);
    expect(listToolRegistryNames(ctx(shared))).toContain("read_callback_hits");
    expect(() =>
      listToolRegistryNames({
        ...ctx(shared),
        target: "https://api.target.example",
      }),
    ).toThrow();
  });

  it("reads through local backends when the host passes callbacks without injecting backends", async () => {
    const local: ToolContext = {
      subagentSpawner: inProcessSubagentSpawner,
      callbacks: backend(async () => ({
        hits: [hit(1, "/ssrf-local")],
        totalHits: 1,
      })),
      session,
      agentCwd: "/nonexistent",
    };
    expect(listToolRegistryNames(local)).toContain("read_callback_hits");
    const result = (await readCallbackHits(local).execute?.(
      { toolCallDescription: "read", marker: "ssrf-local" },
      options,
    )) as unknown as Result;
    expect(result.data?.matchingHits).toBe(1);
  });

  it("reads only the injected backends when the host injects them, as the inbox does", () => {
    const both: ToolContext = {
      ...ctx(),
      backends: {} as ToolBackends,
      callbacks: noHits,
    };
    expect(listToolRegistryNames(both)).not.toContain("read_callback_hits");
  });

  it("bounds an attacker-controlled user agent", async () => {
    const big = hit(1);
    big.headers = { "user-agent": "A".repeat(10_000) };
    const result = await read(
      backend(async () => ({ hits: [big], totalHits: 1 })),
    );
    const ua = result.data?.recentHits[0]?.userAgent as string;
    expect(ua.length).toBeLessThanOrEqual(256);
  });

  it("reads the user agent whatever the header's casing", async () => {
    const cased = hit(1);
    cased.headers = { "User-Agent": "Hookline-Delivery/1.0" };
    const result = await read(
      backend(async () => ({ hits: [cased], totalHits: 1 })),
    );
    expect(result.data?.recentHits[0]?.userAgent).toBe("Hookline-Delivery/1.0");
  });

  it("filters hits by the marker the payload carried", async () => {
    const reader = backend(
      vi.fn().mockResolvedValue({
        hits: [
          hit(1, "/ssrf-avatar-1"),
          hit(2, "/xxe-import?m=7"),
          hit(3, "/ssrf-avatar-1?retry"),
        ],
        totalHits: 3,
      }),
    );
    const result = await read(reader, { marker: "ssrf-avatar-1" });
    expect(result.success).toBe(true);
    expect(result.data?.matchingHits).toBe(2);
    expect(result.data?.recentHits.map((h) => h.hitId)).toEqual([
      "hit-1",
      "hit-3",
    ]);
    expect((await read(reader)).data?.matchingHits).toBe(3);
  });

  it("returns only the most recent hits and bounds attacker-controlled paths", async () => {
    const hits = Array.from({ length: 30 }, (_, i) => hit(i + 1));
    hits[29] = hit(30, `/${"a".repeat(5000)}`);
    const result = await read(backend(async () => ({ hits, totalHits: 40 })));
    expect(result.data?.recentHits).toHaveLength(25);
    expect(result.data?.recentHits[0]?.hitId).toBe("hit-6");
    expect(String(result.data?.recentHits[24]?.path)).toHaveLength(512);
    expect(result.truncated).toBe(true);
    expect(result.summary).toContain(
      "10 more were received past the storage cap",
    );
  });

  it.each([
    [
      "the service is unavailable",
      backend(async () => ({
        state: "unavailable" as const,
        reason: "store_error",
      })),
    ],
    ["the read throws", backend(async () => Promise.reject(new Error("boom")))],
  ])("fails without implying absence when %s", async (_case, reader) => {
    const result = await read(reader);
    expect(result.success).toBe(false);
    expect(result.summary).toContain(
      "says nothing about whether the target called back",
    );
    expect(result.data).toBeUndefined();
  });
});
