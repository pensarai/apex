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
const options = { toolCallId: "tc_1", messages: [] };

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

function ctx(testDomains?: string[], callbacks?: CallbackBackend): ToolContext {
  return {
    ...(callbacks ? { backends: { callbacks } as ToolBackends } : {}),
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_cb",
      rootPath: "/nonexistent",
      config: testDomains ? { testDomains } : {},
    } as SessionInfo,
    agentCwd: "/nonexistent",
  };
}

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
  return readCallbackHits(ctx([CB], callbacks)).execute?.(
    { toolCallDescription: "read", ...input },
    options,
  ) as unknown as Promise<Result>;
}

const noHits: CallbackBackend = {
  readHits: async () => ({ hits: [], totalHits: 0 }),
};

describe("read_callback_hits", () => {
  it("exists only when the session has test domains and the host can read them", () => {
    expect(listToolRegistryNames(ctx([CB], noHits))).toContain(
      "read_callback_hits",
    );
    expect(listToolRegistryNames(ctx([CB]))).not.toContain(
      "read_callback_hits",
    );
    expect(listToolRegistryNames(ctx(undefined, noHits))).not.toContain(
      "read_callback_hits",
    );
    expect(listToolRegistryNames(ctx([], noHits))).not.toContain(
      "read_callback_hits",
    );
  });

  it("reads through local backends when the host passes callbacks without injecting backends", async () => {
    const local: ToolContext = {
      subagentSpawner: inProcessSubagentSpawner,
      callbacks: {
        readHits: async () => ({ hits: [hit(1, "/ssrf-local")], totalHits: 1 }),
      },
      session: {
        id: "ses_cb",
        rootPath: "/nonexistent",
        config: { testDomains: [CB] },
      } as SessionInfo,
      agentCwd: "/nonexistent",
    };
    expect(listToolRegistryNames(local)).toContain("read_callback_hits");
    const result = (await readCallbackHits(local).execute?.(
      { toolCallDescription: "read", marker: "ssrf-local" },
      options,
    )) as unknown as Result;
    expect(result.data?.matchingHits).toBe(1);
  });

  it("filters hits by the marker the payload carried", async () => {
    const reader = {
      readHits: vi.fn().mockResolvedValue({
        hits: [
          hit(1, "/ssrf-avatar-1"),
          hit(2, "/xxe-import?m=7"),
          hit(3, "/ssrf-avatar-1?retry"),
        ],
        totalHits: 3,
      }),
    };
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
    const result = await read({
      readHits: async () => ({ hits, totalHits: 40 }),
    });
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
      {
        readHits: async () => ({
          state: "unavailable" as const,
          reason: "store_error",
        }),
      },
    ],
    [
      "the read throws",
      { readHits: async () => Promise.reject(new Error("boom")) },
    ],
  ])("fails without implying absence when %s", async (_case, reader) => {
    const result = await read(reader);
    expect(result.success).toBe(false);
    expect(result.summary).toContain(
      "says nothing about whether the target called back",
    );
    expect(result.data).toBeUndefined();
  });
});
