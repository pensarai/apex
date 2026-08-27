import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { StaticPromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import { listPromptInjections } from "./listPromptInjections";
import type { ToolContext } from "./types";
import { inProcessSubagentSpawner } from "../subagentSpawner";

const TEST_LIBRARY = new StaticPromptInjectionLibrary([
  {
    id: "pi.encoded.override",
    name: "Encoded Override",
    category: "encoding",
    description: "Safe metadata for an encoding test.",
    tags: ["delimiter"],
    deliveryHints: ["json-body"],
    expectedObservation: "The system should treat decoded text as untrusted.",
    payload: "TEST PAYLOAD: encoded override",
  },
  {
    id: "pi.direct.override",
    name: "Direct Override",
    category: "instruction-hijack",
    description: "Safe metadata for a direct override test.",
    tags: ["baseline"],
    deliveryHints: ["chat-message"],
    expectedObservation: "The system should preserve hierarchy.",
    payload: "TEST PAYLOAD: direct override",
  },
]);

type ListPromptInjectionsResult = {
  success: boolean;
  configured: boolean;
  count: number;
  injections: ReturnType<typeof TEST_LIBRARY.listCatalog>;
};

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    ...overrides,
  };
}

describe("listPromptInjections", () => {
  const originalPensarSource = process.env.PENSAR_PROMPT_INJECTION_LIBRARY;
  const originalApexSource = process.env.APEX_PROMPT_INJECTION_LIBRARY;

  afterEach(() => {
    if (originalPensarSource === undefined) {
      delete process.env.PENSAR_PROMPT_INJECTION_LIBRARY;
    } else {
      process.env.PENSAR_PROMPT_INJECTION_LIBRARY = originalPensarSource;
    }
    if (originalApexSource === undefined) {
      delete process.env.APEX_PROMPT_INJECTION_LIBRARY;
    } else {
      process.env.APEX_PROMPT_INJECTION_LIBRARY = originalApexSource;
    }
  });

  it("returns only safe catalog metadata", async () => {
    const tool = listPromptInjections(
      makeCtx({ promptInjectionLibrary: TEST_LIBRARY }),
    );
    const result = (await tool.execute?.(
      { toolCallDescription: "List prompt injection tests" },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ListPromptInjectionsResult;

    expect(result.success).toBe(true);
    expect(result.configured).toBe(true);
    expect(result.count).toBeGreaterThan(0);

    const serialized = JSON.stringify(result);
    for (const entry of TEST_LIBRARY.listCatalog()) {
      const payload = TEST_LIBRARY.getPayload(entry.id)!;
      expect(serialized).toContain(entry.id);
      expect(serialized).not.toContain(payload);
    }
  });

  it("filters by category and tag", async () => {
    const tool = listPromptInjections(
      makeCtx({ promptInjectionLibrary: TEST_LIBRARY }),
    );
    const result = (await tool.execute?.(
      {
        category: "encoding",
        tag: "delimiter",
        toolCallDescription: "List encoding tests",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ListPromptInjectionsResult;

    expect(result.success).toBe(true);
    expect(result.injections).toHaveLength(1);
    expect(result.injections[0].id).toBe("pi.encoded.override");
  });

  it("loads an externally-curated on-disk catalog and lists every payload", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-listpi-"));
    try {
      await mkdir(join(root, "payloads"));
      // Mimic the shape of the private S3 catalog: many entries, no `name`,
      // categories outside Apex's built-in enum.
      const payloads = Array.from({ length: 5 }, (_, i) => ({
        id: `pi.ext.${i}`,
        category: i % 2 === 0 ? "jailbreak" : "obfuscation",
        payloadPath: `payloads/p${i}.txt`,
      }));
      await Promise.all(
        payloads.map((p, i) =>
          writeFile(join(root, "payloads", `p${i}.txt`), `RAW PAYLOAD ${i}`),
        ),
      );
      await writeFile(join(root, "catalog.json"), JSON.stringify({ payloads }));

      const tool = listPromptInjections(
        makeCtx({ promptInjectionLibrarySource: root }),
      );
      const result = (await tool.execute?.(
        { toolCallDescription: "List prompt injection tests" },
        { toolCallId: "tc_test", messages: [], abortSignal: undefined },
      )) as ListPromptInjectionsResult;

      expect(result.success).toBe(true);
      expect(result.configured).toBe(true);
      expect(result.count).toBe(5);
      expect(JSON.stringify(result)).not.toContain("RAW PAYLOAD");

      const filtered = (await tool.execute?.(
        { category: "jailbreak", toolCallDescription: "List jailbreaks" },
        { toolCallId: "tc_test", messages: [], abortSignal: undefined },
      )) as ListPromptInjectionsResult;
      expect(filtered.count).toBe(3);
      expect(filtered.injections.every((e) => e.category === "jailbreak")).toBe(
        true,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("returns an agent-friendly error instead of throwing on a malformed catalog", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-listpi-bad-"));
    try {
      // Entry missing the required payloadPath — schema parsing must fail.
      await writeFile(
        join(root, "catalog.json"),
        JSON.stringify({ payloads: [{ id: "pi.broken" }] }),
      );

      const tool = listPromptInjections(
        makeCtx({ promptInjectionLibrarySource: root }),
      );
      const result = (await tool.execute?.(
        { toolCallDescription: "List prompt injection tests" },
        { toolCallId: "tc_test", messages: [], abortSignal: undefined },
      )) as ListPromptInjectionsResult & { error?: string };

      expect(result.success).toBe(false);
      expect(result.count).toBe(0);
      expect(result.injections).toEqual([]);
      expect(result.error).toContain("Failed to load the prompt-injection");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("returns an empty catalog when no library is configured", async () => {
    delete process.env.PENSAR_PROMPT_INJECTION_LIBRARY;
    delete process.env.APEX_PROMPT_INJECTION_LIBRARY;

    const tool = listPromptInjections(makeCtx());
    const result = (await tool.execute?.(
      { toolCallDescription: "List prompt injection tests" },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ListPromptInjectionsResult;

    expect(result.success).toBe(true);
    expect(result.configured).toBe(false);
    expect(result.count).toBe(0);
    expect(result.injections).toEqual([]);
  });
});
