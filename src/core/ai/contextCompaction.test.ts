import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModel, ModelMessage } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";

const { generateTextMock } = vi.hoisted(() => ({ generateTextMock: vi.fn() }));
vi.mock("ai", async (importOriginal) => {
  const actual = await importOriginal<typeof import("ai")>();
  return { ...actual, generateText: generateTextMock };
});

import {
  compactConversation,
  groupCompleteTurns,
  partitionForCompaction,
  validateLatestCompactionArchive,
} from "./contextCompaction";

const roots: string[] = [];

afterEach(() => {
  generateTextMock.mockReset();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function assistantToolTurn(id: string, output: string): ModelMessage[] {
  return [
    {
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolCallId: id,
          toolName: "http_request",
          input: {},
        },
      ],
    } as ModelMessage,
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: id,
          toolName: "http_request",
          output: { type: "text", value: output },
        },
      ],
    } as ModelMessage,
  ];
}

describe("context compaction", () => {
  it("never separates an assistant tool call from its tool result", () => {
    const messages: ModelMessage[] = [
      { role: "user", content: "test the target" },
      ...assistantToolTurn("a", "A".repeat(400)),
      ...assistantToolTurn("b", "B".repeat(400)),
    ];

    const groups = groupCompleteTurns(messages);
    expect(groups.map((group) => group.messages.length)).toEqual([1, 2, 2]);

    const partition = partitionForCompaction(messages, 1_000);
    expect(partition.archived.at(-1)?.role).not.toBe("assistant");
    expect(partition.tail[0]?.role).toBe("assistant");
    expect(partition.tail[1]?.role).toBe("tool");
  });

  it("archives raw messages before returning a redacted continuation capsule", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-compaction-"));
    roots.push(root);
    generateTextMock.mockResolvedValue({
      text: JSON.stringify({
        currentPhase: "exploitation",
        confirmedFacts: ["POST /proxy is reachable"],
        authState: [],
        successfulActions: ["Reached Jenkins"],
        exploitChainDependencies: ["proxy -> Jenkins"],
        failedHypotheses: [],
        openLeads: ["query Vault"],
        blockers: [],
        nextActions: ["sign Vault request"],
        artifacts: ["pocs/proxy.ts"],
      }),
      usage: { inputTokens: 100, outputTokens: 40 },
    });
    const secret = "super-secret-token";
    const messages: ModelMessage[] = [
      { role: "user", content: `target with ${secret}` },
      ...assistantToolTurn("a", `response ${secret} ${"A".repeat(1_000)}`),
      ...assistantToolTurn("b", "recent result"),
    ];

    const result = await compactConversation({
      messages,
      contextWindow: 1_000,
      model: {} as LanguageModel,
      modelId: "bedrock/claude-haiku-4-5",
      sessionPath: root,
      secretValues: [secret],
      state: {
        objective: `continue without exposing ${secret}`,
        confirmedFindings: [{ title: "SSRF", token: secret }],
      },
    });

    expect(result).not.toBeNull();
    expect(result?.messages[0]?.role).toBe("user");
    expect(JSON.stringify(result?.capsule)).not.toContain(secret);
    expect(result?.capsule.deterministic.confirmedFindings).toEqual([
      { title: "SSRF", token: "[REDACTED]" },
    ]);
    expect(result?.metadata.semanticModelSucceeded).toBe(true);
    expect(validateLatestCompactionArchive(root)).toBe(true);

    const archived = readFileSync(
      join(root, "compactions", "000001", "messages.json"),
      "utf8",
    );
    expect(archived).toContain(secret);
  });

  it("falls back to deterministic state and detects archive tampering", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-compaction-"));
    roots.push(root);
    generateTextMock.mockRejectedValue(new Error("provider unavailable"));
    const messages: ModelMessage[] = [
      { role: "user", content: "objective" },
      ...assistantToolTurn("a", "A".repeat(1_000)),
      ...assistantToolTurn("b", "recent"),
    ];

    const result = await compactConversation({
      messages,
      contextWindow: 1_000,
      model: {} as LanguageModel,
      modelId: "unavailable-model",
      sessionPath: root,
      state: {
        objective: "keep testing",
        tasks: [{ id: 1, status: "pending" }],
      },
    });

    expect(result?.metadata.semanticModelSucceeded).toBe(false);
    expect(result?.capsule.deterministic.objective).toBe("keep testing");
    expect(validateLatestCompactionArchive(root)).toBe(true);

    writeFileSync(
      join(root, "compactions", "000001", "messages.json"),
      "tampered",
    );
    expect(validateLatestCompactionArchive(root)).toBe(false);
  });
});
