import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, expect, it } from "vitest";
import { grep } from "../agents/offSecAgent/tools/grep";
import { resolveToolOutput } from "../agents/offSecAgent/tools/toolOutput";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import { createToolResultPresenter } from "./toolResultPresentation";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

it("budgets new result batches, retains evidence, and never reprojects consumed results", async () => {
  const root = await mkdtemp(join(tmpdir(), "apex-presenter-"));
  roots.push(root);
  const old: ModelMessage = {
    role: "tool",
    content: [
      {
        type: "tool-result",
        toolCallId: "old",
        toolName: "read_file",
        output: { type: "text", value: "old evidence".repeat(10000) },
      },
    ],
  };
  const reasoning: ModelMessage = {
    role: "assistant",
    content: [
      {
        type: "reasoning",
        text: "",
        providerOptions: { openai: { reasoningEncryptedContent: "opaque" } },
      },
    ],
  };
  const fresh: ModelMessage = {
    role: "tool",
    content: Array.from({ length: 12 }, (_, i) => ({
      type: "tool-result",
      toolName: "read_file",
      toolCallId: `read-${i}`,
      output: {
        type: "json",
        value: {
          success: true,
          content: `${"first\n".repeat(800)}LEAD_${i}\n${"last\n".repeat(800)}`,
        },
      },
    })),
  };
  const raw = [old, reasoning, fresh];
  const project = createToolResultPresenter([old], root);
  const first = project(raw);
  expect(first[0]).toEqual(old);
  expect(first[1]).toBe(reasoning);
  const batch = first[2];
  assert(batch.role === "tool");
  let bytes = 0;
  for (const [i, result] of batch.content.entries()) {
    assert(result.type === "tool-result" && result.output.type === "text");
    bytes += Buffer.byteLength(result.output.value);
    const reference = result.output.value.match(
      /tool-output:[0-9a-f-]{36}/,
    )?.[0];
    assert(reference);
    const path = await resolveToolOutput(
      { session: { logsPath: join(root, "logs") } } as ToolContext,
      reference,
    );
    assert(path);
    expect(await readFile(path, "utf8")).toContain(`LEAD_${i}`);
    if (i === 0) {
      const search = await grep({
        mode: "default-v2",
        agentCwd: root,
        session: { rootPath: root, logsPath: join(root, "logs") },
      } as ToolContext).execute?.(
        {
          directory: reference,
          pattern: "LEAD_0",
          flags: "-n",
          toolCallDescription: "Inspect retained evidence",
        },
        { toolCallId: "retrieve", context: {}, messages: [] },
      );
      expect(search).toMatchObject({ success: true, matchCount: 1 });
      expect(JSON.stringify(search).length).toBeLessThan(500);
    }
  }
  expect(bytes).toBeLessThanOrEqual(32 * 1024);
  expect(project(raw)).toEqual(first);
  expect(createToolResultPresenter(first, root)(first)).toEqual(first);
});
