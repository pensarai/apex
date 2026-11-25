import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ResearchContext } from "./researchContext";

const roots: string[] = [];
async function root() {
  const path = await mkdtemp(join(tmpdir(), "apex-research-context-"));
  roots.push(path);
  return path;
}
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});
const defaults = {
  model: "gpt-6.1-sol",
  prompt: "Investigate the parser",
  reasoning: "low" as const,
};

describe("research session context", () => {
  it("preserves queued input through concurrent checkpoints and a restart", async () => {
    const path = await root();
    const context = new ResearchContext(path, defaults);
    await context.checkpoint(context.prepare("Research instructions"));
    const messages: ModelMessage[] = [
      ...context.latest(),
      { role: "assistant", content: "Current result" },
    ];
    await Promise.all([
      context.queueInput({ id: "input-1", text: "Follow the boundary hint" }),
      context.checkpoint({ messages }),
    ]);
    const resumed = new ResearchContext(path, {
      ...defaults,
      newMessages: [{ role: "user", content: "Then verify it" }],
    });
    expect(resumed.latest()).toEqual([
      ...messages,
      { role: "user", content: "Follow the boundary hint" },
      { role: "user", content: "Then verify it" },
    ]);
    await resumed.checkpoint({ messages: resumed.latest() });
    expect(
      new ResearchContext(path, { ...defaults, newMessages: [] }).latest(),
    ).toEqual(resumed.latest());
  });

  it("rejects input when its durable write fails and prevents later dispatch", async () => {
    const path = await root();
    const context = new ResearchContext(path, defaults);
    await context.checkpoint(context.prepare("Research instructions"));
    await mkdir(join(path, "research-context.json.tmp"));
    await expect(
      context.queueInput({ id: "unsaved", text: "Do not acknowledge this" }),
    ).rejects.toThrow();
    await expect(context.takeInputs(context.latest())).rejects.toThrow();
    await expect(context.flush()).rejects.toThrow();
    const saved = JSON.parse(
      await readFile(join(path, "research-context.json"), "utf8"),
    );
    expect(saved.pendingInputs).toEqual([]);
  });

  it("appends only changed instruction lines and keeps the consumed prefix across restarts", async () => {
    const path = await root();
    const catalog = "skills and tools\n".repeat(500);
    const original = `Research\napproval=required\n${catalog}`;
    const updated = `Research\napproval=automatic\n${catalog}`;
    const first = new ResearchContext(path, defaults);
    await first.checkpoint(first.prepare(original));
    const resumed = new ResearchContext(path, { ...defaults, newMessages: [] });
    const prepared = resumed.prepare(updated);
    expect(prepared.system).toBe(original);
    expect(prepared.messages.slice(0, first.latest().length)).toEqual(
      first.latest(),
    );
    const update = prepared.messages.at(-1)?.content;
    expect(update).toContain("approval=required");
    expect(update).toContain("approval=automatic");
    expect(update).not.toContain("skills and tools");
    await resumed.checkpoint(prepared);
    const next = new ResearchContext(path, { ...defaults, newMessages: [] });
    expect(next.prepare(updated).messages).toEqual(prepared.messages);
    expect(
      next.prepare(`Research\n${catalog}`).messages.at(-1)?.content,
    ).toContain("approval=automatic");
  });

  it("preserves consumed results and reasoning while appending a user correction after restart", async () => {
    const path = await root();
    const first = new ResearchContext(path, defaults);
    const prepared = first.prepare("Research instructions");
    const response: ModelMessage = {
      role: "assistant",
      content: [
        {
          type: "reasoning",
          text: "hypothesis",
          providerOptions: {
            openai: { itemId: "reason", reasoningEncryptedContent: "opaque" },
          },
        },
        {
          type: "tool-call",
          toolName: "read_file",
          toolCallId: "read",
          input: { path: "parser.c" },
        },
      ],
    };
    const result: ModelMessage = {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolName: "read_file",
          toolCallId: "read",
          output: { type: "text", value: "evidence".repeat(20000) },
        },
      ],
    };
    const history = [...prepared.messages, response, result];
    await first.checkpoint({ messages: history });
    const second = new ResearchContext(path, {
      ...defaults,
      newMessages: [
        {
          role: "user",
          content: "Follow the overflow hint in the length calculation",
        },
      ],
    });
    expect(second.latest().slice(0, history.length)).toEqual(history);
    expect(second.latest().at(-1)?.content).toContain("overflow hint");
    const journal = (
      await readFile(join(path, "research-context.jsonl"), "utf8")
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(journal[0].messages).toEqual(history);
  });

  it("keeps the request prefix stable when instructions and reasoning change", async () => {
    const path = await root();
    const first = new ResearchContext(path, defaults);
    await first.checkpoint(first.prepare("Initial instructions"));
    const second = new ResearchContext(path, {
      ...defaults,
      reasoning: "high",
      newMessages: [{ role: "user", content: "Go deeper" }],
    });
    const next = second.prepare("Updated workspace instructions");
    expect(next.system).toBe("Initial instructions");
    expect(next.reasoning).toBe("low");
    expect(next.messages).toContainEqual({
      role: "system",
      content: "",
      providerOptions: { openai: { reasoningEffortUpdate: "high" } },
    });
    expect(next.messages.at(-1)?.content).toContain(
      "Updated workspace instructions",
    );
  });

  it("rehydrates evidence across a model switch after opaque compaction", async () => {
    const path = await root();
    const first = new ResearchContext(path, defaults);
    const original = first.prepare("instructions");
    await first.checkpoint({
      messages: [
        ...original.messages,
        { role: "assistant", content: "Evidence in scratchpad/repro.py" },
      ],
    });
    const opaque: ModelMessage = {
      role: "assistant",
      content: [
        {
          type: "custom",
          kind: "openai.compaction",
          providerOptions: {
            openai: { itemId: "cmp", encryptedContent: "opaque" },
          },
        },
      ],
    };
    await first.checkpoint({ messages: [...first.latest(), opaque] });
    await first.checkpoint({ messages: [opaque] });
    const second = new ResearchContext(path, {
      ...defaults,
      model: "claude-opus-5-5",
      newMessages: [{ role: "user", content: "Inspect the reproducer" }],
    });
    expect(second.latest()).toEqual([
      ...original.messages,
      { role: "assistant", content: "Evidence in scratchpad/repro.py" },
      { role: "user", content: "Inspect the reproducer" },
    ]);
    await second.checkpoint(second.prepare("instructions"));
    const third = new ResearchContext(path, {
      ...defaults,
      newMessages: [{ role: "user", content: "Patch it" }],
    });
    expect(third.latest()).toEqual([
      ...second.latest(),
      { role: "user", content: "Patch it" },
    ]);
  });

  it("rejects callers that rewrite consumed history", async () => {
    const path = await root();
    const first = new ResearchContext(path, defaults);
    await first.checkpoint(first.prepare("instructions"));
    expect(
      () =>
        new ResearchContext(path, {
          ...defaults,
          messages: [{ role: "user", content: "rewritten" }],
        }),
    ).toThrow("Pass newMessages");
  });

  it("journals a fresh correction before the first prepared window compacts it", async () => {
    const path = await root();
    const first = new ResearchContext(path, defaults);
    await first.checkpoint(first.prepare("instructions"));
    const correction: ModelMessage = {
      role: "user",
      content: "Follow the parser hint instead of enumerating routes",
    };
    const resumed = new ResearchContext(path, {
      ...defaults,
      newMessages: [correction],
    });
    resumed.prepare("instructions");
    await resumed.checkpoint({
      messages: [{ role: "user", content: "Compacted representation" }],
    });
    const switched = new ResearchContext(path, {
      ...defaults,
      model: "claude-opus-5-5",
      newMessages: [],
    });
    expect(switched.latest()).toEqual([...first.latest(), correction]);
  });

  it("keeps pre-compaction evidence in the journal", async () => {
    const path = await root();
    const session = new ResearchContext(path, defaults);
    const before = session.prepare("instructions");
    await session.checkpoint(before);
    const compacted: ModelMessage[] = [
      { role: "user", content: "Summary with evidence references" },
    ];
    await session.checkpoint({ messages: compacted });
    const events = (
      await readFile(join(path, "research-context.jsonl"), "utf8")
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(events[0].messages).toEqual(before.messages);
    expect(events[1]).toMatchObject({ kind: "replace", messages: compacted });
    expect(
      new ResearchContext(path, { ...defaults, newMessages: [] }).latest(),
    ).toEqual(compacted);
  });

  it("does not hide a host recorder failure or advance its context", async () => {
    const path = await root();
    const session = new ResearchContext(path, {
      ...defaults,
      recorder: {
        checkpoint: vi.fn().mockRejectedValue(new Error("disk unavailable")),
        flush: vi.fn(),
        latest: () => undefined,
      },
    });
    await expect(
      session.checkpoint(session.prepare("instructions")),
    ).rejects.toThrow();
    await expect(session.flush()).rejects.toThrow();
    await expect(
      readFile(join(path, "research-context.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
