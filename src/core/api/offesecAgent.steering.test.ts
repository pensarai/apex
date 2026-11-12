import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  LanguageModelV4CallOptions,
  LanguageModelV4StreamPart,
} from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs, tool } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { afterEach, expect, it, vi } from "vitest";
import { z } from "zod";
import type { OffensiveSecurityAgentInput } from "../agents/offSecAgent";
import {
  createOffensiveSecurityAgentClient,
  runOffensiveSecurityAgent,
} from "./offesecAgent";

const observed = vi.hoisted(() => ({
  calls: [] as LanguageModelV4CallOptions[],
  respond: async (_index: number): Promise<LanguageModelV4StreamPart[]> => [],
}));
vi.mock("../ai/utils", async (original) => ({
  ...(await original<typeof import("../ai/utils")>()),
  getProviderModel: () =>
    new MockLanguageModelV4({
      doStream: async (options) => {
        const index = observed.calls.push(options) - 1;
        return {
          stream: simulateReadableStream({
            chunks: await observed.respond(index),
          }),
        };
      },
    }),
}));

function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

const finish = (reason: "stop" | "tool-calls"): LanguageModelV4StreamPart => ({
  type: "finish",
  finishReason: { unified: reason, raw: undefined },
  usage: {
    inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
    outputTokens: { total: 2, text: 2, reasoning: 0 },
  },
});
const answer = (): LanguageModelV4StreamPart[] => [
  { type: "text-start", id: "answer" },
  { type: "text-delta", id: "answer", delta: "Followed the correction." },
  { type: "text-end", id: "answer" },
  finish("stop"),
];
const call = (id: string): LanguageModelV4StreamPart => ({
  type: "tool-call",
  toolCallId: id,
  toolName: "inspect",
  input: JSON.stringify({ id }),
});

let root: string;
async function input(): Promise<
  Omit<OffensiveSecurityAgentInput, "abortSignal">
> {
  root = await mkdtemp(join(tmpdir(), "apex-steering-"));
  return {
    mode: "default-v2",
    model: "gpt-6.1-sol",
    prompt: "Investigate the parser",
    system: "Follow the user's objective",
    activeTools: [],
    stopWhen: stepCountIs(10),
    session: {
      id: "ses_steering",
      version: "1",
      time: { created: 0, updated: 0 },
      rootPath: root,
      logsPath: join(root, "logs"),
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
      targets: [],
    },
  };
}
afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  observed.calls = [];
});

it.each([
  "gpt-6.1-sol",
  "claude-opus-4-6",
])("delivers FIFO input after the entire tool batch, retaining it across later steps (%s)", async (model) => {
  const options = await input();
  const started = [gate(), gate()];
  const release = [gate(), gate()];
  observed.respond = async (index) =>
    index === 0
      ? [call("0"), call("1"), finish("tool-calls")]
      : index === 1
        ? [call("2"), finish("tool-calls")]
        : answer();
  const client = createOffensiveSecurityAgentClient();
  const running = client.run({
    ...options,
    model,
    activeTools: ["inspect"],
    extraTools: {
      inspect: tool({
        inputSchema: z.object({ id: z.string() }),
        execute: async ({ id }) => {
          started[Number(id)]?.resolve();
          await release[Number(id)]?.promise;
          return `evidence ${id}`;
        },
      }),
    },
  });
  await Promise.all(started.map(({ promise }) => promise));
  const first = {
    expectedTurnId: client.turnId,
    inputId: "correction",
    text: "Focus on the length conversion",
  };
  const receipt = await client.steer(first);
  expect(receipt.accepted).toBe(true);
  expect(await client.steer(first)).toEqual(receipt);
  await client.steer({
    expectedTurnId: client.turnId,
    text: "Keep the boundary test",
  });
  const pending = JSON.parse(
    await readFile(join(root, "research-context.json"), "utf8"),
  );
  expect(
    pending.pendingInputs.map((entry: { text: string }) => entry.text),
  ).toEqual([first.text, "Keep the boundary test"]);
  release[0]!.resolve();
  expect(observed.calls).toHaveLength(1);
  release[1]!.resolve();
  const result = await running;
  expect(observed.calls).toHaveLength(3);
  for (const options of observed.calls.slice(1)) {
    const prompt = options.prompt;
    expect(
      prompt
        .filter((message) => message.role === "tool")
        .flatMap((message) => message.content)
        .filter((part) => part.type === "tool-result")
        .map((part) => part.toolCallId)
        .slice(0, 2),
    ).toEqual(["0", "1"]);
    const lastTool = prompt.findIndex((message) => message.role === "tool");
    const correction = prompt.findIndex((message) =>
      JSON.stringify(message.content).includes(first.text),
    );
    expect(correction).toBeGreaterThan(lastTool);
    expect(
      JSON.stringify(prompt).match(/Focus on the length conversion/g),
    ).toHaveLength(1);
    expect(prompt[0]).toMatchObject({
      role: "system",
      content: expect.stringContaining("Follow the user's objective"),
    });
  }
  const messages = result.messages!;
  expect(
    messages
      .filter((message) => message.role === "user")
      .map((message) => message.content),
  ).toEqual([options.prompt, first.text, "Keep the boundary test"]);
  expect(
    messages.findIndex((message) => message.content === first.text),
  ).toBeGreaterThan(messages.findIndex((message) => message.role === "tool"));
  expect(
    await client.steer({ expectedTurnId: "old-turn", text: "wrong" }),
  ).toEqual({ accepted: false, reason: "stale-turn" });
  expect(
    await client.steer({ expectedTurnId: client.turnId, text: "too late" }),
  ).toEqual({ accepted: false, reason: "inactive" });
});

it("continues when input arrives during the final model response", async () => {
  const options = await input();
  const started = gate();
  const release = gate();
  observed.respond = async (index) => {
    if (index === 0) {
      started.resolve();
      await release.promise;
    }
    return answer();
  };
  const client = createOffensiveSecurityAgentClient();
  const running = client.run(options);
  await started.promise;
  await client.steer({
    expectedTurnId: client.turnId,
    text: "Verify the crash too",
  });
  release.resolve();
  const result = await running;
  expect(observed.calls).toHaveLength(2);
  expect(result.messages?.map((message) => message.role)).toEqual([
    "user",
    "assistant",
    "user",
    "assistant",
  ]);
  expect(JSON.stringify(observed.calls[1]?.prompt)).toContain(
    "Verify the crash too",
  );
  expect(await result.streamResult.text).toBe("Followed the correction.");
});

it("keeps opaque reasoning and compaction state when steering across steps", async () => {
  const options = await input();
  const client = createOffensiveSecurityAgentClient();
  const opaque = {
    openai: {
      type: "compaction",
      itemId: "cmp_1",
      encryptedContent: "opaque-state",
    },
  };
  observed.respond = async (index) =>
    index === 0
      ? [
          {
            type: "custom",
            kind: "openai.compaction",
            providerMetadata: opaque,
          },
          { type: "reasoning-start", id: "reason" },
          { type: "reasoning-delta", id: "reason", delta: "hypothesis" },
          {
            type: "reasoning-end",
            id: "reason",
            providerMetadata: {
              openai: {
                itemId: "reason",
                reasoningEncryptedContent: "opaque-reasoning",
              },
            },
          },
          call("0"),
          finish("tool-calls"),
        ]
      : index === 1
        ? [call("1"), finish("tool-calls")]
        : answer();
  const result = await client.run({
    ...options,
    activeTools: ["inspect"],
    extraTools: {
      inspect: tool({
        inputSchema: z.object({ id: z.string() }),
        execute: async ({ id }) => {
          if (id === "0")
            await client.steer({
              expectedTurnId: client.turnId,
              text: "Investigate the boundary",
            });
          return `evidence ${id}`;
        },
      }),
    },
  });
  const next = observed.calls[1]!.prompt;
  const later = observed.calls[2]!.prompt;
  expect(later.slice(0, next.length)).toEqual(next);
  expect(JSON.stringify(next)).toContain("opaque-state");
  expect(JSON.stringify(next)).toContain("opaque-reasoning");
  expect(JSON.stringify(next)).toContain("Investigate the boundary");
  expect(JSON.stringify(next)).not.toContain("Investigate the parser");
  expect(JSON.stringify(result.messages)).toContain("opaque-state");
});

it("retains accepted input on abort and delivers it once on resume", async () => {
  const options = await input();
  const started = gate();
  observed.respond = async () => [call("0"), finish("tool-calls")];
  const client = createOffensiveSecurityAgentClient();
  const running = client.run({
    ...options,
    activeTools: ["inspect"],
    extraTools: {
      inspect: tool({
        inputSchema: z.object({ id: z.string() }),
        execute: async (_, { abortSignal }) => {
          started.resolve();
          await new Promise<void>((resolve) =>
            abortSignal?.addEventListener("abort", () => resolve(), {
              once: true,
            }),
          );
          abortSignal?.throwIfAborted();
          return "unexpected";
        },
      }),
    },
  });
  const failure = running.catch((error: unknown) => error);
  await started.promise;
  await client.steer({
    expectedTurnId: client.turnId,
    text: "Preserve this correction",
  });
  await client.abort();
  expect(await failure).toBeInstanceOf(Error);
  const saved = JSON.parse(
    await readFile(join(root, "research-context.json"), "utf8"),
  );
  expect(saved.pendingInputs).toHaveLength(1);
  observed.respond = async () => answer();
  const resumed = await runOffensiveSecurityAgent({
    ...options,
    prompt: "",
    newMessages: [],
  });
  expect(
    resumed.messages?.filter(
      (message) => message.content === "Preserve this correction",
    ),
  ).toHaveLength(1);
  expect(JSON.stringify(observed.calls.at(-1)?.prompt)).toContain(
    "Preserve this correction",
  );
});

it.each([
  "tool-calls",
  "stop",
] as const)("does not bypass a host stop condition after %s", async (reason) => {
  const options = await input();
  const client = createOffensiveSecurityAgentClient();
  observed.respond = async () => {
    await client.steer({
      expectedTurnId: client.turnId,
      text: "After this boundary",
    });
    return reason === "stop" ? answer() : [call("0"), finish("tool-calls")];
  };
  await client.run({
    ...options,
    stopWhen: stepCountIs(1),
    activeTools: ["inspect"],
    extraTools: {
      inspect: tool({
        inputSchema: z.object({ id: z.string() }),
        execute: async () => {
          return "evidence";
        },
      }),
    },
  });
  expect(observed.calls).toHaveLength(1);
  const saved = JSON.parse(
    await readFile(join(root, "research-context.json"), "utf8"),
  );
  expect(saved.pendingInputs).toEqual([
    expect.objectContaining({ text: "After this boundary" }),
  ]);
});
