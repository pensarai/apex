import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV4CallOptions } from "@ai-sdk/provider";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { afterEach, expect, it, vi } from "vitest";
import type { OffensiveSecurityAgentInput } from "../agents/offSecAgent";
import type { SessionInfo } from "../session";
import {
  createOffensiveSecurityAgentClient,
  runOffensiveSecurityAgent,
} from "./offesecAgent";

const observed = vi.hoisted(() => ({
  calls: [] as LanguageModelV4CallOptions[],
}));
vi.mock("../ai/utils", async (original) => ({
  ...(await original<typeof import("../ai/utils")>()),
  getProviderModel: () =>
    new MockLanguageModelV4({
      doStream: async (options) => {
        observed.calls.push(options);
        return {
          stream: simulateReadableStream({
            chunks: [
              { type: "text-start", id: "answer" },
              { type: "text-delta", id: "answer", delta: "Evidence retained." },
              { type: "text-end", id: "answer" },
              {
                type: "finish",
                finishReason: { unified: "stop", raw: undefined },
                usage: {
                  inputTokens: {
                    total: 10,
                    noCache: 10,
                    cacheRead: 0,
                    cacheWrite: 0,
                  },
                  outputTokens: { total: 2, text: 2, reasoning: 0 },
                },
              },
            ],
          }),
        };
      },
    }),
}));
let root: string | undefined;
function session(rootPath: string, id: string): SessionInfo {
  return {
    id,
    version: "1",
    time: { created: 0, updated: 0 },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
    targets: [],
  };
}
afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  observed.calls = [];
});

it("shares durable v2 continuation between the API and cancellable client", async () => {
  root = await mkdtemp(join(tmpdir(), "apex-v2-api-"));
  const input = {
    mode: "default-v2",
    model: "gpt-6.1-sol",
    prompt: "Inspect the parser",
    activeTools: [],
    system: "Follow the user's objective",
    session: session(root, "ses_v2"),
  } satisfies OffensiveSecurityAgentInput;
  const first = await runOffensiveSecurityAgent(input);
  expect(first.messages).toEqual([
    { role: "user", content: input.prompt },
    expect.objectContaining({ role: "assistant" }),
  ]);
  const client = createOffensiveSecurityAgentClient();
  const correction = {
    role: "user" as const,
    content: "The length conversion is the important hint. Follow it deeply.",
  };
  const second = await client.run({
    ...input,
    prompt: correction.content,
    newMessages: [correction],
  });
  expect(second.messages?.slice(0, first.messages?.length)).toEqual(
    first.messages,
  );
  expect(second.messages?.at(-2)).toEqual(correction);
  const secondPrompt = observed.calls[1]?.prompt;
  expect(
    secondPrompt?.some(
      (message) =>
        message.role === "user" &&
        JSON.stringify(message.content).includes("important hint"),
    ),
  ).toBe(true);
  expect(
    JSON.parse(await readFile(join(root, "research-context.json"), "utf8"))
      .messages,
  ).toEqual(second.messages);
});

it("serializes overlapping v2 inputs so neither correction is lost", async () => {
  root = await mkdtemp(join(tmpdir(), "apex-v2-queued-"));
  const input = {
    mode: "default-v2",
    model: "gpt-6.1-sol",
    prompt: "",
    activeTools: [],
    session: session(root, "ses_queued"),
  } satisfies OffensiveSecurityAgentInput;
  await Promise.all(
    ["First lead", "Second correction"].map((content) =>
      runOffensiveSecurityAgent({
        ...input,
        newMessages: [{ role: "user", content }],
      }),
    ),
  );
  const saved = JSON.parse(
    await readFile(join(root, "research-context.json"), "utf8"),
  );
  expect(
    saved.messages
      .filter((message: { role: string }) => message.role === "user")
      .map((message: { content: string }) => message.content),
  ).toEqual(["First lead", "Second correction"]);
});
