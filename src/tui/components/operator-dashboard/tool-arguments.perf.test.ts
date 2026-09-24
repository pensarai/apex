import { performance } from "node:perf_hooks";
import { afterEach, expect, it, vi } from "vitest";
import type { DisplayMessage } from "../agent-display";
import * as messageUtils from "../shared/message-utils";
import { createDisplayEventHandlers } from "./run-events";

const now = performance.now.bind(performance);
const args = { path: "fixture.txt", content: "synthetic text ".repeat(1200) };
const serialized = JSON.stringify(args);
const chunks = serialized.match(/.{1,64}/g) ?? [];

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

it.each([
  { tools: 1, intervalMs: 0 },
  { tools: 1, intervalMs: 4 },
  { tools: 8, intervalMs: 4 },
  { tools: 1, intervalMs: 40 },
])("tool-argument replay: $tools tools, $intervalMs ms chunks", ({
  tools,
  intervalMs,
}) => {
  const samples: { wallMs: number; cpuMs: number }[] = [];
  let metrics = { parserCalls: 0, parserInputCharacters: 0, displayUpdates: 0 };
  for (let trial = 0; trial < 5; trial++) {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const parse = vi.spyOn(messageUtils, "tryParsePartialJson");
    let messages: DisplayMessage[] = Array.from(
      { length: 1000 },
      (_, index) => ({
        role: "user",
        content: `History ${index}`,
        createdAt: new Date(index),
      }),
    );
    let displayUpdates = 0;
    const display = createDisplayEventHandlers({
      updateMessages: (update) => {
        messages = update(messages);
        displayUpdates++;
      },
      setThinking: () => {},
      setError: () => {},
    });
    try {
      for (let tool = 0; tool < tools; tool++) {
        display.onToolCallStart({
          toolCallId: `tool-${tool}`,
          toolName: "create_file",
        });
      }
      displayUpdates = 0;
      const cpuStart = process.cpuUsage();
      const start = now();
      for (const [index, chunk] of chunks.entries()) {
        vi.advanceTimersByTime(index === 0 ? 0 : intervalMs);
        for (let tool = 0; tool < tools; tool++) {
          display.onToolCallDelta({
            toolCallId: `tool-${tool}`,
            argsTextDelta: chunk,
          });
        }
      }
      for (let tool = 0; tool < tools; tool++) {
        display.onToolCallComplete({
          toolCallId: `tool-${tool}`,
          toolName: "create_file",
          args,
        });
      }
      const wallMs = now() - start;
      const cpu = process.cpuUsage(cpuStart);
      samples.push({ wallMs, cpuMs: (cpu.user + cpu.system) / 1000 });
      metrics = {
        parserCalls: parse.mock.calls.length,
        parserInputCharacters: parse.mock.calls.reduce(
          (sum, [input]) => sum + input.length,
          0,
        ),
        displayUpdates,
      };
      const batches =
        intervalMs === 0
          ? 0
          : Math.floor((chunks.length - 1) / Math.ceil(33 / intervalMs));
      expect(metrics.parserCalls).toBe(batches * tools);
      expect(metrics.displayUpdates).toBe(metrics.parserCalls + tools);
      for (let tool = 0; tool < tools; tool++) {
        expect(messages[1000 + tool]).toMatchObject({
          toolCallId: `tool-${tool}`,
          status: "pending",
          args,
          logs: undefined,
        });
      }
      expect(vi.getTimerCount()).toBe(0);
      vi.advanceTimersByTime(1000);
      expect(displayUpdates).toBe(metrics.displayUpdates);
    } finally {
      display.dispose();
      parse.mockRestore();
      vi.useRealTimers();
    }
  }
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[2];
  console.info("tool-argument replay", {
    tools,
    intervalMs,
    chunksPerTool: chunks.length,
    historySize: 1000,
    ...metrics,
    trials: samples.length,
    wallMsMedian: median(samples.map((sample) => sample.wallMs)),
    cpuMsMedian: median(samples.map((sample) => sample.cpuMs)),
    samples,
  });
});
