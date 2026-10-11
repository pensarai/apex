import { AsyncLocalStorage } from "node:async_hooks";
import type { ToolSet } from "ai";
import { expect, it, vi } from "vitest";
import { wrapToolExecutionContext } from "./toolExecutionContext";

it("establishes context before tool work and preserves concurrent tool identities", async () => {
  const scope = new AsyncLocalStorage<string>();
  const order: string[] = [];
  const execute = vi.fn(async (_input, options) => {
    expect(scope.getStore()).toBe(options.toolCallId);
    await new Promise((resolve) => setImmediate(resolve));
    expect(scope.getStore()).toBe(options.toolCallId);
    return options.toolCallId;
  });
  const conversion = vi.fn();
  const tools = wrapToolExecutionContext(
    { probe: { execute, toModelOutput: conversion } } as unknown as ToolSet,
    {
      run(call, body) {
        order.push(call.toolCallId);
        return scope.run(call.toolCallId, body);
      },
    },
  );
  const run = tools.probe!.execute!;
  expect(
    await Promise.all(
      ["first", "second"].map((toolCallId) =>
        run({}, { toolCallId, messages: [] }),
      ),
    ),
  ).toEqual(["first", "second"]);
  expect(order).toEqual(["first", "second"]);
  expect(tools.probe!.toModelOutput).toBe(conversion);
});

it("lets the host reject a tool before any effect", async () => {
  const execute = vi.fn();
  const tools = wrapToolExecutionContext(
    { probe: { execute } } as unknown as ToolSet,
    {
      async run() {
        throw new Error("blocked");
      },
    },
  );
  await expect(
    tools.probe!.execute!({}, { toolCallId: "call", messages: [] }),
  ).rejects.toThrow("blocked");
  expect(execute).not.toHaveBeenCalled();
});
