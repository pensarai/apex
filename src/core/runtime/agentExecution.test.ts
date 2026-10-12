import { describe, expect, it, vi } from "vitest";

import { startAgentExecution } from "./agentExecution";

type FakeAgentOptions = {
  result?: string;
  rejectWith?: unknown;
  pendingConsume?: boolean;
};

/** Mirrors the real agent's drained lifecycle: placeholder until consume() swaps it. */
function makeFakeAgent(options: FakeAgentOptions = {}) {
  const placeholderDrained = Promise.resolve();
  const abortAndDrain = vi.fn(async () => {});
  let resolveDrain: (() => void) | undefined;
  const agent = {
    drained: placeholderDrained,
    abortAndDrain,
    async consume(): Promise<string> {
      agent.drained = new Promise<void>((resolve) => {
        resolveDrain = resolve;
      });
      if (options.rejectWith !== undefined) throw options.rejectWith;
      if (options.pendingConsume) return new Promise<string>(() => {});
      return options.result ?? "ok";
    },
  };
  return {
    agent,
    placeholderDrained,
    abortAndDrain,
    settleDrain: () => resolveDrain?.(),
  };
}

describe("startAgentExecution", () => {
  it("captures drained after consume() starts, not the pre-run placeholder", async () => {
    const { agent, placeholderDrained, settleDrain } = makeFakeAgent();
    const handle = startAgentExecution(agent);
    expect(handle.drained).not.toBe(placeholderDrained);
    expect(handle.drained).toBe(agent.drained);
    settleDrain();
    await handle.drained;
  });

  it("exposes consume()'s value as result", async () => {
    const { agent } = makeFakeAgent({ result: "payload" });
    const handle = startAgentExecution(agent);
    await expect(handle.result).resolves.toBe("payload");
  });

  it("result settles before drained — the early-return ordering", async () => {
    const { agent, settleDrain } = makeFakeAgent({ result: "early" });
    const handle = startAgentExecution(agent);
    const onDrained = vi.fn();
    void handle.drained.then(onDrained);
    await expect(handle.result).resolves.toBe("early");
    expect(onDrained).not.toHaveBeenCalled();
    settleDrain();
    await handle.drained;
    expect(onDrained).toHaveBeenCalledOnce();
  });

  it("propagates consume() rejection to result and leaves teardown to the agent", async () => {
    const sentinel = new Error("stream failed");
    const { agent, abortAndDrain } = makeFakeAgent({ rejectWith: sentinel });
    const handle = startAgentExecution(agent);
    await expect(handle.result).rejects.toBe(sentinel);
    await expect(handle.abortAndDrain()).resolves.toBeUndefined();
    expect(abortAndDrain).toHaveBeenCalledTimes(1);
  });

  it("delegates abortAndDrain to the agent before consume settles", async () => {
    const { agent, abortAndDrain } = makeFakeAgent({ pendingConsume: true });
    const handle = startAgentExecution(agent);
    await expect(handle.abortAndDrain()).resolves.toBeUndefined();
    expect(abortAndDrain).toHaveBeenCalledTimes(1);
  });

  it("delegates every abortAndDrain call — idempotence is the agent's contract", async () => {
    const { agent, abortAndDrain } = makeFakeAgent();
    const handle = startAgentExecution(agent);
    await handle.abortAndDrain();
    await handle.abortAndDrain();
    expect(abortAndDrain).toHaveBeenCalledTimes(2);
  });

  it("starts consume() exactly once", async () => {
    const { agent } = makeFakeAgent();
    const consumeSpy = vi.spyOn(agent, "consume");
    startAgentExecution(agent);
    expect(consumeSpy).toHaveBeenCalledTimes(1);
  });
});
