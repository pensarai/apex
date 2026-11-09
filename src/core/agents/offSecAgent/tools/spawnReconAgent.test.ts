import { describe, expect, it, vi } from "vitest";
import { spawnReconAgent } from "./spawnReconAgent";
import type { ToolContext } from "./types";

function fixture() {
  const spawnBatch = vi.fn(async () => [
    { status: "fulfilled", value: undefined },
  ]);
  const tool = spawnReconAgent({
    model: "test-model",
    session: {
      id: "parent",
      rootPath: "/unused",
      targets: ["https://console.example.test"],
    },
    subagentSpawner: { spawnBatch },
  } as unknown as ToolContext);
  const execute = tool.execute;
  if (!execute) throw new Error("spawn_recon_agent must have an executor");
  const run = (target?: string) =>
    execute(
      {
        tasks: [{ name: "review", goal: "Review auth controls", target }],
        toolCallDescription: "Review auth controls",
      },
      { toolCallId: "call", messages: [] },
    );
  return { run, spawnBatch };
}

describe("recon worker targets", () => {
  it.each([
    ["console.example.test", "https://console.example.test"],
    [
      "console.example.test:8443/path",
      "https://console.example.test:8443/path",
    ],
    ["http://console.example.test/path", "http://console.example.test/path"],
    [undefined, undefined],
  ])("passes a browser-ready authorized target for %s", async (input, target) => {
    const { run, spawnBatch } = fixture();
    await run(input);
    expect(spawnBatch).toHaveBeenCalledWith(
      [expect.objectContaining({ spec: expect.objectContaining({ target }) })],
      expect.anything(),
    );
  });
  it("rejects out-of-scope hosts before starting any workers", async () => {
    const { run, spawnBatch } = fixture();
    expect(await run("outside.example.test")).toMatchObject({ success: false });
    expect(spawnBatch).not.toHaveBeenCalled();
  });
});
