import { describe, expect, it, vi } from "vitest";
import { spawnReconAgent } from "./spawnReconAgent";
import type { ToolContext } from "./types";

function fixture(
  activeToolNames?: string[],
  response = "Inspected the OAuth callback.",
) {
  const spawnBatch = vi.fn(async () => [
    { status: "fulfilled", value: { response } },
  ]);
  const tool = spawnReconAgent({
    model: "test-model",
    activeToolNames,
    toolProtocol: "direct",
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
      {
        context: {},
        toolCallId: "call",
        messages: [],
      },
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
      [
        expect.objectContaining({
          spec: expect.objectContaining({ target }),
        }),
      ],
      expect.anything(),
    );
  });
  it("passes the parent's tool restrictions and protocol to the worker", async () => {
    const { run, spawnBatch } = fixture(["http_request", "spawn_recon_agent"]);
    await run();
    expect(spawnBatch).toHaveBeenCalledWith(
      [
        expect.objectContaining({
          spec: expect.objectContaining({
            excludeTools: expect.arrayContaining([
              "clone_repository",
              "execute_command",
            ]),
          }),
          runtime: expect.objectContaining({ toolProtocol: "direct" }),
        }),
      ],
      expect.anything(),
    );
  });
  it("returns the final worker summary across a workflow boundary without a shared bus", async () => {
    const { run } = fixture();
    expect(await run()).toMatchObject({
      success: true,
      results: [{ output: "Inspected the OAuth callback." }],
    });
  });
  it("reports workers that finish without a summary", async () => {
    const { run } = fixture(undefined, "");
    expect(await run()).toMatchObject({
      success: false,
      failedTasks: 1,
      results: [{ error: "Worker returned no final summary." }],
    });
  });
  it("rejects out-of-scope hosts before starting any workers", async () => {
    const { run, spawnBatch } = fixture();
    expect(await run("outside.example.test")).toMatchObject({ success: false });
    expect(spawnBatch).not.toHaveBeenCalled();
  });
});
