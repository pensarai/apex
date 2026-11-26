import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3 } from "@ai-sdk/provider";
import { expect, it, vi } from "vitest";
import { LanceRuntime } from "../core/agents/lance";
import { withNativeRolloutEvidenceModel } from "../core/ai/native-rollout-evidence";
import { runLance } from "../core/api/lance";
import type { SessionInfo } from "../core/session";
import { runCliLance } from "./lance";

vi.mock("../core/api/lance", () => ({ runLance: vi.fn() }));

it("captures Lance model-boundary evidence when the CLI destination is configured", async () => {
  const root = await mkdtemp(join(tmpdir(), "lance-cli-"));
  const outputDirectory = join(root, "evidence");
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  vi.stubEnv("APEX_OBJECTIVE_VERIFIER_IPC", undefined);
  const session = {
    id: "lance-cli-fixture",
    config: { nativeRolloutEvidence: { outputDirectory } },
  } as SessionInfo;
  const runtime = new LanceRuntime();
  runtime.finish();
  vi.mocked(runLance).mockImplementation(async () => {
    const model: LanguageModelV3 = {
      specificationVersion: "v3",
      provider: "fixture",
      modelId: "fixture-model",
      supportedUrls: {},
      doGenerate: async () => ({
        content: [{ type: "text", text: "done" }],
        finishReason: { unified: "stop", raw: "stop" },
        usage: {
          inputTokens: { total: 2, noCache: 2, cacheRead: 0, cacheWrite: 0 },
          outputTokens: { total: 1, text: 1, reasoning: 0 },
        },
        warnings: [],
      }),
      doStream: vi.fn(),
    };
    await withNativeRolloutEvidenceModel(model, {
      requestedModelId: "fixture-model",
      operationKind: "agent.stream",
      sessionId: session.id,
    }).doGenerate({ prompt: [] });
    return { session, result: runtime.metrics("fixture-model") };
  });
  try {
    await runCliLance({ session, model: "fixture-model", prompt: "fixture" });
    const manifest = JSON.parse(
      await readFile(join(outputDirectory, "manifest.json"), "utf8"),
    );
    expect(manifest.runId).toBe(session.id);
    expect(manifest.files).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "evidence" }),
        expect.objectContaining({ kind: "attempt" }),
      ]),
    );
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/^LANCE_RESULT:/));
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/^METRICS:/));
    expect(log).toHaveBeenCalledWith(
      `Native evidence: ${join(outputDirectory, "manifest.json")}`,
    );
  } finally {
    log.mockRestore();
    vi.unstubAllEnvs();
    await rm(root, { recursive: true, force: true });
  }
});
