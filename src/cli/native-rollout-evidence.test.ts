import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
} from "@ai-sdk/provider";
import { afterEach, describe, expect, it, vi } from "vitest";
import { withNativeRolloutEvidenceModel } from "../core/ai/native-rollout-evidence";
import { runWithCliNativeRolloutEvidence } from "./native-rollout-evidence";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function outputFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "apex-native-capture-"));
  temporaryDirectories.push(root);
  return join(root, "capture");
}

function model(): LanguageModelV3 {
  return {
    specificationVersion: "v3",
    provider: "fixture",
    modelId: "fixture-model",
    supportedUrls: {},
    doGenerate: async () => ({
      content: [{ type: "text", text: "done" }],
      finishReason: { unified: "stop", raw: "stop" },
      usage: {
        inputTokens: {
          total: 2,
          noCache: 2,
          cacheRead: 0,
          cacheWrite: 0,
        },
        outputTokens: { total: 1, text: 1, reasoning: 0 },
      },
      response: { id: "response-fixture", modelId: "fixture-model" },
      warnings: [],
    }),
    doStream: vi.fn(),
  };
}

const callOptions = { prompt: [] } as LanguageModelV3CallOptions;

describe("CLI native rollout evidence", () => {
  it("stays disabled without an explicit output directory", async () => {
    const run = vi.fn(async () => "done");

    const result = await runWithCliNativeRolloutEvidence({
      session: { id: "ses-disabled" },
      run,
    });

    expect(result).toEqual({ value: "done" });
    expect(run).toHaveBeenCalledOnce();
  });

  it("rejects an existing destination before starting the run", async () => {
    const outputDirectory = await outputFixture();
    await mkdir(outputDirectory);
    await writeFile(join(outputDirectory, "sentinel"), "keep");
    const run = vi.fn(async () => "unreachable");

    await expect(
      runWithCliNativeRolloutEvidence({
        session: { id: "ses-existing" },
        outputDirectory,
        run,
      }),
    ).rejects.toThrow("destination already exists");

    expect(run).not.toHaveBeenCalled();
    expect(await readFile(join(outputDirectory, "sentinel"), "utf8")).toBe(
      "keep",
    );
  });

  it("publishes evidence and matching attempt identities before the final marker", async () => {
    const outputDirectory = await outputFixture();

    const result = await runWithCliNativeRolloutEvidence({
      session: { id: "ses-cli-capture" },
      outputDirectory,
      run: async () => {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "fixture-model",
          operationKind: "agent.stream",
          sessionId: "ses-cli-capture",
        });
        await wrapped.doGenerate(callOptions);
        return "done";
      },
    });
    const manifest = JSON.parse(
      await readFile(join(outputDirectory, "manifest.json"), "utf8"),
    ) as {
      report: { state: string };
      files: Array<{ kind: string; path: string; sha256: string }>;
    };
    const evidenceEntry = manifest.files.find(
      (entry) => entry.kind === "evidence",
    );
    const attemptEntries = manifest.files.filter(
      (entry) => entry.kind === "attempt",
    );
    expect(evidenceEntry).toBeDefined();
    if (!evidenceEntry) throw new Error("missing evidence entry");
    const evidence = JSON.parse(
      await readFile(join(outputDirectory, evidenceEntry.path), "utf8"),
    ) as { attempt: { attemptId: string } };
    const attempts = await Promise.all(
      attemptEntries.map(async (entry) =>
        JSON.parse(await readFile(join(outputDirectory, entry.path), "utf8")),
      ),
    );

    expect(result).toMatchObject({
      value: "done",
      outputDirectory,
      manifestPath: join(outputDirectory, "manifest.json"),
      report: { state: "complete" },
    });
    expect(manifest.report.state).toBe("complete");
    expect(attempts.map((attempt) => attempt.lifecycle).sort()).toEqual([
      "completed",
      "started",
    ]);
    expect(
      attempts.every(
        (attempt) => attempt.attemptId === evidence.attempt.attemptId,
      ),
    ).toBe(true);
    expect(manifest.files.every((entry) => entry.sha256.length === 64)).toBe(
      true,
    );
  });

  it("retains interrupted evidence with a final marker when the run fails", async () => {
    const outputDirectory = await outputFixture();

    await expect(
      runWithCliNativeRolloutEvidence({
        session: { id: "ses-failed" },
        outputDirectory,
        run: async () => {
          throw new Error("runner failed");
        },
      }),
    ).rejects.toThrow("runner failed");

    expect(
      JSON.parse(
        await readFile(join(outputDirectory, "manifest.json"), "utf8"),
      ),
    ).toMatchObject({ report: { state: "interrupted" }, files: [] });
  });
});
