import {
  mkdir,
  mkdtemp,
  type open,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
} from "@ai-sdk/provider";
import { afterEach, describe, expect, it, vi } from "vitest";
import { withNativeRolloutEvidenceModel } from "../core/ai/native-rollout-evidence";
import { runWithCliNativeRolloutEvidence } from "./native-rollout-evidence";

const fsMocks = vi.hoisted(() => ({
  open: vi.fn(),
  realOpen: undefined as typeof open | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  fsMocks.realOpen = actual.open;
  fsMocks.open.mockImplementation(actual.open);
  return { ...actual, open: fsMocks.open };
});

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.useRealTimers();
  if (fsMocks.realOpen) fsMocks.open.mockImplementation(fsMocks.realOpen);
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

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
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
  it("creates missing parents while reserving the destination exclusively", async () => {
    const outputDirectory = join(await outputFixture(), "nested", "run");
    await runWithCliNativeRolloutEvidence({
      session: { id: "nested" },
      outputDirectory,
      run: async () => "done",
    });
    expect(await pathExists(join(outputDirectory, "manifest.json"))).toBe(true);
  });

  it.each([
    false,
    true,
  ])("keeps the commit marker absent during a blocked write (failure: %s)", async (fail) => {
    const outputDirectory = await outputFixture();
    let release!: () => void;
    let started!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const writing = new Promise<void>((resolve) => {
      started = resolve;
    });
    const realOpen = fsMocks.realOpen;
    if (!realOpen) throw new Error("missing real fs.open implementation");
    fsMocks.open.mockImplementation(async (...args) => {
      const handle = await realOpen(args[0], args[1], args[2]);
      if (!String(args[0]).includes("manifest.json")) return handle;
      return {
        close: handle.close.bind(handle),
        sync: handle.sync.bind(handle),
        writeFile: async (bytes: Uint8Array) => {
          await handle.writeFile(bytes.subarray(0, 8));
          started();
          await blocked;
          if (fail) throw new Error("interrupted manifest write");
          await handle.writeFile(bytes.subarray(8));
        },
      } as Awaited<ReturnType<typeof open>>;
    });
    const result = runWithCliNativeRolloutEvidence({
      session: { id: "atomic" },
      outputDirectory,
      run: async () => "done",
    });
    await writing;
    const visible = await pathExists(join(outputDirectory, "manifest.json"));
    release();
    if (fail)
      await expect(result).rejects.toThrow("interrupted manifest write");
    else await result;
    expect(visible).toBe(false);
    expect(await pathExists(join(outputDirectory, "manifest.json"))).toBe(
      !fail,
    );
    if (!fail)
      expect(
        JSON.parse(
          await readFile(join(outputDirectory, "manifest.json"), "utf8"),
        ),
      ).toMatchObject({ runId: "atomic" });
  });

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

  it("waits for an aborted disk write to settle before publishing the manifest", async () => {
    const outputDirectory = await outputFixture();
    let delayedEvidencePath: string | undefined;
    let releaseWrite: (() => void) | undefined;
    let writeStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      writeStarted = resolve;
    });
    const released = new Promise<void>((resolve) => {
      releaseWrite = resolve;
    });
    const realOpen = fsMocks.realOpen;
    if (!realOpen) throw new Error("missing real fs.open implementation");
    fsMocks.open.mockImplementation(async (...args) => {
      const handle = await realOpen(args[0], args[1], args[2]);
      if (!String(args[0]).includes("/evidence/")) return handle;
      delayedEvidencePath = String(args[0]);
      return {
        close: handle.close.bind(handle),
        sync: handle.sync.bind(handle),
        writeFile: async (bytes: Uint8Array) => {
          writeStarted?.();
          await released;
          await handle.writeFile(bytes);
        },
      } as Awaited<ReturnType<typeof open>>;
    });

    const result = runWithCliNativeRolloutEvidence({
      session: { id: "ses-delayed-write" },
      outputDirectory,
      run: async () => {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "fixture-model",
          operationKind: "agent.stream",
          sessionId: "ses-delayed-write",
        });
        await wrapped.doGenerate(callOptions);
        return "done";
      },
    });
    await started;
    await new Promise((resolve) => setTimeout(resolve, 2_250));
    const manifestPublishedBeforeWriteSettled = await pathExists(
      join(outputDirectory, "manifest.json"),
    );
    releaseWrite?.();
    await result;

    const manifest = JSON.parse(
      await readFile(join(outputDirectory, "manifest.json"), "utf8"),
    ) as { files: Array<{ path: string }>; report: { state: string } };
    if (!delayedEvidencePath) throw new Error("missing delayed evidence path");
    expect(manifestPublishedBeforeWriteSettled).toBe(false);
    expect(await pathExists(delayedEvidencePath)).toBe(false);
    expect(
      manifest.files.some((entry) => entry.path.startsWith("evidence/")),
    ).toBe(false);
    expect(manifest.report.state).toBe("limited");
  });
});
