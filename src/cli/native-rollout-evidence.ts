import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import {
  createNativeRolloutEvidenceCapture,
  type InferenceAttempt,
  type NativeRolloutCaptureReportV1,
  type NativeRolloutEvidenceEnvelopeV1,
  serializeNativeRolloutEvidence,
  stringifyCanonicalJson,
  toJsonValue,
} from "../core/ai";
import type { SessionInfo } from "../core/session";

const MAX_CAPTURE_FILES = 4_096;

interface CaptureFile {
  kind: "attempt" | "evidence";
  path: string;
  sha256: string;
  sizeBytes: number;
}

interface CliNativeRolloutEvidenceResult<T> {
  value: T;
  outputDirectory?: string;
  manifestPath?: string;
  report?: NativeRolloutCaptureReportV1;
}

interface RunWithCliNativeRolloutEvidenceInput<T> {
  session: Pick<SessionInfo, "id">;
  outputDirectory?: string;
  run: () => T | Promise<T>;
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function writeExclusive(path: string, bytes: Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function runWithCliNativeRolloutEvidence<T>(
  input: RunWithCliNativeRolloutEvidenceInput<T>,
): Promise<CliNativeRolloutEvidenceResult<T>> {
  if (!input.outputDirectory) return { value: await input.run() };

  const outputDirectory = resolve(input.outputDirectory);
  let ownsDirectory = false;
  let runStarted = false;
  const files: CaptureFile[] = [];
  let reservedFiles = 0;

  const record = async (
    kind: CaptureFile["kind"],
    path: string,
    bytes: Uint8Array,
  ): Promise<void> => {
    reservedFiles += 1;
    if (reservedFiles > MAX_CAPTURE_FILES) {
      throw new Error(
        `native rollout capture exceeds ${MAX_CAPTURE_FILES} files`,
      );
    }
    const absolutePath = join(outputDirectory, path);
    await writeExclusive(absolutePath, bytes);
    files.push({
      kind,
      path,
      sha256: digest(bytes),
      sizeBytes: bytes.byteLength,
    });
  };

  try {
    await mkdir(outputDirectory, { recursive: false, mode: 0o700 });
    ownsDirectory = true;

    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: input.session.id,
      sink: {
        write: (envelope: NativeRolloutEvidenceEnvelopeV1) =>
          record(
            "evidence",
            `evidence/${envelope.attempt.attemptId}.json`,
            Buffer.from(serializeNativeRolloutEvidence(envelope)),
          ),
      },
      attemptSink: {
        write: (attempt: InferenceAttempt) =>
          record(
            "attempt",
            `attempts/${attempt.attemptId}/${attempt.lifecycle}.json`,
            Buffer.from(stringifyCanonicalJson(toJsonValue(attempt))),
          ),
      },
    });

    let value: T | undefined;
    let runError: unknown;
    runStarted = true;
    try {
      value = await capture.run(input.run);
    } catch (error) {
      runError = error;
    }

    const report = await capture.flush();
    const manifest = {
      schema: "pensar.native_rollout_capture" as const,
      version: 1 as const,
      runId: input.session.id,
      report,
      files: [...files].sort((left, right) =>
        left.path.localeCompare(right.path),
      ),
    };
    const manifestPath = join(outputDirectory, "manifest.json");
    await writeExclusive(
      manifestPath,
      Buffer.from(stringifyCanonicalJson(toJsonValue(manifest))),
    );

    if (runError !== undefined) throw runError;
    return {
      value: value as T,
      outputDirectory,
      manifestPath,
      report,
    };
  } catch (error) {
    if (ownsDirectory && !runStarted) {
      await rm(outputDirectory, { recursive: true, force: true });
    }
    if (
      !ownsDirectory &&
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "EEXIST"
    ) {
      throw new Error(
        `native rollout evidence destination already exists: ${outputDirectory}`,
        { cause: error },
      );
    }
    throw error;
  }
}
