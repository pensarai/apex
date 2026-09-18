import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { type FileHandle, mkdir, open, readFile, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import {
  ATIF_EXPORT_SOURCE_LIMITS,
  type AtifBundleFile,
  type AtifExporterIdentity,
  type AtifTrajectoryV1_8,
  serializeAtifExportBundle,
  TrajectoryBundleManifestSchema,
  type TrajectoryBundleManifestV1,
} from "../atif";

export interface TrajectoryEvidenceFile {
  id: string;
  path: string;
  sha256: string;
  sizeBytes: number;
}

export interface TrajectoryExportInput {
  sources: readonly TrajectoryEvidenceFile[];
  rootSourceId: string;
  agent: Pick<AtifTrajectoryV1_8["agent"], "name" | "version">;
  exporter: AtifExporterIdentity;
  outputDirectory: string;
  independentValidation?: {
    status: "passed" | "failed";
    detail: string;
  };
}

export interface TrajectoryExportFile {
  kind: AtifBundleFile["kind"];
  path: string;
  mediaType: string;
  sha256: string;
  sizeBytes: number;
}

export interface TrajectoryExportResult {
  outputDirectory: string;
  manifestPath: string;
  manifest: TrajectoryBundleManifestV1;
  files: readonly TrajectoryExportFile[];
}

export type TrajectoryExportErrorCode =
  | "INVALID_INPUT"
  | "SOURCE_UNAVAILABLE"
  | "SOURCE_IDENTITY_MISMATCH"
  | "BUNDLE_VALIDATION_FAILED"
  | "DESTINATION_EXISTS"
  | "PUBLISH_FAILED";

export class TrajectoryExportError extends Error {
  constructor(
    readonly code: TrajectoryExportErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "TrajectoryExportError";
  }
}

const sha256Pattern = /^[a-f0-9]{64}$/;

function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function invalid(message: string): never {
  throw new TrajectoryExportError("INVALID_INPUT", message);
}

function portableBundlePath(path: string): boolean {
  if (!path || path.includes("\\") || path.includes("\0")) return false;
  if (path.startsWith("/") || path.endsWith("/")) return false;
  return path
    .split("/")
    .every((part) => part !== "" && part !== "." && part !== "..");
}

function validateInput(input: TrajectoryExportInput): void {
  if (
    !input ||
    !Array.isArray(input.sources) ||
    input.sources.length === 0 ||
    input.sources.length > ATIF_EXPORT_SOURCE_LIMITS.maxSources
  )
    invalid(
      `sources must contain 1-${ATIF_EXPORT_SOURCE_LIMITS.maxSources} saved evidence files`,
    );
  if (!input.rootSourceId || !input.outputDirectory)
    invalid("rootSourceId and outputDirectory are required");
  if (!input.agent?.name || !input.agent.version)
    invalid("agent name and version are required");
  if (!input.exporter?.name || !input.exporter.version)
    invalid("exporter name and version are required");

  const ids = new Set<string>();
  let total = 0;
  for (const source of input.sources) {
    if (
      !source.id ||
      !source.path ||
      !sha256Pattern.test(source.sha256) ||
      !Number.isSafeInteger(source.sizeBytes) ||
      source.sizeBytes < 0
    )
      invalid(
        "each source needs an id, path, lowercase SHA-256, and safe byte length",
      );
    if (ids.has(source.id)) invalid(`duplicate source id: ${source.id}`);
    ids.add(source.id);
    total += source.sizeBytes;
    if (
      !Number.isSafeInteger(total) ||
      total > ATIF_EXPORT_SOURCE_LIMITS.maxTotalSourceBytes
    )
      invalid(
        `source bytes exceed ${ATIF_EXPORT_SOURCE_LIMITS.maxTotalSourceBytes}`,
      );
  }
}

async function readExactSource(
  handle: FileHandle,
  source: TrajectoryEvidenceFile,
): Promise<Buffer> {
  const bytes = Buffer.allocUnsafe(source.sizeBytes);
  let offset = 0;
  while (offset < source.sizeBytes) {
    const result = await handle.read(
      bytes,
      offset,
      source.sizeBytes - offset,
      offset,
    );
    if (result.bytesRead === 0) break;
    offset += result.bytesRead;
  }
  const extra = Buffer.allocUnsafe(1);
  const extraRead = await handle.read(extra, 0, 1, offset);
  if (offset !== source.sizeBytes || extraRead.bytesRead !== 0)
    throw new TrajectoryExportError(
      "SOURCE_IDENTITY_MISMATCH",
      `saved evidence changed while it was being read: ${source.id}`,
    );
  return bytes;
}

async function readSource(source: TrajectoryEvidenceFile) {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      source.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size !== source.sizeBytes)
      throw new TrajectoryExportError(
        "SOURCE_IDENTITY_MISMATCH",
        `saved evidence size does not match: ${source.id}`,
      );
    const bytes = await readExactSource(handle, source);
    if (hash(bytes) !== source.sha256)
      throw new TrajectoryExportError(
        "SOURCE_IDENTITY_MISMATCH",
        `saved evidence digest does not match: ${source.id}`,
      );
    return {
      id: source.id,
      bytes,
      sha256: source.sha256,
      sizeBytes: source.sizeBytes,
    };
  } catch (error) {
    if (error instanceof TrajectoryExportError) throw error;
    throw new TrajectoryExportError(
      "SOURCE_UNAVAILABLE",
      `saved evidence could not be read: ${source.id}`,
      { cause: error },
    );
  } finally {
    await handle?.close();
  }
}

function validateBundle(
  files: readonly AtifBundleFile[],
  manifest: TrajectoryBundleManifestV1,
) {
  if (manifest.validation.status !== "passed")
    throw new TrajectoryExportError(
      "BUNDLE_VALIDATION_FAILED",
      "trajectory bundle validation failed",
    );
  const parsedManifest = TrajectoryBundleManifestSchema.parse(manifest);
  const paths = new Set<string>();
  let manifestFile: AtifBundleFile | undefined;
  for (const file of files) {
    if (!portableBundlePath(file.path) || paths.has(file.path))
      throw new TrajectoryExportError(
        "BUNDLE_VALIDATION_FAILED",
        `invalid or duplicate bundle path: ${file.path}`,
      );
    paths.add(file.path);
    if (
      file.sizeBytes !== file.bytes.byteLength ||
      !sha256Pattern.test(file.sha256) ||
      hash(file.bytes) !== file.sha256
    )
      throw new TrajectoryExportError(
        "BUNDLE_VALIDATION_FAILED",
        `bundle file identity does not match: ${file.path}`,
      );
    if (file.kind === "manifest") {
      if (manifestFile)
        throw new TrajectoryExportError(
          "BUNDLE_VALIDATION_FAILED",
          "trajectory bundle contains more than one manifest",
        );
      manifestFile = file;
    }
  }
  if (!manifestFile || manifestFile.path !== "manifest.json")
    throw new TrajectoryExportError(
      "BUNDLE_VALIDATION_FAILED",
      "trajectory bundle must contain manifest.json",
    );
  let persistedManifest: TrajectoryBundleManifestV1;
  try {
    persistedManifest = TrajectoryBundleManifestSchema.parse(
      JSON.parse(Buffer.from(manifestFile.bytes).toString("utf8")),
    );
  } catch (error) {
    throw new TrajectoryExportError(
      "BUNDLE_VALIDATION_FAILED",
      "trajectory bundle manifest bytes are invalid",
      { cause: error },
    );
  }
  if (JSON.stringify(persistedManifest) !== JSON.stringify(parsedManifest))
    throw new TrajectoryExportError(
      "BUNDLE_VALIDATION_FAILED",
      "trajectory bundle manifest bytes do not match the validated manifest",
    );
}

async function persistFile(root: string, file: AtifBundleFile): Promise<void> {
  const path = join(root, ...file.path.split("/"));
  await mkdir(dirname(path), { recursive: true });
  const handle = await open(path, "wx", 0o444);
  try {
    await handle.writeFile(file.bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const bytes = await readFile(path);
  if (bytes.byteLength !== file.sizeBytes || hash(bytes) !== file.sha256)
    throw new TrajectoryExportError(
      "PUBLISH_FAILED",
      `persisted bundle file identity does not match: ${file.path}`,
    );
}

async function publishBundle(
  destination: string,
  files: readonly AtifBundleFile[],
): Promise<void> {
  const parent = dirname(destination);
  const name = basename(destination);
  if (!name || name === ".") invalid("outputDirectory needs a directory name");
  const manifest = files.find((file) => file.kind === "manifest");
  if (!manifest)
    throw new TrajectoryExportError(
      "BUNDLE_VALIDATION_FAILED",
      "trajectory bundle must contain a manifest",
    );
  await mkdir(parent, { recursive: true });
  let ownsDestination = false;
  try {
    try {
      await mkdir(destination, { recursive: false, mode: 0o700 });
      ownsDestination = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST")
        throw new TrajectoryExportError(
          "DESTINATION_EXISTS",
          `output directory already exists: ${destination}`,
        );
      throw error;
    }
    for (const file of files) {
      if (file !== manifest) await persistFile(destination, file);
    }
    await persistFile(destination, manifest);
    ownsDestination = false;
  } catch (error) {
    if (error instanceof TrajectoryExportError) throw error;
    throw new TrajectoryExportError(
      "PUBLISH_FAILED",
      `trajectory bundle could not be published: ${destination}`,
      { cause: error },
    );
  } finally {
    if (ownsDestination)
      await rm(destination, { recursive: true, force: true });
  }
}

export async function exportTrajectoryBundle(
  input: TrajectoryExportInput,
): Promise<TrajectoryExportResult> {
  validateInput(input);
  const sources = [];
  for (const source of input.sources) sources.push(await readSource(source));
  const bundle = serializeAtifExportBundle({
    sources,
    rootSourceId: input.rootSourceId,
    agent: input.agent,
    exporter: input.exporter,
    ...(input.independentValidation
      ? { independentValidation: input.independentValidation }
      : {}),
  });
  validateBundle(bundle.files, bundle.manifest);
  const outputDirectory = resolve(input.outputDirectory);
  await publishBundle(outputDirectory, bundle.files);
  return {
    outputDirectory,
    manifestPath: join(outputDirectory, "manifest.json"),
    manifest: bundle.manifest,
    files: bundle.files.map(({ bytes: _bytes, ...file }) => file),
  };
}
