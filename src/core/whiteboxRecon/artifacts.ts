import { randomUUID } from "node:crypto";
import {
  appendFile,
  mkdir,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import type { RepositoryInventory } from "./types";

export interface ReconArtifactPaths {
  root: string;
  inventory: string;
  repositoryMap: string;
  planner: string;
  formalArtifacts: string;
  configArtifacts: string;
  selectors: string;
  candidates: string;
  observations: string;
  workers: string;
  reconciliationInput: string;
  reconciliation: string;
  registry: string;
  result: string;
  metrics: string;
}

export async function createReconArtifacts(
  sessionRoot: string,
  runKey: string,
): Promise<ReconArtifactPaths> {
  const root = path.join(sessionRoot, "whitebox-recon-v2", "runs", runKey);
  const workers = path.join(root, "batches");
  await mkdir(workers, { recursive: true });
  return {
    root,
    inventory: path.join(root, "inventory.ndjson"),
    repositoryMap: path.join(root, "repository-map.json"),
    planner: path.join(root, "planner.json"),
    formalArtifacts: path.join(root, "formal-artifacts.json"),
    configArtifacts: path.join(root, "config-artifacts.json"),
    selectors: path.join(root, "selectors.json"),
    candidates: path.join(root, "candidates.json"),
    observations: path.join(root, "observations.ndjson"),
    workers,
    reconciliationInput: path.join(root, "reconciliation-input.json"),
    reconciliation: path.join(root, "reconciliation.json"),
    registry: path.join(root, "registry.json"),
    result: path.join(root, "result.json"),
    metrics: path.join(root, "metrics.json"),
  };
}

export async function writeInventoryArtifact(
  artifactPath: string,
  inventory: RepositoryInventory,
): Promise<void> {
  const records = [
    {
      record_type: "repository",
      repository_root: inventory.repository_root,
    },
    ...inventory.files.map((file) => ({ record_type: "file", ...file })),
    ...inventory.excluded_directories.map((directory) => ({
      record_type: "excluded_directory",
      ...directory,
    })),
  ];
  await atomicWrite(
    artifactPath,
    `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
  );
}

export async function writeJsonArtifact(
  artifactPath: string,
  value: unknown,
): Promise<void> {
  await atomicWrite(artifactPath, `${JSON.stringify(value, null, 2)}\n`);
}

export async function readJsonArtifact(
  artifactPath: string,
): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(artifactPath, "utf8"));
  } catch (error) {
    if (isMissingFile(error)) return null;
    throw error;
  }
}

export class ObservationJournal {
  private pending: Promise<void> = Promise.resolve();

  constructor(private readonly artifactPath: string) {}

  append(record: unknown): Promise<void> {
    this.pending = this.pending.then(() =>
      appendFile(this.artifactPath, `${JSON.stringify(record)}\n`, "utf8"),
    );
    return this.pending;
  }

  flush(): Promise<void> {
    return this.pending;
  }
}

async function atomicWrite(
  artifactPath: string,
  content: string,
): Promise<void> {
  await mkdir(path.dirname(artifactPath), { recursive: true });
  const temporaryPath = `${artifactPath}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, content, "utf8");
  await rename(temporaryPath, artifactPath);
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}
