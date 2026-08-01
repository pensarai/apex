import { createHash } from "node:crypto";
import path from "node:path";
import type {
  ReconApplication,
  ReconResource,
  ReconSurface,
  RepositoryInventory,
} from "./types";

export function canonicalApplicationId(
  application: Pick<ReconApplication, "name" | "source_roots">,
): string {
  const slug = slugify(application.name) || "application";
  const roots = normalizeStringSet(application.source_roots);
  const seed = roots.length > 0 ? roots.join("\n") : application.name.trim();
  return `${slug}-${shortHash(seed)}`;
}

export function surfaceIdentity(surface: ReconSurface): string {
  return [
    surface.application_id,
    surface.type,
    (surface.method ?? "").toUpperCase(),
    surface.path_or_name,
  ].join("\u0000");
}

export function resourceIdentity(resource: ReconResource): string {
  return [
    resource.application_id,
    resource.type,
    resource.provider.toLowerCase(),
    resource.identifier,
  ].join("\u0000");
}

export function observationId(
  kind: "surface" | "resource",
  seed: string,
): string {
  return `${kind}-${shortHash(seed, 16)}`;
}

export function normalizeRepositoryPath(input: string): string | null {
  if (!input || path.isAbsolute(input)) return null;
  const normalized = path.posix.normalize(input.replaceAll("\\", "/"));
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../")
  ) {
    return null;
  }
  return normalized.replace(/^\.\//, "");
}

export function normalizeStringSet(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort(
    (a, b) => a.localeCompare(b),
  );
}

export function shortHash(value: string, length = 10): string {
  return createHash("sha256").update(value).digest("hex").slice(0, length);
}

export function repositoryRunKey(
  inventory: RepositoryInventory,
  configuration: unknown,
): string {
  const hash = createHash("sha256");
  hash.update(JSON.stringify(configuration));
  for (const file of inventory.files) {
    hash.update("\u0000");
    hash.update(file.path);
    hash.update("\u0000");
    hash.update(file.sha256 ?? `${file.relevance}:${file.reason ?? ""}`);
  }
  for (const directory of inventory.excluded_directories) {
    hash.update("\u0000directory\u0000");
    hash.update(directory.path);
    hash.update("\u0000");
    hash.update(directory.reason);
  }
  return hash.digest("hex").slice(0, 24);
}

function slugify(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}
