import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { z } from "zod";

/**
 * Categories Apex ships with first-class knowledge of. The runtime library is
 * an open-ended, externally-curated dataset, so the catalog schema accepts any
 * non-empty category string — these are kept only for typing/autocomplete and
 * as the suggested set surfaced to agents.
 */
export const KNOWN_PROMPT_INJECTION_CATEGORIES = [
  "instruction-hijack",
  "data-exfiltration",
  "tool-misuse",
  "role-confusion",
  "encoding",
] as const;

export type PromptInjectionCategory =
  | (typeof KNOWN_PROMPT_INJECTION_CATEGORIES)[number]
  // Allow any other category the external library defines without losing
  // autocomplete on the known values above.
  | (string & {});

export type PromptInjectionRef = {
  kind: "prompt_injection_ref";
  id: string;
};

export type PromptInjectionCatalogEntry = {
  id: string;
  name: string;
  category: PromptInjectionCategory;
  description: string;
  tags: string[];
  deliveryHints: string[];
  expectedObservation: string;
  payloadHash: string;
};

type PromptInjectionEntry = Omit<PromptInjectionCatalogEntry, "payloadHash"> & {
  payload: string;
  payloadFilePath?: string;
};

export type PromptInjectionLibrary = {
  listCatalog(): PromptInjectionCatalogEntry[];
  getPayload(id: string): string | undefined;
  getPayloadFilePath(id: string): string | undefined;
  getPayloadHash(id: string): string | undefined;
  has(id: string): boolean;
};

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

// The runtime catalog is a large, externally-curated dataset that evolves
// independently of Apex. Only `id` and `payloadPath` are structurally required;
// every other field is optional and tolerant so a new taxonomy or a missing
// display name never hard-fails the whole library load (and never surfaces a
// raw Zod union error to the agent calling list_prompt_injections).
//
// Exported so producers of the catalog (e.g. the console admin upload route)
// can validate against the exact same contract Apex parses at runtime, instead
// of duplicating the shape and silently drifting.
export const PromptInjectionCatalogEntrySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).optional(),
  category: z.string().min(1).optional(),
  description: z.string().default(""),
  tags: z.array(z.string()).default([]),
  deliveryHints: z.array(z.string()).default([]),
  expectedObservation: z.string().default(""),
  payloadPath: z.string().min(1),
});

export const PromptInjectionLibraryFileSchema = z.union([
  z.array(PromptInjectionCatalogEntrySchema),
  z.object({
    payloads: z.array(PromptInjectionCatalogEntrySchema),
  }),
  z.object({
    injections: z.array(PromptInjectionCatalogEntrySchema),
  }),
]);

export type PromptInjectionCatalogValidation =
  | { ok: true; entryCount: number }
  | { ok: false; error: string };

/**
 * Structurally validate a parsed `catalog.json` against the canonical schema
 * Apex's loader uses, WITHOUT touching the filesystem (the payload files the
 * entries point at are uploaded separately and may not exist yet at validation
 * time). Returns the entry count on success or a concise, human-readable error
 * string on failure. Intended for upload-time validation at the perimeter.
 */
export function validatePromptInjectionCatalog(
  raw: unknown,
): PromptInjectionCatalogValidation {
  // Resolve the accepted container shape first so per-entry errors carry a
  // useful path (e.g. `payloads.0.payloadPath`). Validating against the raw
  // `z.union` instead collapses to a single unhelpful "(root): Invalid input".
  let entriesRaw: unknown;
  let pathPrefix: string;
  if (Array.isArray(raw)) {
    entriesRaw = raw;
    pathPrefix = "";
  } else if (
    raw !== null &&
    typeof raw === "object" &&
    Array.isArray((raw as { payloads?: unknown }).payloads)
  ) {
    entriesRaw = (raw as { payloads: unknown }).payloads;
    pathPrefix = "payloads.";
  } else if (
    raw !== null &&
    typeof raw === "object" &&
    Array.isArray((raw as { injections?: unknown }).injections)
  ) {
    entriesRaw = (raw as { injections: unknown }).injections;
    pathPrefix = "injections.";
  } else {
    return {
      ok: false,
      error:
        "Catalog must be a JSON array of entries, or an object with a `payloads` (or `injections`) array.",
    };
  }

  const result = z
    .array(PromptInjectionCatalogEntrySchema)
    .safeParse(entriesRaw);
  if (!result.success) {
    const error = result.error.issues
      .slice(0, 8)
      .map((issue) => `${pathPrefix}${issue.path.join(".")}: ${issue.message}`)
      .join("; ");
    return { ok: false, error: error || "Invalid prompt-injection catalog" };
  }
  return { ok: true, entryCount: result.data.length };
}

function isPromptInjectionRef(value: unknown): value is PromptInjectionRef {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>).kind === "prompt_injection_ref" &&
    typeof (value as Record<string, unknown>).id === "string"
  );
}

export class StaticPromptInjectionLibrary implements PromptInjectionLibrary {
  private readonly ordered: PromptInjectionEntry[];
  private readonly entries: Map<string, PromptInjectionEntry>;
  private readonly hashes: Map<string, string>;

  constructor(entries: PromptInjectionEntry[]) {
    this.ordered = entries;
    this.entries = new Map(entries.map((entry) => [entry.id, entry]));
    this.hashes = new Map(
      entries.map((entry) => [entry.id, sha256(entry.payload)]),
    );
  }

  listCatalog(): PromptInjectionCatalogEntry[] {
    return this.ordered.map(
      ({ payload, payloadFilePath: _path, ...entry }) => ({
        ...entry,
        payloadHash: sha256(payload),
      }),
    );
  }

  getPayload(id: string): string | undefined {
    return this.entries.get(id)?.payload;
  }

  getPayloadFilePath(id: string): string | undefined {
    return this.entries.get(id)?.payloadFilePath;
  }

  getPayloadHash(id: string): string | undefined {
    return this.hashes.get(id);
  }

  has(id: string): boolean {
    return this.entries.has(id);
  }
}

export const EMPTY_PROMPT_INJECTION_LIBRARY = new StaticPromptInjectionLibrary(
  [],
);

const SOURCE_CACHE = new Map<string, Promise<PromptInjectionLibrary>>();

function resolvePromptInjectionLibrarySource(
  explicit?: string,
): string | undefined {
  return (
    explicit ||
    process.env.PENSAR_PROMPT_INJECTION_LIBRARY ||
    process.env.APEX_PROMPT_INJECTION_LIBRARY
  );
}

function resolveCatalogPath(source: string): {
  catalogPath: string;
  root: string;
} {
  if (source.startsWith("https://") || source.startsWith("http://")) {
    throw new Error(
      "Prompt injection library source must be a local path, not a URL.",
    );
  }

  const path = source.startsWith("file://") ? source.slice(7) : source;
  const resolved = isAbsolute(path) ? path : resolve(process.cwd(), path);
  const stat = statSync(resolved);
  if (stat.isDirectory()) {
    return { catalogPath: join(resolved, "catalog.json"), root: resolved };
  }
  return { catalogPath: resolved, root: dirname(resolved) };
}

function resolvePayloadPath(root: string, payloadPath: string): string {
  if (isAbsolute(payloadPath)) {
    throw new Error("Prompt injection payloadPath must be relative.");
  }

  const resolved = resolve(root, payloadPath);
  const relativePath = relative(root, resolved);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`)) {
    throw new Error(
      "Prompt injection payloadPath must stay within the library.",
    );
  }

  return resolved;
}

function parsePromptInjectionLibrary(
  raw: string,
  root: string,
): PromptInjectionLibrary {
  const parsed = PromptInjectionLibraryFileSchema.parse(JSON.parse(raw));
  const catalogEntries = Array.isArray(parsed)
    ? parsed
    : "payloads" in parsed
      ? parsed.payloads
      : parsed.injections;

  const entries: PromptInjectionEntry[] = catalogEntries.map((entry) => {
    const payloadFile = resolvePayloadPath(root, entry.payloadPath);
    const payload = readFileSync(payloadFile, "utf-8");
    const { payloadPath: _payloadPath, name, category, ...safeEntry } = entry;
    return {
      ...safeEntry,
      // Fall back to the id for display when the catalog omits a name, and to a
      // neutral bucket when it omits a category, so downstream metadata is
      // always populated.
      name: name ?? entry.id,
      category: category ?? "uncategorized",
      payload,
      payloadFilePath: payloadFile,
    };
  });

  return new StaticPromptInjectionLibrary(entries);
}

async function readSource(source: string): Promise<PromptInjectionLibrary> {
  if (source.startsWith("https://") || source.startsWith("http://")) {
    throw new Error(
      "Prompt injection library source must be a local path, not a URL.",
    );
  }

  const { catalogPath, root } = resolveCatalogPath(source);
  return parsePromptInjectionLibrary(readFileSync(catalogPath, "utf-8"), root);
}

async function loadPromptInjectionLibrary(
  source: string,
): Promise<PromptInjectionLibrary> {
  let cached = SOURCE_CACHE.get(source);
  if (!cached) {
    cached = readSource(source).catch((err) => {
      SOURCE_CACHE.delete(source);
      throw err;
    });
    SOURCE_CACHE.set(source, cached);
  }
  return cached;
}

export async function getPromptInjectionLibrary(opts?: {
  library?: PromptInjectionLibrary;
  source?: string;
}): Promise<PromptInjectionLibrary> {
  if (opts?.library) return opts.library;
  const source = resolvePromptInjectionLibrarySource(opts?.source);
  if (!source) return EMPTY_PROMPT_INJECTION_LIBRARY;
  return loadPromptInjectionLibrary(source);
}

export function promptInjectionRef(id: string): PromptInjectionRef {
  return { kind: "prompt_injection_ref", id };
}

export function resolvePromptInjectionRefs<T>(
  value: T,
  library: PromptInjectionLibrary,
): T {
  if (isPromptInjectionRef(value)) {
    const payload = library.getPayload(value.id);
    if (!payload) throw new Error(`Unknown prompt injection id: ${value.id}`);
    return payload as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => resolvePromptInjectionRefs(item, library)) as T;
  }

  if (typeof value === "object" && value !== null) {
    const resolved: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      resolved[key] = resolvePromptInjectionRefs(nested, library);
    }
    return resolved as T;
  }

  return value;
}

export function redactPromptInjectionPayloads(
  value: string,
  library: PromptInjectionLibrary,
): string {
  let redacted = value;
  for (const entry of library.listCatalog()) {
    const payload = library.getPayload(entry.id);
    if (!payload) continue;
    redacted = redacted.split(payload).join(`[PROMPT_INJECTION:${entry.id}]`);
  }
  return redacted;
}
