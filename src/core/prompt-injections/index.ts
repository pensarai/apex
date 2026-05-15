import { createHash } from "crypto";
import { readFileSync, statSync } from "fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "path";
import { z } from "zod";

export type PromptInjectionCategory =
  | "instruction-hijack"
  | "data-exfiltration"
  | "tool-misuse"
  | "role-confusion"
  | "encoding";

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

type PromptInjectionEntry = Omit<
  PromptInjectionCatalogEntry,
  "payloadHash"
> & {
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

const PromptInjectionCatalogEntrySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  category: z.enum([
    "instruction-hijack",
    "data-exfiltration",
    "tool-misuse",
    "role-confusion",
    "encoding",
  ]),
  description: z.string(),
  tags: z.array(z.string()).default([]),
  deliveryHints: z.array(z.string()).default([]),
  expectedObservation: z.string().default(""),
  payloadPath: z.string().min(1),
});

const PromptInjectionLibraryFileSchema = z.union([
  z.array(PromptInjectionCatalogEntrySchema),
  z.object({
    payloads: z.array(PromptInjectionCatalogEntrySchema),
  }),
  z.object({
    injections: z.array(PromptInjectionCatalogEntrySchema),
  }),
]);

export function isPromptInjectionRef(value: unknown): value is PromptInjectionRef {
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

  constructor(entries: PromptInjectionEntry[]) {
    this.ordered = entries;
    this.entries = new Map(entries.map((entry) => [entry.id, entry]));
  }

  listCatalog(): PromptInjectionCatalogEntry[] {
    return this.ordered.map(({ payload, payloadFilePath: _path, ...entry }) => ({
      ...entry,
      payloadHash: sha256(payload),
    }));
  }

  getPayload(id: string): string | undefined {
    return this.entries.get(id)?.payload;
  }

  getPayloadFilePath(id: string): string | undefined {
    return this.entries.get(id)?.payloadFilePath;
  }

  getPayloadHash(id: string): string | undefined {
    const payload = this.getPayload(id);
    return payload ? sha256(payload) : undefined;
  }

  has(id: string): boolean {
    return this.entries.has(id);
  }
}

export const EMPTY_PROMPT_INJECTION_LIBRARY = new StaticPromptInjectionLibrary(
  [],
);

const SOURCE_CACHE = new Map<string, Promise<PromptInjectionLibrary>>();

export function resolvePromptInjectionLibrarySource(
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
    throw new Error("Prompt injection payloadPath must stay within the library.");
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
    const { payloadPath: _payloadPath, ...safeEntry } = entry;
    return { ...safeEntry, payload, payloadFilePath: payloadFile };
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

export async function loadPromptInjectionLibrary(
  source: string,
): Promise<PromptInjectionLibrary> {
  let cached = SOURCE_CACHE.get(source);
  if (!cached) {
    cached = readSource(source);
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

export function summarizePromptInjectionRef(
  ref: PromptInjectionRef,
  library: PromptInjectionLibrary,
): { id: string; payloadHash?: string } {
  return {
    id: ref.id,
    payloadHash: library.getPayloadHash(ref.id),
  };
}
