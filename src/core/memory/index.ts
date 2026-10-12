import { AsyncLocalStorage } from "node:async_hooks";
import * as Storage from "../storage";

export const MEMORY_CATEGORIES = ["app", "framework", "general"] as const;
export type MemoryCategory = (typeof MEMORY_CATEGORIES)[number];

/** A persisted entry returned by the configured memory backend. */
export interface Memory {
  /** Unique identifier (kebab-case slug) */
  id: string;
  /** Storage category — "app", "framework", or "general" */
  category: MemoryCategory;
  /** Human-readable title */
  title: string;
  /** Free-form content of the memory */
  content: string;
  /** Optional tags for categorisation / filtering */
  tags: string[];
  /** ISO-8601 timestamp when the memory was created */
  createdAt: string;
  /** ISO-8601 timestamp of the last update */
  updatedAt: string;
}

export interface AddMemoryInput {
  title: string;
  content: string;
  category?: MemoryCategory;
  tags?: string[];
}

export interface MemoryListOptions {
  category?: MemoryCategory;
  tag?: string;
}

export interface MemoryOperationContext {
  sessionId: string;
  toolCallId: string;
}

export interface MemoryBackend {
  add(input: AddMemoryInput, context?: MemoryOperationContext): Promise<Memory>;
  list(
    options?: MemoryListOptions,
    context?: MemoryOperationContext,
  ): Promise<MemorySummary[]>;
  get(
    category: MemoryCategory,
    id: string,
    context?: MemoryOperationContext,
  ): Promise<Memory | null>;
}

const memoryBackend = new AsyncLocalStorage<MemoryBackend>();

/**
 * The backend is inherited by async child work and restored when the scope exits.
 * @public
 */
export function withMemoryBackend<T>(backend: MemoryBackend, run: () => T): T {
  return memoryBackend.run(backend, run);
}

const MEMORIES_PREFIX = "memories";

/** Disabled via the `PENSAR_MEMORY_ENABLED` env var; enabled when unset. */
export function isMemoryEnabled(): boolean {
  const v = process.env.PENSAR_MEMORY_ENABLED?.trim().toLowerCase();
  return !(v === "false" || v === "0" || v === "off" || v === "no");
}

function storageKey(category: MemoryCategory, id: string): string[] {
  return [MEMORIES_PREFIX, category, id];
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function makeId(title: string): string {
  const slug = slugify(title);
  const ts = Date.now().toString(36);
  return slug ? `${slug}-${ts}` : ts;
}

/**
 * Validate that an id does not contain path traversal sequences.
 * Throws an error if the id is unsafe.
 */
function validateId(id: string): void {
  if (id.includes("/") || id.includes("\\") || id.includes("..")) {
    throw new Error("Invalid memory id: contains path traversal characters");
  }
}

/**
 * Create and persist a new memory.
 *
 * @param input.category — "app", "framework", or "general" (default)
 */
export async function addMemory(
  input: AddMemoryInput,
  context?: MemoryOperationContext,
): Promise<Memory> {
  const backend = memoryBackend.getStore();
  if (backend) return backend.add(input, context);
  const category: MemoryCategory = input.category ?? "general";
  const id = makeId(input.title);
  const now = new Date().toISOString();

  const memory: Memory = {
    id,
    category,
    title: input.title,
    content: input.content,
    tags: input.tags ?? [],
    createdAt: now,
    updatedAt: now,
  };

  // Disabled: no-op write.
  if (!isMemoryEnabled()) return memory;

  await Storage.write(storageKey(category, id), memory);
  return memory;
}

/**
 * Create or overwrite a memory with a pre-determined ID.
 * Used for idempotent syncing from external sources (e.g., project knowledge).
 *
 * @knipignore Console imports this from `@/packages/apex/src/core/memory`;
 * nothing in this repo calls it, so knip would otherwise report it as dead.
 */
export async function addMemoryWithId(input: {
  id: string;
  title: string;
  content: string;
  category?: MemoryCategory;
  tags?: string[];
}): Promise<Memory> {
  if (memoryBackend.getStore())
    throw new Error("addMemoryWithId is only supported by filesystem memory");
  validateId(input.id);
  const category: MemoryCategory = input.category ?? "general";
  const now = new Date().toISOString();

  // Disabled: no-op write.
  if (!isMemoryEnabled()) {
    return {
      id: input.id,
      category,
      title: input.title,
      content: input.content,
      tags: input.tags ?? [],
      createdAt: now,
      updatedAt: now,
    };
  }

  // Preserve createdAt if this is an update
  let createdAt = now;
  try {
    const existing = await Storage.read<Memory>(storageKey(category, input.id));
    createdAt = existing.createdAt;
  } catch {
    // New memory — use current timestamp
  }

  const memory: Memory = {
    id: input.id,
    category,
    title: input.title,
    content: input.content,
    tags: input.tags ?? [],
    createdAt,
    updatedAt: now,
  };

  await Storage.write(storageKey(category, input.id), memory);
  return memory;
}

/**
 * Delete a single memory by category + id.
 * Returns true if deleted, false if not found.
 *
 * @knipignore Console imports this from `@/packages/apex/src/core/memory`;
 * nothing in this repo calls it, so knip would otherwise report it as dead.
 */
export async function deleteMemory(
  category: MemoryCategory,
  id: string,
): Promise<boolean> {
  if (memoryBackend.getStore())
    throw new Error("deleteMemory is only supported by filesystem memory");
  if (!isMemoryEnabled()) return false;
  validateId(id);
  // Check existence first — Storage.remove silently succeeds on missing files
  const existing = await getMemory(category, id);
  if (!existing) return false;
  await Storage.remove(storageKey(category, id));
  return true;
}

/**
 * Retrieve a single memory by category + id.
 * Returns `null` when the entry does not exist.
 */
export async function getMemory(
  category: MemoryCategory,
  id: string,
  context?: MemoryOperationContext,
): Promise<Memory | null> {
  const backend = memoryBackend.getStore();
  if (backend) return backend.get(category, id, context);
  if (!isMemoryEnabled()) return null;
  validateId(id);
  try {
    return await Storage.read<Memory>(storageKey(category, id));
  } catch (e) {
    if (e instanceof Storage.NotFoundError) return null;
    throw e;
  }
}

export interface MemorySummary {
  id: string;
  category: MemoryCategory;
  title: string;
  tags: string[];
  createdAt: string;
}

/**
 * List memories (lightweight summaries).
 *
 * - `category` — restrict to a single category; omit to list all.
 * - `tag` — further filter to entries containing this tag.
 */
export async function listMemories(
  opts?: MemoryListOptions,
  context?: MemoryOperationContext,
): Promise<MemorySummary[]> {
  const backend = memoryBackend.getStore();
  if (backend) return backend.list(opts, context);
  if (!isMemoryEnabled()) return [];
  const prefix = opts?.category
    ? [MEMORIES_PREFIX, opts.category]
    : [MEMORIES_PREFIX];
  const keys = await Storage.list(prefix);

  const summaries: MemorySummary[] = [];
  for (const key of keys) {
    try {
      const memory = await Storage.read<Memory>(key);
      if (opts?.tag && !memory.tags.includes(opts.tag)) continue;
      summaries.push({
        id: memory.id,
        category: memory.category,
        title: memory.title,
        tags: memory.tags,
        createdAt: memory.createdAt,
      });
    } catch {
      // Skip unreadable entries
    }
  }

  summaries.sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );
  return summaries;
}
