import * as Storage from "../storage";

export const MEMORY_CATEGORIES = ["app", "framework", "general"] as const;
export type MemoryCategory = (typeof MEMORY_CATEGORIES)[number];

/**
 * A single persisted memory entry stored in
 * ~/.pensar/memories/{category}/{id}.json
 */
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

const MEMORIES_PREFIX = "memories";

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
export async function addMemory(input: {
  title: string;
  content: string;
  category?: MemoryCategory;
  tags?: string[];
}): Promise<Memory> {
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

  await Storage.write(storageKey(category, id), memory);
  return memory;
}

/**
 * Retrieve a single memory by category + id.
 * Returns `null` when the entry does not exist.
 */
export async function getMemory(
  category: MemoryCategory,
  id: string,
): Promise<Memory | null> {
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
export async function listMemories(opts?: {
  category?: MemoryCategory;
  tag?: string;
}): Promise<MemorySummary[]> {
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
