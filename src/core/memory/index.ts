import * as Storage from "../storage";

/**
 * A single persisted memory entry stored in ~/.pensar/memories/{id}.json
 */
export interface Memory {
  /** Unique identifier (kebab-case slug) */
  id: string;
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

function storageKey(id: string): string[] {
  return [MEMORIES_PREFIX, id];
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
 * Create and persist a new memory.
 */
export async function addMemory(input: {
  title: string;
  content: string;
  tags?: string[];
}): Promise<Memory> {
  const id = makeId(input.title);
  const now = new Date().toISOString();

  const memory: Memory = {
    id,
    title: input.title,
    content: input.content,
    tags: input.tags ?? [],
    createdAt: now,
    updatedAt: now,
  };

  await Storage.write(storageKey(id), memory);
  return memory;
}

/**
 * Retrieve a single memory by its id.
 * Returns `null` when the id does not exist.
 */
export async function getMemory(id: string): Promise<Memory | null> {
  try {
    return await Storage.read<Memory>(storageKey(id));
  } catch (e) {
    if (e instanceof Storage.NotFoundError) return null;
    throw e;
  }
}

export interface MemorySummary {
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
}

/**
 * List all memories (lightweight summaries).
 *
 * An optional `tag` filter can be supplied to restrict results to
 * memories that contain that tag.
 */
export async function listMemories(tag?: string): Promise<MemorySummary[]> {
  const keys = await Storage.list([MEMORIES_PREFIX]);

  const summaries: MemorySummary[] = [];
  for (const key of keys) {
    try {
      const memory = await Storage.read<Memory>(key);
      if (tag && !memory.tags.includes(tag)) continue;
      summaries.push({
        id: memory.id,
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
