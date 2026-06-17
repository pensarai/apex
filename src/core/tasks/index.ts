/**
 * Task Decomposition System
 *
 * Per-agent, file-based task tracking for pentest agents.
 * Each agent decomposes objectives into concrete tasks (one per technique × endpoint),
 * tracks execution status, and uses task coverage as a gate before finishing.
 *
 * Storage: `{session.rootPath}/subagents/{subagentId}-tasks/{id}.json`
 *
 * Design decisions:
 * - Synchronous filesystem ops (matching trace.ts and persistence.ts patterns)
 * - Per-agent directories (no cross-agent contention, no file locking needed)
 * - High water mark for ID generation (prevents reuse after deletion)
 */

import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Task {
  id: number;
  /** Short subject: "Test /api/users id param for UNION-based SQLi" */
  subject: string;
  /** Detailed test plan */
  description: string;
  /** Current status */
  status: TaskStatus;
  /** Links back to the SwarmTarget objective this task addresses */
  objective: string;
  /** Specific attack technique: "UNION-based SQL injection", "reflected XSS" */
  technique: string;
  /** Outcome description on completion/failure */
  result?: string;
  /** Intermediate observations or notes */
  observation?: string;
  /** Arbitrary extensible metadata */
  metadata?: Record<string, unknown>;
  /** ISO 8601 creation timestamp */
  createdAt: string;
  /** ISO 8601 last update timestamp */
  updatedAt: string;
}

export type TaskStatus = "pending" | "in_progress" | "completed" | "failed";

export interface CreateTaskInput {
  subject: string;
  description: string;
  objective: string;
  technique: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateTaskInput {
  status?: TaskStatus;
  result?: string;
  observation?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HWM_FILENAME = "_hwm.json";

interface HighWaterMark {
  nextId: number;
}

// ---------------------------------------------------------------------------
// Directory management
// ---------------------------------------------------------------------------

function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true });
}

function taskPath(tasksDir: string, id: number): string {
  return join(tasksDir, `${id}.json`);
}

function hwmPath(tasksDir: string): string {
  return join(tasksDir, HWM_FILENAME);
}

// ---------------------------------------------------------------------------
// High water mark
// ---------------------------------------------------------------------------

function readHighWaterMark(tasksDir: string): HighWaterMark {
  try {
    const raw = readFileSync(hwmPath(tasksDir), "utf-8");
    const parsed = JSON.parse(raw) as HighWaterMark;
    return { nextId: parsed.nextId ?? 1 };
  } catch {
    return { nextId: 1 };
  }
}

function writeHighWaterMark(tasksDir: string, hwm: HighWaterMark): void {
  writeFileSync(hwmPath(tasksDir), JSON.stringify(hwm), "utf-8");
}

// ---------------------------------------------------------------------------
// CRUD Operations
// ---------------------------------------------------------------------------

/**
 * Create a new task. Assigns a monotonically increasing ID via high water mark.
 */
export function createTask(tasksDir: string, input: CreateTaskInput): Task {
  ensureDir(tasksDir);

  const hwm = readHighWaterMark(tasksDir);
  const id = hwm.nextId;

  const now = new Date().toISOString();
  const task: Task = {
    id,
    subject: input.subject,
    description: input.description,
    status: "pending",
    objective: input.objective,
    technique: input.technique,
    metadata: input.metadata,
    createdAt: now,
    updatedAt: now,
  };

  // HWM first, then task file. If crash between the two writes,
  // we skip an ID (harmless) rather than reuse one (data loss).
  writeHighWaterMark(tasksDir, { nextId: id + 1 });
  writeFileSync(taskPath(tasksDir, id), JSON.stringify(task, null, 2), "utf-8");

  return task;
}

/**
 * Read a single task by ID. Returns null if not found.
 */
function getTask(tasksDir: string, id: number): Task | null {
  try {
    const raw = readFileSync(taskPath(tasksDir, id), "utf-8");
    return JSON.parse(raw) as Task;
  } catch {
    return null;
  }
}

/**
 * Update an existing task. Merges the update fields into the existing task.
 * Returns the updated task, or null if not found.
 */
export function updateTask(
  tasksDir: string,
  id: number,
  update: UpdateTaskInput,
): Task | null {
  const existing = getTask(tasksDir, id);
  if (!existing) return null;

  const updated: Task = {
    ...existing,
    ...(update.status !== undefined && { status: update.status }),
    ...(update.result !== undefined && { result: update.result }),
    ...(update.observation !== undefined && {
      observation: update.observation,
    }),
    ...(update.metadata !== undefined && {
      metadata: { ...existing.metadata, ...update.metadata },
    }),
    updatedAt: new Date().toISOString(),
  };

  writeFileSync(
    taskPath(tasksDir, id),
    JSON.stringify(updated, null, 2),
    "utf-8",
  );

  return updated;
}

/**
 * List all tasks, optionally filtered by status.
 * Returns tasks sorted by ID ascending.
 */
export function listTasks(
  tasksDir: string,
  filter?: { status?: TaskStatus },
): Task[] {
  let files: string[];
  try {
    files = readdirSync(tasksDir);
  } catch {
    return [];
  }

  const tasks: Task[] = [];
  for (const file of files) {
    // Skip non-task files (high water mark, etc.)
    if (!file.endsWith(".json") || file === HWM_FILENAME) continue;

    try {
      const raw = readFileSync(join(tasksDir, file), "utf-8");
      const task = JSON.parse(raw) as Task;
      if (filter?.status && task.status !== filter.status) continue;
      tasks.push(task);
    } catch {}
  }

  // Sort by ID ascending
  tasks.sort((a, b) => a.id - b.id);
  return tasks;
}

/**
 * Get a summary of task counts by status.
 * Accepts a pre-loaded task array to avoid redundant directory reads.
 */
export function getTaskSummary(
  tasksDir: string,
  preloaded?: Task[],
): {
  total: number;
  pending: number;
  in_progress: number;
  completed: number;
  failed: number;
} {
  const tasks = preloaded ?? listTasks(tasksDir);
  const counts = { pending: 0, in_progress: 0, completed: 0, failed: 0 };
  for (const t of tasks) counts[t.status]++;
  return {
    total: tasks.length,
    ...counts,
  };
}
