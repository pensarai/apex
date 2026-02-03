/**
 * Background Task Manager
 *
 * Manages background tool executions that run asynchronously.
 * Used when tools have `background: true` to return immediately
 * with a task ID while the actual work continues in the background.
 */

export type TaskStatus = "pending" | "running" | "completed" | "failed";

export interface BackgroundTask {
  id: string;
  toolName: string;
  status: TaskStatus;
  logs: string[];
  result?: unknown;
  error?: string;
  startedAt: Date;
  completedAt?: Date;
}

class TaskManager {
  private tasks: Map<string, BackgroundTask> = new Map();

  /**
   * Create a new background task
   */
  createTask(toolName: string): BackgroundTask {
    const task: BackgroundTask = {
      id: `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      toolName,
      status: "pending",
      logs: [],
      startedAt: new Date(),
    };
    this.tasks.set(task.id, task);
    return task;
  }

  /**
   * Update task status
   */
  updateStatus(taskId: string, status: TaskStatus): void {
    const task = this.tasks.get(taskId);
    if (task) {
      task.status = status;
      if (status === "completed" || status === "failed") {
        task.completedAt = new Date();
      }
    }
  }

  /**
   * Add a log line to the task
   */
  addLog(taskId: string, log: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      task.logs.push(log);
      // Keep logs bounded to prevent memory issues
      if (task.logs.length > 1000) {
        task.logs = task.logs.slice(-500);
      }
    }
  }

  /**
   * Set the task result (marks as completed)
   */
  setResult(taskId: string, result: unknown): void {
    const task = this.tasks.get(taskId);
    if (task) {
      task.result = result;
      task.status = "completed";
      task.completedAt = new Date();
    }
  }

  /**
   * Set task error (marks as failed)
   */
  setError(taskId: string, error: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      task.error = error;
      task.status = "failed";
      task.completedAt = new Date();
    }
  }

  /**
   * Get a task by ID
   */
  getTask(taskId: string): BackgroundTask | undefined {
    return this.tasks.get(taskId);
  }

  /**
   * Get all running/pending tasks
   */
  getRunningTasks(): BackgroundTask[] {
    return Array.from(this.tasks.values()).filter(
      (t) => t.status === "running" || t.status === "pending"
    );
  }

  /**
   * Get all tasks (for debugging)
   */
  getAllTasks(): BackgroundTask[] {
    return Array.from(this.tasks.values());
  }

  /**
   * Cleanup old completed tasks (keep last N)
   */
  cleanup(keepLast: number = 50): void {
    const completed = Array.from(this.tasks.values())
      .filter((t) => t.status === "completed" || t.status === "failed")
      .sort(
        (a, b) =>
          (b.completedAt?.getTime() || 0) - (a.completedAt?.getTime() || 0)
      );

    completed.slice(keepLast).forEach((t) => this.tasks.delete(t.id));
  }

  /**
   * Clear all tasks (for session reset)
   */
  clear(): void {
    this.tasks.clear();
  }
}

// Singleton instance
export const taskManager = new TaskManager();
