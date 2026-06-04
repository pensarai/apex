import { context } from "@opentelemetry/api";

/**
 * Run tasks with bounded concurrency.
 * Returns an array of results in the same order as items.
 * Failed tasks produce null in the results array.
 *
 * When abortSignal fires, no NEW tasks are launched, but all
 * currently-running tasks are awaited to completion. This prevents
 * orphaned promises where agents finish their work but persistence
 * (saveSubagentData, manifest updates) never executes.
 *
 * Trace context: this is the seam where a code workflow fans out into agent
 * work, so it must carry the caller's OTel context into every task. Tasks are
 * launched from a `new Promise` executor and re-scheduled from `.finally()`
 * continuations, neither of which inherits the active context on its own — so
 * each `fn` invocation is explicitly run under the context that was active when
 * this helper was called. Without this, spans created inside `fn` (agent
 * `invoke_agent` spans and their gen_ai children) detach from the parent span
 * and never join the trace. Route all agent fan-out through this helper so the
 * routing can't be forgotten.
 */
export async function runWithBoundedConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
  abortSignal?: AbortSignal,
): Promise<(R | null)[]> {
  const results: (R | null)[] = new Array(items.length).fill(null);
  const parentContext = context.active();
  let nextIdx = 0;
  let completed = 0;

  await new Promise<void>((resolve) => {
    if (items.length === 0) {
      resolve();
      return;
    }

    let active = 0;

    function canLaunchMore(): boolean {
      return (
        active < concurrency && nextIdx < items.length && !abortSignal?.aborted
      );
    }

    function next() {
      // Resolve when all launched tasks have completed and no more can start.
      // After abort, this waits for in-flight tasks instead of resolving early.
      if (completed >= nextIdx && !canLaunchMore()) {
        resolve();
        return;
      }

      while (canLaunchMore()) {
        const idx = nextIdx++;
        active++;

        context
          .with(parentContext, () => fn(items[idx]!, idx))
          .then((r) => {
            results[idx] = r;
          })
          .catch(() => {
            results[idx] = null;
          })
          .finally(() => {
            active--;
            completed++;
            next();
          });
      }
    }

    next();
  });

  return results;
}
