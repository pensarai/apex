/**
 * Run tasks with bounded concurrency.
 * Returns an array of results in the same order as items.
 * Failed tasks produce null in the results array.
 *
 * When abortSignal fires, no NEW tasks are launched, but all
 * currently-running tasks are awaited to completion. This prevents
 * orphaned promises where agents finish their work but persistence
 * (saveSubagentData, manifest updates) never executes.
 */
export async function runWithBoundedConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
  abortSignal?: AbortSignal,
): Promise<(R | null)[]> {
  const results: (R | null)[] = new Array(items.length).fill(null);
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

        fn(items[idx]!, idx)
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
