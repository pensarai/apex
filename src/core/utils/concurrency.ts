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
  let launched = 0;
  let completed = 0;

  await new Promise<void>((resolve) => {
    if (items.length === 0) {
      resolve();
      return;
    }

    let active = 0;

    function next() {
      // Resolve when all LAUNCHED tasks have completed.
      // This ensures in-flight tasks are always awaited, even after abort.
      if (completed >= launched && launched > 0 && !canLaunchMore()) {
        resolve();
        return;
      }

      // Also resolve if nothing was ever launched (edge case: abort before first launch)
      if (launched === 0 && abortSignal?.aborted) {
        resolve();
        return;
      }

      while (canLaunchMore()) {
        const idx = nextIdx++;
        active++;
        launched++;

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

    function canLaunchMore(): boolean {
      return (
        active < concurrency && nextIdx < items.length && !abortSignal?.aborted
      );
    }

    next();
  });

  return results;
}
