/**
 * Run tasks with bounded concurrency.
 * Returns an array of results in the same order as items.
 * Failed tasks produce null in the results array.
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

    function next() {
      // Resolve when all launched tasks complete and either all items
      // have been launched or the signal was aborted.
      if (
        completed >= nextIdx &&
        (nextIdx === items.length || abortSignal?.aborted)
      ) {
        resolve();
        return;
      }

      while (
        active < concurrency &&
        nextIdx < items.length &&
        !abortSignal?.aborted
      ) {
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
