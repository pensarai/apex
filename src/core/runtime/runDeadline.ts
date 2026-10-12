export function runDeadline(deadlineAt?: string, parent?: AbortSignal) {
  if (!deadlineAt) return { signal: parent, dispose() {} };
  const controller = new AbortController();
  const deadline = Date.parse(deadlineAt);
  if (!Number.isFinite(deadline)) throw new Error("Invalid run deadline");
  let timer: ReturnType<typeof setTimeout> | undefined;
  const schedule = () => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      controller.abort(
        new DOMException("Recorded run deadline expired", "AbortError"),
      );
    } else {
      // Node clamps longer delays to 1ms; recheck long deadlines in bounded intervals.
      timer = setTimeout(schedule, Math.min(remaining, 2_147_483_647));
      timer.unref();
    }
  };
  schedule();
  return {
    signal: parent
      ? AbortSignal.any([parent, controller.signal])
      : controller.signal,
    dispose() {
      if (timer) clearTimeout(timer);
    },
  };
}
