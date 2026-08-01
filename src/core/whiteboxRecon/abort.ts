export function throwIfReconAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  if (signal.reason instanceof Error) throw signal.reason;
  const error = new Error(String(signal.reason ?? "Whitebox recon aborted"));
  error.name = "AbortError";
  throw error;
}
