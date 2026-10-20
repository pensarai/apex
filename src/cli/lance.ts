import { runLance } from "../core/api/lance";
import { createIpcObjectiveVerifier } from "./lance-verifier";

export async function runCliLance(input: Parameters<typeof runLance>[0]) {
  const ipc = process.env.APEX_OBJECTIVE_VERIFIER_IPC;
  if (ipc !== undefined && ipc !== "1")
    throw new Error("Invalid Lance verifier IPC configuration");
  const verifier = ipc ? createIpcObjectiveVerifier() : undefined;
  const abort = new AbortController();
  const onSignal = () => abort.abort();
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);
  try {
    const { result } = await runLance({
      ...input,
      abortSignal: input.abortSignal
        ? AbortSignal.any([input.abortSignal, abort.signal])
        : abort.signal,
      lance: {
        ...input.lance,
        ...(verifier ? { verifyObjective: verifier.verifyObjective } : {}),
      },
    });
    if (result.outcome === "error") process.exitCode = 1;
    console.log(`LANCE_RESULT:${JSON.stringify(result)}`);
    console.log(
      `METRICS:${JSON.stringify({ input_tokens: result.usage.inputTokens, output_tokens: result.usage.outputTokens, cached_tokens: result.usage.cacheReadTokens, cache_write_tokens: result.usage.cacheWriteTokens, tool_calls: result.toolCalls, request_count: result.usage.requests })}`,
    );
  } finally {
    verifier?.close();
    process.off("SIGTERM", onSignal);
    process.off("SIGINT", onSignal);
  }
}
