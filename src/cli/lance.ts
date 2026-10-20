import { runLance } from "../core/api/lance";
import type { SessionInfo } from "../core/session";
import { createIpcObjectiveVerifier } from "./lance-verifier";
import { runWithCliNativeRolloutEvidence } from "./native-rollout-evidence";

export async function runCliLance(
  input: Parameters<typeof runLance>[0] & { session: SessionInfo },
) {
  const ipc = process.env.APEX_OBJECTIVE_VERIFIER_IPC;
  if (ipc !== undefined && ipc !== "1")
    throw new Error("Invalid Lance verifier IPC configuration");
  const verifier = ipc ? createIpcObjectiveVerifier() : undefined;
  const abort = new AbortController();
  const onSignal = () => abort.abort();
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);
  try {
    const evidence = await runWithCliNativeRolloutEvidence({
      session: input.session,
      outputDirectory:
        input.session.config?.nativeRolloutEvidence?.outputDirectory,
      run: () =>
        runLance({
          ...input,
          abortSignal: input.abortSignal
            ? AbortSignal.any([input.abortSignal, abort.signal])
            : abort.signal,
          lance: {
            ...input.lance,
            ...(verifier ? { verifyObjective: verifier.verifyObjective } : {}),
          },
        }),
    });
    const { result } = evidence.value;
    if (result.outcome === "error") process.exitCode = 1;
    console.log(`LANCE_RESULT:${JSON.stringify(result)}`);
    console.log(
      `METRICS:${JSON.stringify({ input_tokens: result.usage.inputTokens, output_tokens: result.usage.outputTokens, cached_tokens: result.usage.cacheReadTokens, cache_write_tokens: result.usage.cacheWriteTokens, tool_calls: result.toolCalls, request_count: result.usage.requests })}`,
    );
    if (evidence.manifestPath) {
      console.log(`Native evidence: ${evidence.manifestPath}`);
    }
  } finally {
    verifier?.close();
    process.off("SIGTERM", onSignal);
    process.off("SIGINT", onSignal);
  }
}
