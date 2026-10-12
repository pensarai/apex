import { buildAuthConfig } from "../ai";
import { config } from "../config";
import { serveLocalRunWorker as serveWorker } from "../runtime/localRunWorker";
import { resumeRecordedAgent, runRecordedAgent } from "./recordedRun";

export async function serveLocalRunWorker(input: {
  runId: string;
  databasePath: string;
}): Promise<void> {
  const authConfig = buildAuthConfig(await config.get());
  await serveWorker({
    ...input,
    execute: ({ request, store, signal }) =>
      request.method === "start"
        ? runRecordedAgent({
            spec: request.spec,
            store,
            authConfig,
            abortSignal: signal,
          })
        : resumeRecordedAgent({
            runId: input.runId,
            expectedAttemptId: request.expectedAttemptId,
            store,
            authConfig,
            abortSignal: signal,
          }),
  });
}
