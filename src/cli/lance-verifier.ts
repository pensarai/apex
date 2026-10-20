import type { LanceOptions, ObjectiveVerification } from "../core/agents/lance";

export function createIpcObjectiveVerifier() {
  if (!process.send || !process.connected)
    throw new Error(
      "Lance requires an inherited objective verifier IPC channel",
    );
  let sequence = 0;
  const verifyObjective: NonNullable<LanceOptions["verifyObjective"]> = (
    candidate,
    signal,
  ) =>
    new Promise((resolve, reject) => {
      const id = ++sequence;
      const cleanup = () => {
        process.off("message", onMessage);
        process.off("disconnect", onDisconnect);
        signal.removeEventListener("abort", onAbort);
      };
      const fail = (error: unknown) => {
        cleanup();
        reject(error);
      };
      const onDisconnect = () =>
        fail(new Error("Objective verifier disconnected"));
      const onAbort = () => fail(signal.reason);
      const onMessage = (message: unknown) => {
        const result = message as
          | (ObjectiveVerification & { id: number })
          | null;
        if (
          !result ||
          result.id !== id ||
          typeof result.verified !== "boolean" ||
          (result.objectiveComplete !== undefined &&
            typeof result.objectiveComplete !== "boolean") ||
          typeof result.verifierId !== "string" ||
          !result.verifierId ||
          (result.reason !== undefined &&
            (typeof result.reason !== "string" ||
              result.reason.length > 32_768))
        ) {
          fail(new Error("Invalid objective verifier response"));
          return;
        }
        cleanup();
        resolve(result);
      };
      if (signal.aborted) return onAbort();
      if (!process.connected) return onDisconnect();
      process.on("message", onMessage);
      process.once("disconnect", onDisconnect);
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        process.send!(
          { id, evidence: candidate.evidence },
          undefined,
          undefined,
          (error: Error | null) => {
            if (error) fail(error);
          },
        );
      } catch (error) {
        fail(error);
      }
    });
  return {
    verifyObjective,
    close: () => {
      if (process.connected) process.disconnect?.();
    },
  };
}
