import type { OperatorSnapshot } from "./contract";

const surfaceTools = new Set([
  "document_boundary",
  "document_component",
  "document_flow",
  "document_control",
  "document_threat",
  "review_topology",
  "update_record",
  "merge_records",
  "retire_record",
]);

export function hasSurfaceToolCall(snapshot: OperatorSnapshot): boolean {
  const matches = (messages: OperatorSnapshot["messages"]) =>
    messages.some(
      (message) =>
        message.role === "tool" &&
        !!message.toolName &&
        surfaceTools.has(message.toolName),
    );
  return (
    matches(snapshot.messages) ||
    snapshot.subagents.some((agent) => matches(agent.messages))
  );
}

type RevealStorage = Pick<Storage, "getItem" | "setItem">;

export function createSurfaceRevealState(storage: () => RevealStorage) {
  const shown = new Set<string>();
  const key = (sessionId: string) => `apex:attack-surface:shown:${sessionId}`;
  const markShown = (sessionId: string) => {
    shown.add(sessionId);
    try {
      storage().setItem(key(sessionId), "1");
    } catch {
      // Keep the once-per-session behavior in memory when webview storage is unavailable.
    }
  };
  return {
    markShown,
    claim(sessionId: string): boolean {
      if (shown.has(sessionId)) return false;
      try {
        if (storage().getItem(key(sessionId)) === "1") {
          shown.add(sessionId);
          return false;
        }
      } catch {
        // The in-memory set still protects sessions in this app run.
      }
      markShown(sessionId);
      return true;
    },
  };
}

export const surfaceReveal = createSurfaceRevealState(
  () => window.localStorage,
);
