import type { Dispatch, SetStateAction } from "react";
import type { DisplayMessage } from "../agent-display";
import {
  tryParsePartialJson,
  extractStreamableContent,
} from "../shared/message-utils";
import { loadSubagents } from "../../../core/session/persistence";

export type SubagentStatus = "running" | "completed" | "failed" | "cancelled";

export const SUBAGENT_STATUS_ORDER: Record<SubagentStatus, number> = {
  running: 0,
  completed: 1,
  cancelled: 2,
  failed: 3,
};

export interface SubagentSession {
  id: string;
  name: string;
  status: SubagentStatus;
  spawnedAt: Date;
  completedAt?: Date;
  input: unknown;
  messages: DisplayMessage[];
  parentToolCallId?: string;
}

/**
 * Load subagent sessions from disk for a resumed session.
 * Reads subagents/*.json + agent-manifest.json and converts to SubagentSession entries.
 */
export function loadSubagentSessionsFromDisk(
  rootPath: string,
): Map<string, SubagentSession> {
  const uiSubagents = loadSubagents(rootPath);
  const map = new Map<string, SubagentSession>();

  for (const sub of uiSubagents) {
    const status: SubagentSession["status"] =
      sub.status === "completed" || sub.status === "failed"
        ? sub.status
        : "cancelled";

    const messages: DisplayMessage[] = sub.messages.map((m) =>
      m.role === "tool" && m.status === "pending"
        ? { ...m, status: "error" as const, result: "Interrupted" }
        : (m as DisplayMessage),
    );

    // Approximate completedAt from the last message timestamp so the hub
    // card shows the actual run duration instead of an ever-increasing
    // elapsed time. All restored sessions are non-running (they come from
    // a prior ended execution).
    const completedAt =
      messages.length > 0
        ? messages[messages.length - 1].createdAt
        : sub.createdAt;

    map.set(sub.id, {
      id: sub.id,
      name: sub.name,
      status,
      spawnedAt: sub.createdAt,
      completedAt,
      input: { target: sub.target },
      messages,
    });
  }

  return map;
}

type SetState = Dispatch<SetStateAction<Map<string, SubagentSession>>>;

/**
 * External subscribable store for subagent sessions.
 *
 * Bridges imperative updates (from stream handlers) and the SubagentDialog,
 * which is rendered inside a DialogProvider portal and can't receive React
 * prop updates from the dashboard tree. Consumers subscribe via
 * `useSyncExternalStore`.
 */
export interface SubagentStore {
  getSnapshot: () => Map<string, SubagentSession>;
  subscribe: (listener: () => void) => () => void;
  setState: SetState;
}

export function createSubagentStore(): SubagentStore {
  let snapshot: Map<string, SubagentSession> = new Map();
  const listeners = new Set<() => void>();
  const setState: SetState = (action) => {
    const next =
      typeof action === "function"
        ? (
            action as (
              prev: Map<string, SubagentSession>,
            ) => Map<string, SubagentSession>
          )(snapshot)
        : action;
    if (next === snapshot) return;
    snapshot = next;
    for (const l of listeners) l();
  };
  return {
    getSnapshot: () => snapshot,
    subscribe: (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    setState,
  };
}

/**
 * Creates helper functions for managing per-subagent session state.
 *
 * All helpers follow the React `setState(prev => ...)` pattern with
 * immutable updates (new Map + cloned SubagentSession objects).
 */
export function createSubagentSessionHelpers(setState: SetState) {
  // Streaming-delta buffers held outside the message shape so parser scratch
  // never leaks into `args`. Keyed by toolCallId; cleared on finalization.
  const toolArgsDeltaBuffers = new Map<string, { accumulated: string }>();

  const spawnSession = (id: string, name?: string, input?: unknown) => {
    setState((prev) => {
      const next = new Map(prev);
      next.set(id, {
        id,
        name: name ?? id,
        status: "running",
        spawnedAt: new Date(),
        input: input ?? null,
        messages: [],
      });
      return next;
    });
  };

  const appendText = (id: string, text: string) => {
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const messages = [...session.messages];
      const last = messages[messages.length - 1];

      if (last && last.role === "assistant") {
        const content =
          typeof last.content === "string" ? last.content + text : text;
        messages[messages.length - 1] = { ...last, content };
      } else {
        messages.push({
          role: "assistant",
          content: text,
          createdAt: new Date(),
        });
      }

      const next = new Map(prev);
      next.set(id, { ...session, messages });
      return next;
    });
  };

  const addStreamingToolCall = (
    id: string,
    toolCallId: string,
    toolName: string,
  ) => {
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const messages: DisplayMessage[] = [
        ...session.messages,
        {
          role: "tool",
          content: toolName,
          createdAt: new Date(),
          toolCallId,
          toolName,
          args: {},
          status: "streaming",
        },
      ];

      const next = new Map(prev);
      next.set(id, { ...session, messages });
      return next;
    });
  };

  const appendToolCallDelta = (
    id: string,
    toolCallId: string,
    argsTextDelta: string,
  ) => {
    const existing = toolArgsDeltaBuffers.get(toolCallId);
    const accumulated = (existing?.accumulated ?? "") + argsTextDelta;
    toolArgsDeltaBuffers.set(toolCallId, { accumulated });

    const parsed = tryParsePartialJson(accumulated);
    if (!parsed) return;

    const contentText = extractStreamableContent(parsed);
    const logs = contentText ? contentText.split("\n") : undefined;

    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const idx = session.messages.findIndex(
        (m) => m.role === "tool" && m.toolCallId === toolCallId,
      );
      if (idx === -1) return prev;

      const messages = [...session.messages];
      messages[idx] = {
        ...messages[idx],
        args: parsed,
        ...(logs && { logs }),
      };

      const next = new Map(prev);
      next.set(id, { ...session, messages });
      return next;
    });
  };

  const addToolCall = (
    id: string,
    toolCallId: string,
    toolName: string,
    args?: Record<string, unknown>,
  ) => {
    toolArgsDeltaBuffers.delete(toolCallId);
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const idx = session.messages.findIndex(
        (m) => m.role === "tool" && m.toolCallId === toolCallId,
      );

      const messages = [...session.messages];
      if (idx !== -1) {
        messages[idx] = {
          ...messages[idx],
          args,
          logs: undefined,
          status: "pending",
        };
      } else {
        messages.push({
          role: "tool",
          content: toolName,
          createdAt: new Date(),
          toolCallId,
          toolName,
          args,
          status: "pending",
        });
      }

      const next = new Map(prev);
      next.set(id, { ...session, messages });
      return next;
    });
  };

  const updateToolResult = (
    id: string,
    toolCallId: string,
    result: unknown,
  ) => {
    toolArgsDeltaBuffers.delete(toolCallId);
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const idx = session.messages.findIndex(
        (m) => m.role === "tool" && m.toolCallId === toolCallId,
      );
      if (idx === -1) return prev;

      const messages = [...session.messages];
      messages[idx] = { ...messages[idx], status: "completed", result };

      const next = new Map(prev);
      next.set(id, { ...session, messages });
      return next;
    });
  };

  const completeSession = (id: string, status: "completed" | "failed") => {
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      // Tools still in-flight when the session ends never received a
      // tool-result event, so we can't assert they succeeded. Mark as
      // error (with a clear label) so spinners stop and the UI doesn't
      // falsely claim success.
      const messages = session.messages.map((m) =>
        m.role === "tool" &&
        (m.status === "pending" || m.status === "streaming")
          ? {
              ...m,
              status: "error" as const,
              result: m.result ?? "No result recorded",
            }
          : m,
      );

      const next = new Map(prev);
      next.set(id, {
        ...session,
        status,
        completedAt: new Date(),
        messages,
      });
      return next;
    });
  };

  return {
    spawnSession,
    appendText,
    addStreamingToolCall,
    appendToolCallDelta,
    addToolCall,
    updateToolResult,
    completeSession,
  };
}
