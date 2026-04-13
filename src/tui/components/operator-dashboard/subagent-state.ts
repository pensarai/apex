import type { Dispatch, SetStateAction } from "react";
import type { DisplayMessage } from "../agent-display";
import {
  tryParsePartialJson,
  extractStreamableContent,
} from "../shared/message-utils";
import { loadSubagents } from "../../../core/session/persistence";

export interface SubagentSession {
  id: string;
  name: string;
  status: "running" | "completed" | "failed";
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
    // Map UISubagent status to SubagentSession status
    let status: SubagentSession["status"];
    switch (sub.status) {
      case "completed":
        status = "completed";
        break;
      case "failed":
      case "canceled":
        status = "failed";
        break;
      case "pending":
      case "paused":
      default:
        status = "failed";
        break;
    }

    // Convert UIMessage[] to DisplayMessage[] (same shape, just need createdAt)
    const messages: DisplayMessage[] = sub.messages.map((m) => ({
      role: m.role,
      content: m.content,
      createdAt: m.createdAt,
      toolCallId: m.toolCallId,
      toolName: m.toolName,
      args: m.args,
      result: m.result,
      status: m.status,
    }));

    map.set(sub.id, {
      id: sub.id,
      name: sub.name,
      status,
      spawnedAt: sub.createdAt,
      input: { target: sub.target },
      messages,
    });
  }

  return map;
}

type SetState = Dispatch<SetStateAction<Map<string, SubagentSession>>>;

/**
 * Creates helper functions for managing per-subagent session state.
 *
 * All helpers follow the React `setState(prev => ...)` pattern with
 * immutable updates (new Map + cloned SubagentSession objects).
 */
export function createSubagentSessionHelpers(setState: SetState) {
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
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const idx = session.messages.findIndex(
        (m) => m.role === "tool" && m.toolCallId === toolCallId,
      );
      if (idx === -1) return prev;

      const msg = session.messages[idx];
      // Accumulate the args text. We store partial JSON in args.__raw if
      // present, otherwise start fresh.
      const existingRaw = (msg.args as Record<string, unknown> | undefined)
        ?.__raw;
      const accumulated =
        (typeof existingRaw === "string" ? existingRaw : "") + argsTextDelta;

      const parsed = tryParsePartialJson(accumulated);
      const argsObj: Record<string, unknown> = parsed
        ? { ...parsed, __raw: accumulated }
        : { __raw: accumulated };

      const contentText = parsed ? extractStreamableContent(parsed) : null;
      const logs = contentText ? contentText.split("\n") : undefined;

      const messages = [...session.messages];
      messages[idx] = { ...msg, args: argsObj, ...(logs && { logs }) };

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
    setState((prev) => {
      const session = prev.get(id);
      if (!session) return prev;

      const idx = session.messages.findIndex(
        (m) => m.role === "tool" && m.toolCallId === toolCallId,
      );

      const messages = [...session.messages];
      if (idx !== -1) {
        // Strip __raw from finalized args
        const cleanArgs = args ? { ...args } : undefined;
        if (cleanArgs) delete cleanArgs.__raw;
        messages[idx] = {
          ...messages[idx],
          args: cleanArgs,
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
    _toolName: string,
    result: unknown,
  ) => {
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

      // Mark any in-flight tool messages as completed/error so spinners stop
      const messages = session.messages.map((m) =>
        m.role === "tool" &&
        (m.status === "pending" || m.status === "streaming")
          ? {
              ...m,
              status: (status === "failed" ? "error" : "completed") as
                | "error"
                | "completed",
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
