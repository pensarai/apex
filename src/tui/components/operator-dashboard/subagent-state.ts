import type { Dispatch, SetStateAction } from "react";
import type { DisplayMessage } from "../agent-display";
import {
  tryParsePartialJson,
  extractStreamableContent,
} from "../shared/message-utils";

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
      const existingRaw =
        (msg.args as Record<string, unknown> | undefined)?.__raw;
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

      const next = new Map(prev);
      next.set(id, {
        ...session,
        status,
        completedAt: new Date(),
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
