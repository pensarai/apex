/**
 * useAgentMessages Hook
 *
 * Encapsulates the message accumulation pattern (text deltas, tool calls,
 * tool results) used by agent-driven UI components. Each call manages one
 * independent message list with its own text buffer.
 *
 * For multi-context usage (e.g., pentest subagents keyed by ID), callers
 * should manage a Record/Map of state externally and reuse the exported
 * `toolResultUpdater` pure function.
 */

import { useState, useCallback, useRef } from "react";
import type { DisplayMessage } from "../components/agent-display";
import { isToolMessage } from "../components/shared/type-guards";

// ---------------------------------------------------------------------------
// Pure function — module-level, reusable outside of React
// ---------------------------------------------------------------------------

/**
 * Apply a tool result to a message list.
 *
 * If the matching tool-call message is found, its status is set to
 * "completed" and the result is attached.  If not found, a new completed
 * tool message is appended as a fallback so the result is never lost.
 */
export function toolResultUpdater(
  messages: DisplayMessage[],
  toolCallId: string,
  toolName: string,
  result?: unknown,
): DisplayMessage[] {
  const idx = messages.findIndex(
    (m) => isToolMessage(m) && m.toolCallId === toolCallId,
  );

  if (idx !== -1) {
    const updated = [...messages];
    updated[idx] = {
      ...updated[idx]!,
      status: "completed" as const,
      result,
    };
    return updated;
  }

  // Fallback: create a completed message if the tool call was never recorded
  return [
    ...messages,
    {
      role: "tool" as const,
      content: toolName,
      toolCallId,
      toolName,
      status: "completed" as const,
      result,
      createdAt: new Date(),
    },
  ];
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseAgentMessagesReturn {
  /** Current message list (React state — triggers re-renders). */
  messages: DisplayMessage[];
  /** Append a text delta to the current assistant message. */
  appendText: (text: string) => void;
  /** Add a new pending tool-call message (with dedup guard). */
  addToolCall: (
    toolCallId: string,
    toolName: string,
    args?: Record<string, unknown>,
  ) => void;
  /** Mark a tool call as completed with its result. */
  updateToolResult: (
    toolCallId: string,
    toolName: string,
    result?: unknown,
  ) => void;
  /** Append a system message (e.g., errors, status notices). */
  addSystemMessage: (content: string) => void;
  /** Append an arbitrary message (e.g., user messages). */
  addMessage: (msg: DisplayMessage) => void;
  /** Reset messages and the text buffer. */
  clear: () => void;
}

/**
 * Hook that manages a single independent message list with ref-based text
 * accumulation to avoid unnecessary re-renders during streaming.
 */
export function useAgentMessages(): UseAgentMessagesReturn {
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const textRef = useRef("");

  // -- appendText ------------------------------------------------------------
  const appendText = useCallback((text: string) => {
    textRef.current += text;
    const accumulated = textRef.current;
    setMessages((prev) => {
      const last = prev[prev.length - 1];
      if (last && last.role === "assistant") {
        const updated = [...prev];
        updated[updated.length - 1] = { ...last, content: accumulated };
        return updated;
      }
      return [
        ...prev,
        {
          role: "assistant" as const,
          content: accumulated,
          createdAt: new Date(),
        },
      ];
    });
  }, []);

  // -- addToolCall -----------------------------------------------------------
  const addToolCall = useCallback(
    (toolCallId: string, toolName: string, args?: Record<string, unknown>) => {
      textRef.current = "";

      const description =
        typeof args?.toolCallDescription === "string"
          ? args.toolCallDescription
          : toolName;

      const msg: DisplayMessage = {
        role: "tool",
        content: description,
        toolCallId,
        toolName,
        args,
        status: "pending",
        createdAt: new Date(),
      };

      setMessages((prev) => {
        // Duplicate guard — don't add the same tool call twice
        if (prev.some((m) => m.toolCallId === toolCallId)) return prev;
        return [...prev, msg];
      });
    },
    [],
  );

  // -- updateToolResult ------------------------------------------------------
  const updateToolResult = useCallback(
    (toolCallId: string, toolName: string, result?: unknown) => {
      textRef.current = "";
      setMessages((prev) =>
        toolResultUpdater(prev, toolCallId, toolName, result),
      );
    },
    [],
  );

  // -- addSystemMessage ------------------------------------------------------
  const addSystemMessage = useCallback((content: string) => {
    textRef.current = "";
    setMessages((prev) => [
      ...prev,
      {
        role: "system" as const,
        content,
        createdAt: new Date(),
      },
    ]);
  }, []);

  // -- addMessage -------------------------------------------------------------
  const addMessage = useCallback((msg: DisplayMessage) => {
    textRef.current = "";
    setMessages((prev) => [...prev, msg]);
  }, []);

  // -- clear -----------------------------------------------------------------
  const clear = useCallback(() => {
    textRef.current = "";
    setMessages([]);
  }, []);

  return {
    messages,
    appendText,
    addToolCall,
    updateToolResult,
    addSystemMessage,
    addMessage,
    clear,
  };
}
