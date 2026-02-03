/**
 * Message State Reducer
 *
 * Centralized state management for messages with O(1) lookup by toolCallId.
 * Fixes race conditions by using toolCallId for updates instead of array index.
 */

import { useReducer, useCallback, useMemo } from "react";
import type { DisplayMessage, ToolStatus } from "../agent-display";
import { isToolMessage } from "./type-guards";

/**
 * State structure with both array and lookup map.
 */
interface MessageState {
  messages: DisplayMessage[];
  /** O(1) lookup by toolCallId for tool messages */
  toolCallIndex: Map<string, number>;
}

/**
 * Actions for message state updates.
 */
type MessageAction =
  | { type: "ADD_MESSAGE"; message: DisplayMessage }
  | {
      type: "UPDATE_TOOL";
      toolCallId: string;
      updates: Partial<{
        status: ToolStatus;
        result: unknown;
        logs: string[];
      }>;
    }
  | { type: "UPDATE_BY_INDEX"; index: number; message: DisplayMessage }
  | { type: "CLEAR_MESSAGES" }
  | { type: "SET_MESSAGES"; messages: DisplayMessage[] };

/**
 * Reducer function for message state.
 */
function messageReducer(state: MessageState, action: MessageAction): MessageState {
  switch (action.type) {
    case "ADD_MESSAGE": {
      const newMessages = [...state.messages, action.message];
      const newIndex = new Map(state.toolCallIndex);

      // Track tool message index for O(1) updates
      if (isToolMessage(action.message)) {
        newIndex.set(action.message.toolCallId, newMessages.length - 1);
      }

      return {
        messages: newMessages,
        toolCallIndex: newIndex,
      };
    }

    case "UPDATE_TOOL": {
      const idx = state.toolCallIndex.get(action.toolCallId);
      if (idx === undefined) {
        // Tool not found, return unchanged
        return state;
      }

      const newMessages = [...state.messages];
      const existing = newMessages[idx];

      if (isToolMessage(existing)) {
        newMessages[idx] = {
          ...existing,
          ...action.updates,
        };
      }

      return {
        ...state,
        messages: newMessages,
      };
    }

    case "UPDATE_BY_INDEX": {
      if (action.index < 0 || action.index >= state.messages.length) {
        return state;
      }

      const newMessages = [...state.messages];
      newMessages[action.index] = action.message;

      // Update toolCallIndex if this is a tool message
      const newIndex = new Map(state.toolCallIndex);
      if (isToolMessage(action.message)) {
        newIndex.set(action.message.toolCallId, action.index);
      }

      return {
        messages: newMessages,
        toolCallIndex: newIndex,
      };
    }

    case "CLEAR_MESSAGES":
      return {
        messages: [],
        toolCallIndex: new Map(),
      };

    case "SET_MESSAGES": {
      // Rebuild index from messages
      const newIndex = new Map<string, number>();
      action.messages.forEach((msg, idx) => {
        if (isToolMessage(msg)) {
          newIndex.set(msg.toolCallId, idx);
        }
      });

      return {
        messages: action.messages,
        toolCallIndex: newIndex,
      };
    }

    default:
      return state;
  }
}

/**
 * Initial state factory.
 */
function createInitialState(initialMessages?: DisplayMessage[]): MessageState {
  const messages = initialMessages || [];
  const toolCallIndex = new Map<string, number>();

  messages.forEach((msg, idx) => {
    if (isToolMessage(msg)) {
      toolCallIndex.set(msg.toolCallId, idx);
    }
  });

  return { messages, toolCallIndex };
}

/**
 * Hook for message state management.
 *
 * Provides O(1) lookups by toolCallId and prevents race conditions
 * when updating messages.
 */
export function useMessageState(initialMessages?: DisplayMessage[]) {
  const [state, dispatch] = useReducer(
    messageReducer,
    initialMessages,
    createInitialState
  );

  const addMessage = useCallback((message: DisplayMessage) => {
    dispatch({ type: "ADD_MESSAGE", message });
    return state.messages.length; // Return new index
  }, [state.messages.length]);

  const updateTool = useCallback(
    (
      toolCallId: string,
      updates: Partial<{ status: ToolStatus; result: unknown; logs: string[] }>
    ) => {
      dispatch({ type: "UPDATE_TOOL", toolCallId, updates });
    },
    []
  );

  const updateByIndex = useCallback(
    (index: number, message: DisplayMessage) => {
      dispatch({ type: "UPDATE_BY_INDEX", index, message });
    },
    []
  );

  const clearMessages = useCallback(() => {
    dispatch({ type: "CLEAR_MESSAGES" });
  }, []);

  const setMessages = useCallback((messages: DisplayMessage[]) => {
    dispatch({ type: "SET_MESSAGES", messages });
  }, []);

  const findToolByCallId = useCallback(
    (toolCallId: string): DisplayMessage | undefined => {
      const idx = state.toolCallIndex.get(toolCallId);
      return idx !== undefined ? state.messages[idx] : undefined;
    },
    [state.messages, state.toolCallIndex]
  );

  // Memoize check for pending tools in recent messages
  const hasPendingTool = useMemo(() => {
    const recentMessages = state.messages.slice(-5);
    return recentMessages.some(
      (m) => isToolMessage(m) && m.status === "pending"
    );
  }, [state.messages]);

  return {
    messages: state.messages,
    addMessage,
    updateTool,
    updateByIndex,
    clearMessages,
    setMessages,
    findToolByCallId,
    hasPendingTool,
  };
}
