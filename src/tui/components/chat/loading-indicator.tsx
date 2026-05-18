/**
 * Loading Indicator Component
 *
 * Animated spinner with contextual messages for agent states.
 */

import { useEffect, useRef, useState } from "react";
import { INTERNAL_ID_PATTERN } from "../../../core/operator";
import { useTheme } from "../../theme";

// Braille spinner frames for smooth animation
const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL = 80;

// Dots animation for "thinking" effect
const DOTS_FRAMES = ["", ".", "..", "..."];
const DOTS_INTERVAL = 400;

export type LoadingState = "thinking" | "executing" | "streaming" | "waiting";

interface LoadingIndicatorProps {
  /** Current loading state */
  state: LoadingState;
  /** Optional action description (for executing state) */
  action?: string | null;
  /** Optional tool name being executed */
  toolName?: string | null;
}

/**
 * Animated loading indicator with contextual messages
 */
export function LoadingIndicator({
  state,
  action,
  toolName,
}: LoadingIndicatorProps) {
  const { colors } = useTheme();
  const [spinnerFrame, setSpinnerFrame] = useState(0);
  const [dotsFrame, setDotsFrame] = useState(0);
  const warnedIdsRef = useRef<Set<string>>(new Set());

  // Spinner animation
  useEffect(() => {
    const interval = setInterval(() => {
      setSpinnerFrame((f) => (f + 1) % SPINNER_FRAMES.length);
    }, SPINNER_INTERVAL);
    return () => clearInterval(interval);
  }, []);

  // Dots animation
  useEffect(() => {
    const interval = setInterval(() => {
      setDotsFrame((f) => (f + 1) % DOTS_FRAMES.length);
    }, DOTS_INTERVAL);
    return () => clearInterval(interval);
  }, []);

  const spinner = SPINNER_FRAMES[spinnerFrame];
  const dots = DOTS_FRAMES[dotsFrame];

  // Build the message based on state
  const getMessage = () => {
    switch (state) {
      case "thinking":
        return `Thinking${dots}`;
      case "streaming":
        return `Responding${dots}`;
      case "waiting":
        return `Waiting for agents${dots}`;
      case "executing":
        if (action && !INTERNAL_ID_PATTERN.test(action)) {
          return action;
        }
        if (
          action &&
          process.env.NODE_ENV !== "production" &&
          !warnedIdsRef.current.has(action)
        ) {
          warnedIdsRef.current.add(action);
          console.warn(
            `[LoadingIndicator] internal correlation ID leaked into action prop: ${action}`,
          );
        }
        if (toolName) {
          return `Running ${toolName}${dots}`;
        }
        return `Executing${dots}`;
      default:
        return `Working${dots}`;
    }
  };

  const getColor = () => {
    switch (state) {
      case "thinking":
        return colors.warning;
      case "streaming":
        return colors.primary;
      case "waiting":
        return colors.info;
      case "executing":
        return colors.info;
      default:
        return colors.textMuted;
    }
  };

  return (
    <box flexDirection="row" marginTop={1} marginLeft={2} gap={1}>
      <text fg={getColor()}>{spinner}</text>
      <text fg={colors.textMuted}>{getMessage()}</text>
    </box>
  );
}
