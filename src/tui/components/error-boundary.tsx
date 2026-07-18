import React, { useCallback } from "react";
import { createLogger } from "../../core/logger/structured";
import { scopedLogger } from "../../core/util/lazyLogger";
import { useToast } from "../context/toast";
import { useTheme } from "../theme";

const MAX_ERRORS = 3;
const ERROR_WINDOW_MS = 5000;
const log = scopedLogger(() => createLogger("tui:error-boundary"));

interface ErrorBoundaryInnerProps {
  children?: React.ReactNode;
  fallback: (message: string) => React.ReactNode;
  onError: (message: string) => void;
}

interface ErrorBoundaryInnerState {
  hasError: boolean;
  errorTimestamps: number[];
  halted: boolean;
  lastError: string;
}

class ErrorBoundaryInner extends React.Component<
  ErrorBoundaryInnerProps,
  ErrorBoundaryInnerState
> {
  override state: ErrorBoundaryInnerState = {
    hasError: false,
    errorTimestamps: [],
    halted: false,
    lastError: "Unknown rendering error",
  };

  static getDerivedStateFromError(): Pick<ErrorBoundaryInnerState, "hasError"> {
    return { hasError: true };
  }

  override componentDidCatch(error: Error) {
    log.error("Render error", error);
    this.props.onError(error.message);

    const now = Date.now();
    const recent = [...this.state.errorTimestamps, now].filter(
      (t) => now - t < ERROR_WINDOW_MS,
    );

    if (recent.length >= MAX_ERRORS) {
      this.props.onError(
        "Too many errors in quick succession — UI recovery halted.",
      );
      this.setState({
        halted: true,
        hasError: false,
        errorTimestamps: recent,
        lastError: error.message,
      });
      return;
    }

    this.setState({ hasError: false, errorTimestamps: recent });
  }

  override render() {
    if (this.state.halted) {
      return this.props.fallback(this.state.lastError);
    }
    return this.props.children;
  }
}

/**
 * Functional wrapper that bridges the useToast hook into the class-based
 * ErrorBoundary. Uses React.createElement to avoid @opentui/react JSX
 * type mismatch with class components.
 */
export function ErrorBoundary({ children }: { children: React.ReactNode }) {
  const { toast } = useToast();
  const { colors } = useTheme();

  const handleError = useCallback(
    (message: string) => {
      toast(message, "error");
    },
    [toast],
  );

  return React.createElement(
    ErrorBoundaryInner,
    {
      onError: handleError,
      fallback: (message: string) => (
        <box
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          width="100%"
          height="100%"
          gap={1}
          padding={2}
          overflow="hidden"
        >
          <text fg={colors.error}>Apex could not recover this view</text>
          <text fg={colors.textMuted}>{message}</text>
          <text fg={colors.textMuted}>Press Ctrl+C to exit safely.</text>
        </box>
      ),
    },
    children,
  );
}
