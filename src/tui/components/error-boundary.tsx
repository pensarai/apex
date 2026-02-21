import React, { useCallback } from "react";
import { useToast } from "../context/toast";
import { writeErrorLog } from "../../core/logger";

const MAX_ERRORS = 3;
const ERROR_WINDOW_MS = 5000;

interface ErrorBoundaryInnerProps {
  children?: React.ReactNode;
  onError: (message: string) => void;
}

interface ErrorBoundaryInnerState {
  hasError: boolean;
  errorTimestamps: number[];
  halted: boolean;
}

class ErrorBoundaryInner extends React.Component<
  ErrorBoundaryInnerProps,
  ErrorBoundaryInnerState
> {
  override state: ErrorBoundaryInnerState = {
    hasError: false,
    errorTimestamps: [],
    halted: false,
  };

  static getDerivedStateFromError(): Pick<ErrorBoundaryInnerState, "hasError"> {
    return { hasError: true };
  }

  override componentDidCatch(error: Error) {
    console.error("[ErrorBoundary]", error);
    writeErrorLog(error, "TUI");
    this.props.onError(error.message);

    const now = Date.now();
    const recent = [...this.state.errorTimestamps, now].filter(
      (t) => now - t < ERROR_WINDOW_MS,
    );

    if (recent.length >= MAX_ERRORS) {
      this.setState({ halted: true, errorTimestamps: recent });
      return;
    }

    this.setState({ hasError: false, errorTimestamps: recent });
  }

  override render() {
    if (this.state.halted) {
      return null;
    }
    if (this.state.hasError) {
      return null;
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

  const handleError = useCallback(
    (message: string) => {
      toast(message, "error");
    },
    [toast],
  );

  return React.createElement(
    ErrorBoundaryInner,
    { onError: handleError },
    children,
  );
}
