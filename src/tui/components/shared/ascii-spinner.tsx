/**
 * ASCII Spinner Component
 *
 * Simple spinner that works in all terminals.
 * Replaces 3 duplicate implementations across the codebase.
 */

import type { RGBA } from "@opentui/core";
import { useEffect, useState } from "react";
import { useTheme } from "../../theme";

const SPINNER_FRAMES = ["/", "-", "\\", "|"];
const SPINNER_INTERVAL = 100;

interface AsciiSpinnerProps {
  /** Label text to show after spinner */
  label: string;
  /** Optional custom color (defaults to info/toolColor) */
  fg?: RGBA;
}

/**
 * Animated ASCII spinner for pending operations.
 */
export function AsciiSpinner({ label, fg }: AsciiSpinnerProps) {
  const { colors } = useTheme();
  const spinnerColor = fg ?? colors.info;
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((f) => (f + 1) % SPINNER_FRAMES.length);
    }, SPINNER_INTERVAL);
    return () => clearInterval(interval);
  }, []);

  return (
    <text fg={spinnerColor} content={`${SPINNER_FRAMES[frame]} ${label}`} />
  );
}

export default AsciiSpinner;
