import { useEffect } from "react";
import { useRenderer } from "@opentui/react";
import { useFocus } from "../context/focus";

/**
 * Re-focuses the prompt input when the terminal window regains focus (e.g. after alt-tab).
 * OpenTUI already handles cursor restoration via restoreTerminalModes on focus-in;
 * this component only needs to re-focus the prompt so keyboard input works again.
 */
export function TerminalFocusHandler() {
  const renderer = useRenderer();
  const { refocusPrompt } = useFocus();

  useEffect(() => {
    const handleFocus = () => refocusPrompt();
    renderer.on("focus", handleFocus);
    return () => {
      renderer.off("focus", handleFocus);
    };
  }, [renderer, refocusPrompt]);

  return null;
}
