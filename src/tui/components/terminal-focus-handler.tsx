/**
 * Terminal Focus Handler Component
 *
 * Sets up terminal focus event handling to ensure cursor visibility
 * and input focus are maintained when alt-tabbing or switching applications.
 */

import { useRenderer } from "@opentui/react";
import { useEffect } from "react";
import { useFocus } from "../context/focus";
import { setupTerminalFocusHandling } from "../terminal-focus";

/**
 * Component that sets up terminal focus handling.
 * Must be rendered inside FocusProvider to access refocusPrompt.
 */
export function TerminalFocusHandler() {
  const { refocusPrompt } = useFocus();
  const renderer = useRenderer();

  useEffect(() => {
    // Set up terminal focus handling with a callback to re-focus the prompt
    const cleanup = setupTerminalFocusHandling(renderer, {
      onTerminalFocus: refocusPrompt,
      debug: false, // Set to true for debugging
    });

    // Clean up on unmount
    return cleanup;
  }, [renderer, refocusPrompt]);

  // This component doesn't render anything
  return null;
}
