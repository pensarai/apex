/**
 * Terminal Focus Management
 *
 * Handles terminal window focus/blur events to ensure the cursor remains visible
 * and input stays focused when alt-tabbing or switching between applications.
 *
 * This is necessary because:
 * 1. When you alt-tab away, the terminal may hide the cursor
 * 2. When you return, the terminal needs to explicitly re-show the cursor
 * 3. The input field needs to be re-focused to accept keyboard input
 */

import type { CliRenderer } from "@opentui/core";

export interface TerminalFocusOptions {
  /** Callback to re-focus the prompt input when terminal regains focus */
  onTerminalFocus?: () => void;
  /** Enable debug logging */
  debug?: boolean;
}

/**
 * Track whether bracketed focus mode is currently enabled.
 * This is used to ensure we only disable it if we enabled it.
 */
let bracketedFocusModeEnabled = false;

/**
 * Set up terminal focus event handling.
 * Returns a cleanup function that removes all listeners.
 */
export function setupTerminalFocusHandling(
  renderer: CliRenderer,
  options: TerminalFocusOptions = {},
): () => void {
  const { onTerminalFocus, debug = false } = options;

  const log = (...args: unknown[]) => {
    if (debug) console.error("[TerminalFocus]", ...args);
  };

  // Enable bracketed focus mode
  // This tells the terminal to send \x1b[I when focused and \x1b[O when unfocused
  // See: https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h3-FocusIn_FocusOut
  const enableBracketedFocus = () => {
    if (process.stdout.isTTY) {
      process.stdout.write("\x1b[?1004h");
      bracketedFocusModeEnabled = true;
      log("Enabled bracketed focus mode");
    }
  };

  const disableBracketedFocus = () => {
    if (process.stdout.isTTY && bracketedFocusModeEnabled) {
      process.stdout.write("\x1b[?1004l");
      bracketedFocusModeEnabled = false;
      log("Disabled bracketed focus mode");
    }
  };

  // Show cursor explicitly using DECTCEM escape sequence
  const showCursor = () => {
    if (process.stdout.isTTY) {
      process.stdout.write("\x1b[?25h");
      log("Showed cursor");
    }
  };

  // Handle terminal gaining focus
  const handleFocusIn = () => {
    log("Terminal gained focus");
    showCursor();
    renderer.requestRender();

    // Re-focus the input after a short delay to ensure the terminal is ready
    if (onTerminalFocus) {
      setTimeout(() => {
        onTerminalFocus();
        log("Re-focused prompt input");
      }, 10);
    }
  };

  // Handle terminal losing focus
  const handleFocusOut = () => {
    log("Terminal lost focus");
    // We don't hide the cursor on focus out because it can cause issues
    // The terminal emulator will handle cursor visibility on its own
  };

  // Handle SIGCONT (terminal resume after being suspended)
  const handleSigCont = () => {
    log("Received SIGCONT (terminal resumed)");
    showCursor();
    renderer.requestRender();

    if (onTerminalFocus) {
      setTimeout(() => {
        onTerminalFocus();
        log("Re-focused prompt input after SIGCONT");
      }, 10);
    }
  };

  // Listen for bracketed focus events on stdin
  let stdinListenerActive = false;
  const handleStdinData = (data: Buffer) => {
    const str = data.toString();

    // Focus in event: \x1b[I
    if (str.includes("\x1b[I")) {
      handleFocusIn();
    }

    // Focus out event: \x1b[O
    if (str.includes("\x1b[O")) {
      handleFocusOut();
    }
  };

  // Set up listeners
  const setupListeners = () => {
    // Enable bracketed focus mode
    enableBracketedFocus();

    // Show cursor initially
    showCursor();

    // Listen for SIGCONT (resume after suspend)
    process.on("SIGCONT", handleSigCont);

    // Listen for bracketed focus events on stdin
    // Note: We need to be careful not to interfere with OpenTUI's stdin handling
    // We only listen for specific escape sequences
    if (process.stdin.isTTY && !stdinListenerActive) {
      process.stdin.on("data", handleStdinData);
      stdinListenerActive = true;
      log("Set up stdin listener for bracketed focus events");
    }
  };

  // Clean up function
  const cleanup = () => {
    log("Cleaning up terminal focus handling");

    // Disable bracketed focus mode
    disableBracketedFocus();

    // Remove listeners
    process.off("SIGCONT", handleSigCont);

    if (stdinListenerActive) {
      process.stdin.off("data", handleStdinData);
      stdinListenerActive = false;
    }
  };

  // Set up listeners
  setupListeners();

  return cleanup;
}

/**
 * Global cleanup function to disable bracketed focus mode.
 * This MUST be called before process.exit() to prevent leaving the terminal
 * in focus reporting mode, which causes garbage characters in the user's shell.
 */
export function cleanupTerminalFocusMode(): void {
  if (process.stdout.isTTY && bracketedFocusModeEnabled) {
    process.stdout.write("\x1b[?1004l");
    bracketedFocusModeEnabled = false;
  }
}
