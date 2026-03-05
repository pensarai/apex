import type { ParsedKey } from "@opentui/core";

export type OperatorDashboardStatus = "idle" | "running" | "waiting" | "done";

type KeyboardKey = Pick<ParsedKey, "name" | "ctrl" | "meta" | "super">;

/**
 * Terminal copy shortcuts (Cmd+C on macOS / Super+C variants) should not be
 * hijacked by operator-level Ctrl+C handling.
 */
export function isTerminalCopyShortcut(key: KeyboardKey): boolean {
  return (Boolean(key.meta) || Boolean(key.super)) && key.name === "c";
}

/**
 * Operator dashboard should only consume Ctrl+C when it maps to an operator
 * action (stop active run or clear non-empty input).
 */
export function shouldHandleOperatorCtrlC(
  key: KeyboardKey,
  status: OperatorDashboardStatus,
  inputValue: string,
): boolean {
  if (isTerminalCopyShortcut(key)) return false;
  if (!key.ctrl || key.name !== "c") return false;
  return status === "running" || status === "waiting" || inputValue.trim() !== "";
}
