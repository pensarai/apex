export type CtrlCAction = "clear-input" | "warn-exit" | "exit";

export function resolveCtrlCAction(
  inputValue: string,
  inputFocused: boolean,
  lastPressTime: number | null,
  now: number,
): CtrlCAction {
  if (inputFocused && inputValue.trim()) return "clear-input";
  if (lastPressTime && now - lastPressTime < 1_000) return "exit";
  return "warn-exit";
}
