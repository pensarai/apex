import type { Renderable } from "@opentui/core";

export type FocusOwner = Pick<Renderable, "isDestroyed">;

export function shouldRefocusPrompt(
  currentFocus: FocusOwner | null,
  prompt: FocusOwner | null,
): boolean {
  return (
    currentFocus === null || currentFocus === prompt || currentFocus.isDestroyed
  );
}
