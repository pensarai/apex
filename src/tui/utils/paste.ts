import type { PasteEvent } from "@opentui/core";

/** Extract the pasted text from OpenTUI's `PasteEvent`. */
export function getPasteText(event: PasteEvent): string {
  return event.text;
}
