import type { PasteEvent } from "@opentui/core";

const textDecoder = new TextDecoder();

/** Decode pasted bytes from OpenTUI's `PasteEvent` to a JavaScript string. */
export function getPasteText(event: PasteEvent): string {
  return textDecoder.decode(event.bytes);
}
