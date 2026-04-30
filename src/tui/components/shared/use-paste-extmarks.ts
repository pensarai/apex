import { useRef } from "react";
import {
  decodePasteBytes,
  stripAnsiSequences,
  type PasteEvent,
  type TextareaRenderable,
} from "@opentui/core";

interface PasteEntry {
  fullText: string;
  placeholder: string;
}

const LARGE_PASTE_MIN_LINES = 5;
const LARGE_PASTE_MIN_CHARS = 500;

/**
 * Manages virtual extmarks for large pasted text.
 *
 * Large pastes are replaced with an atomic inline placeholder (e.g.
 * `[Pasted text #1 +17 lines]`). On submit the placeholder is expanded
 * back to the full text — unless the user has modified it.
 */
export function usePasteExtmarks(
  textareaRef: React.RefObject<TextareaRenderable | null>,
) {
  const countRef = useRef(0);
  const typeIdRef = useRef(-1);
  const dataRef = useRef<Map<number, PasteEntry>>(new Map());

  /** Reset all paste state and clear extmarks on the textarea. */
  const clearPaste = () => {
    textareaRef.current?.extmarks.clear();
    countRef.current = 0;
    dataRef.current.clear();
  };

  /**
   * Paste handler — pass directly to `<textarea onPaste={handlePaste}>`.
   * Intercepts large pastes (5+ lines or 500+ chars) and inserts a
   * virtual extmark placeholder instead.
   */
  const handlePaste = (event: PasteEvent) => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    const text = stripAnsiSequences(decodePasteBytes(event.bytes));
    const lineCount = text.split("\n").length;

    if (
      lineCount < LARGE_PASTE_MIN_LINES &&
      text.length < LARGE_PASTE_MIN_CHARS
    )
      return;

    event.preventDefault();

    if (typeIdRef.current === -1) {
      typeIdRef.current = textarea.extmarks.registerType("pasted-block");
    }

    countRef.current += 1;
    const placeholder = `[Pasted text #${countRef.current} +${lineCount} lines]`;

    const startOffset = textarea.cursorOffset;
    textarea.insertText(placeholder);
    const endOffset = startOffset + placeholder.length;

    const extmarkId = textarea.extmarks.create({
      start: startOffset,
      end: endOffset,
      virtual: true,
      typeId: typeIdRef.current,
    });
    dataRef.current.set(extmarkId, { fullText: text, placeholder });
  };

  /**
   * Expand paste placeholders in `plainText` back to the full pasted text.
   * Only expands placeholders whose text is still intact — if the user
   * modified the placeholder, the modified text is kept as-is.
   */
  const resolveText = (plainText: string): string => {
    const dataMap = dataRef.current;
    if (dataMap.size === 0) return plainText;

    const textarea = textareaRef.current;
    if (!textarea) return plainText;

    const allExtmarks = textarea.extmarks.getAll();
    const pasteExtmarks = allExtmarks.filter((ext) => dataMap.has(ext.id));
    if (pasteExtmarks.length === 0) return plainText;

    const sorted = [...pasteExtmarks].sort((a, b) => a.start - b.start);
    let result = "";
    let lastEnd = 0;
    for (const ext of sorted) {
      result += plainText.slice(lastEnd, ext.start);
      const entry = dataMap.get(ext.id)!;
      const currentText = plainText.slice(ext.start, ext.end);
      if (currentText === entry.placeholder) {
        result += entry.fullText;
      } else {
        result += currentText;
      }
      lastEnd = ext.end;
    }
    result += plainText.slice(lastEnd);
    return result;
  };

  return { handlePaste, resolveText, clearPaste } as const;
}
