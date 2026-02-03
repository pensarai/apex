/**
 * Shared Markdown Utilities
 *
 * Converts markdown text to StyledText for terminal rendering.
 * Merged from agent-display.tsx and chat-message.tsx implementations.
 */

import {
  RGBA,
  TextAttributes,
  StyledText,
  type TextChunk,
} from "@opentui/core";
import { marked } from "marked";

// Shared color constants
export const codeColor = RGBA.fromInts(100, 255, 100, 255); // green for code
export const linkColor = RGBA.fromInts(100, 200, 255, 255); // cyan for links

/**
 * Convert markdown content to StyledText for terminal rendering.
 *
 * Supports:
 * - Bold (**text**)
 * - Italic (*text*)
 * - Code spans (`code`)
 * - Code blocks (```)
 * - Links [text](url)
 * - Headings (#, ##, etc.)
 * - Lists (-, *, numbered)
 * - Blockquotes (>)
 * - Paragraphs
 */
export function markdownToStyledText(content: string): StyledText {
  // Handle empty or whitespace-only content
  if (!content || !content.trim()) {
    return new StyledText([
      { __isChunk: true, text: content || "", attributes: 0 },
    ]);
  }

  try {
    const tokens = marked.lexer(content);
    const chunks: TextChunk[] = [];

    function processInlineTokens(
      inlineTokens: any[],
      defaultAttrs: number = 0
    ): void {
      for (const token of inlineTokens) {
        if (token.type === "text") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            attributes: defaultAttrs,
          });
        } else if (token.type === "strong") {
          processInlineTokens(token.tokens, defaultAttrs | TextAttributes.BOLD);
        } else if (token.type === "em") {
          processInlineTokens(
            token.tokens,
            defaultAttrs | TextAttributes.ITALIC
          );
        } else if (token.type === "codespan") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            fg: codeColor,
            attributes: defaultAttrs,
          });
        } else if (token.type === "link") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            fg: linkColor,
            attributes: defaultAttrs | TextAttributes.UNDERLINE,
          });
        } else if (token.type === "br") {
          chunks.push({
            __isChunk: true,
            text: "\n",
            attributes: defaultAttrs,
          });
        } else if (token.tokens) {
          processInlineTokens(token.tokens, defaultAttrs);
        }
      }
    }

    for (const token of tokens) {
      if (token.type === "paragraph") {
        if (token.tokens) processInlineTokens(token.tokens);
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      } else if (token.type === "heading") {
        if (token.tokens)
          processInlineTokens(token.tokens, TextAttributes.BOLD);
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      } else if (token.type === "list") {
        for (const item of token.items) {
          chunks.push({
            __isChunk: true,
            text: token.ordered ? `${item.task ? "☐ " : "• "}` : "• ",
            attributes: 0,
          });
          processInlineTokens(item.tokens[0]?.tokens || []);
          chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
        }
      } else if (token.type === "code") {
        chunks.push({
          __isChunk: true,
          text: token.text + "\n",
          fg: codeColor,
          attributes: 0,
        });
      } else if (token.type === "blockquote") {
        // Add blockquote indicator and process content
        chunks.push({
          __isChunk: true,
          text: "│ ",
          fg: RGBA.fromInts(150, 150, 150, 255),
          attributes: 0,
        });
        if (token.tokens) processInlineTokens(token.tokens);
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      } else if (token.type === "space") {
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      }
    }

    // Trim trailing newlines cleanly
    while (chunks.length > 0) {
      const lastChunk = chunks[chunks.length - 1];
      if (lastChunk && lastChunk.text === "\n") {
        chunks.pop();
      } else if (lastChunk && lastChunk.text.endsWith("\n\n")) {
        lastChunk.text = lastChunk.text.slice(0, -1);
      } else if (lastChunk && lastChunk.text) {
        lastChunk.text = lastChunk.text.trimEnd();
        if (lastChunk.text === "") {
          chunks.pop();
        } else {
          break;
        }
      } else {
        break;
      }
    }

    return new StyledText(chunks);
  } catch (error) {
    // Fallback to plain text if parsing fails
    return new StyledText([
      {
        __isChunk: true,
        text: content,
        attributes: 0,
      },
    ]);
  }
}
