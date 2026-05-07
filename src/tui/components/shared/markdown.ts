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
import type { ThemeColors } from "../../theme";
import { obfuscate } from "../../../core/obfuscation";

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
export function markdownToStyledText(
  rawContent: string,
  colors?: ThemeColors,
): StyledText {
  // Apply obfuscation before any tokenisation so emails/URLs/hostnames are
  // redacted before they get coloured as links/codespans.
  const content = obfuscate(rawContent);
  // Resolve colors with fallbacks for backwards compatibility.
  // textColor must be set on every plain-text chunk: StyledText chunks
  // without an explicit fg fall back to opentui's default (white), which
  // is invisible on light themes regardless of the parent <text fg=…>.
  const textColor = colors?.text ?? RGBA.fromInts(220, 220, 220, 255);
  const mutedColor = colors?.textMuted ?? RGBA.fromInts(150, 150, 150, 255);
  const codeColor = colors?.markdownCode ?? RGBA.fromInts(100, 255, 100, 255);
  const linkColor = colors?.markdownLink ?? RGBA.fromInts(100, 200, 255, 255);

  // Handle empty or whitespace-only content
  if (!content || !content.trim()) {
    return new StyledText([
      { __isChunk: true, text: content || "", fg: textColor, attributes: 0 },
    ]);
  }

  try {
    const tokens = marked.lexer(content);
    const chunks: TextChunk[] = [];

    type InlineToken = {
      type?: string;
      text?: string;
      raw?: string;
      tokens?: InlineToken[];
      [key: string]: unknown;
    };

    function processInlineTokens(
      inlineTokens: InlineToken[],
      defaultAttrs: number = 0,
    ): void {
      for (const token of inlineTokens) {
        if (token.type === "text") {
          chunks.push({
            __isChunk: true,
            text: token.text || "",
            fg: textColor,
            attributes: defaultAttrs,
          });
        } else if (token.type === "strong") {
          processInlineTokens(
            token.tokens || [],
            defaultAttrs | TextAttributes.BOLD,
          );
        } else if (token.type === "em") {
          processInlineTokens(
            token.tokens || [],
            defaultAttrs | TextAttributes.ITALIC,
          );
        } else if (token.type === "codespan") {
          chunks.push({
            __isChunk: true,
            text: token.text || "",
            fg: codeColor,
            attributes: defaultAttrs,
          });
        } else if (token.type === "link") {
          chunks.push({
            __isChunk: true,
            text: token.text || "",
            fg: linkColor,
            attributes: defaultAttrs | TextAttributes.UNDERLINE,
          });
        } else if (token.type === "br") {
          chunks.push({
            __isChunk: true,
            text: "\n",
            fg: textColor,
            attributes: defaultAttrs,
          });
        } else if (token.type === "html") {
          // Inline HTML — emit as literal text so any angle-bracketed
          // content the assistant produces appears on screen instead of
          // being silently consumed by the markdown lexer.
          chunks.push({
            __isChunk: true,
            text: token.raw || token.text || "",
            fg: textColor,
            attributes: defaultAttrs,
          });
        } else if (token.tokens) {
          processInlineTokens(token.tokens, defaultAttrs);
        }
      }
    }

    for (const token of tokens) {
      if (token.type === "paragraph") {
        if (token.tokens)
          processInlineTokens(token.tokens as unknown as InlineToken[]);
        chunks.push({
          __isChunk: true,
          text: "\n",
          fg: textColor,
          attributes: 0,
        });
      } else if (token.type === "heading") {
        if (token.tokens)
          processInlineTokens(
            token.tokens as unknown as InlineToken[],
            TextAttributes.BOLD,
          );
        chunks.push({
          __isChunk: true,
          text: "\n",
          fg: textColor,
          attributes: 0,
        });
      } else if (token.type === "list") {
        for (const item of token.items) {
          chunks.push({
            __isChunk: true,
            text: token.ordered ? `${item.task ? "☐ " : "• "}` : "• ",
            fg: textColor,
            attributes: 0,
          });
          processInlineTokens(item.tokens[0]?.tokens || []);
          chunks.push({
            __isChunk: true,
            text: "\n",
            fg: textColor,
            attributes: 0,
          });
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
          fg: mutedColor,
          attributes: 0,
        });
        if (token.tokens)
          processInlineTokens(token.tokens as unknown as InlineToken[]);
        chunks.push({
          __isChunk: true,
          text: "\n",
          fg: textColor,
          attributes: 0,
        });
      } else if (token.type === "space") {
        chunks.push({
          __isChunk: true,
          text: "\n",
          fg: textColor,
          attributes: 0,
        });
      } else if (token.type === "html") {
        // Block-level HTML — pass through as literal text. Mirrors the
        // inline `html` handler so angle-bracketed obfuscation
        // placeholders survive a full-line emission.
        const tk = token as { raw?: string; text?: string };
        chunks.push({
          __isChunk: true,
          text: tk.raw || tk.text || "",
          fg: textColor,
          attributes: 0,
        });
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
        fg: textColor,
        attributes: 0,
      },
    ]);
  }
}
