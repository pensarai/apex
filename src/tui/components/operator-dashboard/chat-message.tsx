/**
 * Chat Message Component
 *
 * Claude Code-like message display for Operator mode.
 * Minimal chrome, streaming text, terminal-style.
 */

import { memo, useMemo } from "react";
import { RGBA, StyledText, TextAttributes, type TextChunk } from "@opentui/core";
import { marked } from "marked";
import { SpinnerDots } from "../sprites";
import type { DisplayMessage } from "../agent-display";

const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const toolColor = RGBA.fromInts(100, 180, 255, 255);
// Use consistent RGBA for spinners to avoid color mismatches
const blueSpinner = toolColor;  // Same blue for tool spinners

// Simplified markdown to styled text
function markdownToStyledText(content: string): StyledText {
  if (!content || !content.trim()) {
    return new StyledText([{ __isChunk: true, text: content || "", attributes: 0 }]);
  }

  try {
    const tokens = marked.lexer(content);
    const chunks: TextChunk[] = [];

    function processInlineTokens(inlineTokens: any[], defaultAttrs: number = 0): void {
      for (const token of inlineTokens) {
        if (token.type === "text") {
          chunks.push({ __isChunk: true, text: token.text, attributes: defaultAttrs });
        } else if (token.type === "strong") {
          processInlineTokens(token.tokens, defaultAttrs | TextAttributes.BOLD);
        } else if (token.type === "em") {
          processInlineTokens(token.tokens, defaultAttrs | TextAttributes.ITALIC);
        } else if (token.type === "codespan") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            fg: RGBA.fromInts(100, 255, 100, 255),
            attributes: defaultAttrs,
          });
        } else if (token.type === "link") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            fg: RGBA.fromInts(100, 200, 255, 255),
            attributes: defaultAttrs | TextAttributes.UNDERLINE,
          });
        } else if (token.type === "br") {
          chunks.push({ __isChunk: true, text: "\n", attributes: defaultAttrs });
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
        if (token.tokens) processInlineTokens(token.tokens, TextAttributes.BOLD);
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      } else if (token.type === "list") {
        for (const item of token.items) {
          chunks.push({ __isChunk: true, text: "  - ", attributes: 0 });
          processInlineTokens(item.tokens[0]?.tokens || []);
          chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
        }
      } else if (token.type === "code") {
        chunks.push({
          __isChunk: true,
          text: token.text + "\n",
          fg: RGBA.fromInts(100, 255, 100, 255),
          attributes: 0,
        });
      } else if (token.type === "space") {
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      }
    }

    // Trim trailing newlines
    while (chunks.length > 0) {
      const lastChunk = chunks[chunks.length - 1];
      if (lastChunk && lastChunk.text === "\n") {
        chunks.pop();
      } else if (lastChunk && lastChunk.text.endsWith("\n\n")) {
        lastChunk.text = lastChunk.text.slice(0, -1);
      } else {
        break;
      }
    }

    return new StyledText(chunks);
  } catch {
    return new StyledText([{ __isChunk: true, text: content, attributes: 0 }]);
  }
}

interface ChatMessageProps {
  message: DisplayMessage;
  isStreaming?: boolean;
  verbose?: boolean;
}

export const ChatMessage = memo(function ChatMessage({ message, isStreaming = false, verbose = false }: ChatMessageProps) {
  const content = typeof message.content === "string"
    ? message.content
    : JSON.stringify(message.content);

  // User messages - simple prompt style
  if (message.role === "user") {
    return (
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={greenAccent}>{">"}</text>
        <text fg={creamText}>{content}</text>
      </box>
    );
  }

  // System messages - dimmed
  if (message.role === "system") {
    return (
      <box marginTop={1}>
        <text fg={dimText}>  {content}</text>
      </box>
    );
  }

  // Tool messages - inline with status
  if (message.role === "tool") {
    const isPending = message.status === "pending";
    const toolName = (message as any).toolName || "";
    const args = (message as any).args || {};
    const result = (message as any).result;

    // Get the key info to display based on tool type
    const getToolSummary = (): string => {
      switch (toolName) {
        case "http_request": {
          const method = (args.method || "GET").toUpperCase();
          const url = args.url || "";
          return `${method} ${url}`;
        }
        case "crawl":
          return `crawl ${args.url || args.target || ""}`;
        case "execute_command":
          return `$ ${args.command || ""}`;
        case "nuclei_scan":
          return `nuclei ${args.templates || "all"} -> ${args.target || ""}`;
        case "document_finding":
          return `finding: ${args.title || args.name || ""}`;
        case "read_file":
          return `read ${args.path || ""}`;
        case "write_file":
          return `write ${args.path || ""}`;
        case "scratchpad":
          return `note: ${(args.content || "").slice(0, 40)}...`;
        default: {
          // For unknown tools, show first meaningful arg
          const firstArg = Object.entries(args)
            .filter(([k]) => k !== "toolCallDescription")
            .map(([_, v]) => typeof v === "string" ? v : JSON.stringify(v))
            .find(v => v.length > 0);
          return `${toolName}${firstArg ? ` ${firstArg.slice(0, 50)}` : ""}`;
        }
      }
    };

    const summary = getToolSummary();

    // Compact view (default) - shows actual command
    if (!verbose) {
      return (
        <box flexDirection="row" gap={1} marginLeft={2}>
          {isPending ? (
            <SpinnerDots label={summary} fg={blueSpinner} />
          ) : (
            <text fg={toolColor}>+ {summary}</text>
          )}
        </box>
      );
    }

    // Verbose view - show tool name, args, and result
    const formatArgs = (obj: Record<string, unknown>): string => {
      const entries = Object.entries(obj)
        .filter(([k]) => k !== "toolCallDescription")
        .slice(0, 5);
      return entries.map(([k, v]) => {
        const val = typeof v === "string" ? v : JSON.stringify(v);
        const truncated = val.length > 60 ? val.slice(0, 57) + "..." : val;
        return `  ${k}: ${truncated}`;
      }).join("\n");
    };

    const formatResult = (res: unknown): string => {
      if (!res) return "";
      const str = typeof res === "string" ? res : JSON.stringify(res, null, 2);
      const lines = str.split("\n").slice(0, 8);
      if (str.split("\n").length > 8) lines.push("  ...");
      return lines.map(l => `  ${l.slice(0, 80)}`).join("\n");
    };

    return (
      <box flexDirection="column" marginLeft={2} marginTop={1}>
        <box flexDirection="row" gap={1}>
          {isPending ? (
            <SpinnerDots label={`${toolName}`} fg={blueSpinner} />
          ) : (
            <text fg={toolColor}>+ {toolName}</text>
          )}
        </box>
        {Object.keys(args).length > 0 && (
          <text fg={dimText}>{formatArgs(args)}</text>
        )}
        {result && !isPending && (
          <box marginTop={1}>
            <text fg={RGBA.fromInts(80, 80, 80, 255)}>{formatResult(result)}</text>
          </box>
        )}
      </box>
    );
  }

  // Assistant messages - streaming markdown (memoized to avoid re-parsing on every render)
  const displayContent = useMemo(() => markdownToStyledText(content), [content]);

  return (
    <box flexDirection="column" marginTop={1}>
      <box flexDirection="row" gap={0}>
        <box
          width={2}
          borderStyle="heavy"
          border={["left"]}
          borderColor={greenAccent}
        />
        <box flexDirection="column" paddingLeft={1}>
          <text fg={creamText} content={displayContent} />
          {isStreaming && !content.trim() && (
            <SpinnerDots label="" fg="green" />
          )}
        </box>
      </box>
    </box>
  );
});

export default ChatMessage;
