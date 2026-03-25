/**
 * Result Summary Registry
 *
 * Centralized logic for generating human-readable result summaries.
 * Handles HTTP status, errors, collections, browser results, etc.
 */

import { RGBA, StyledText, type TextChunk } from "@opentui/core";
import { highlightCode } from "./syntax-highlight";
import type { ColorMode } from "../../theme/types";

export interface ResultSummary {
  text: string;
  isError: boolean;
  /** Optional full text for expandable display */
  fullText?: string;
  /** Syntax-highlighted rich text (preferred over plain text when available) */
  styledText?: StyledText;
  /** Optional label shown above styledText (e.g. "2 replacements") */
  label?: string;
}

/**
 * Get a human-readable summary for a tool result.
 *
 * @param result - The raw tool result
 * @param toolName - Optional tool name for tool-specific summaries
 * @param args - Optional tool args (used by file tools to show content previews)
 * @param mode - Color mode for syntax highlighting ("dark" or "light")
 * @returns Summary object with text and error flag, or null if no summary available
 */
export function getResultSummary(
  result: unknown,
  toolName?: string,
  args?: Record<string, unknown>,
  mode: ColorMode = "dark",
): ResultSummary | null {
  if (result === null || result === undefined) {
    return null;
  }

  // Tool-specific handlers
  if (toolName) {
    switch (toolName) {
      // File system tools
      case "Read":
      case "read_file": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Failed to read file").slice(0, 120),
              isError: true,
            };
          }
          const filePath = String(obj.path || args?.path || "");
          const content = typeof obj.content === "string" ? obj.content : "";
          const totalLines = obj.totalLines
            ? Number(obj.totalLines)
            : content.split("\n").length;

          if (content) {
            const lines = content.split("\n");
            const preview = lines.slice(0, 4).join("\n");
            const suffix = lines.length > 4 ? `\n… (${totalLines} lines)` : "";
            return {
              text: preview + suffix,
              isError: false,
              label: `${totalLines} lines`,
              styledText:
                highlightCode(preview + suffix, filePath, mode) ?? undefined,
              fullText:
                content.length > 400 ? content.slice(0, 2000) : undefined,
            };
          }
          return {
            text: `Read ${totalLines} lines`,
            isError: false,
          };
        }
        if (typeof result === "string") {
          const lines = result.split("\n").length;
          return { text: `Read ${lines} lines`, isError: false };
        }
        break;
      }
      case "Grep": {
        if (typeof result === "string") {
          const lines = result.trim() ? result.split("\n").length : 0;
          return {
            text: lines > 0 ? `Found ${lines} lines` : "No matches",
            isError: false,
          };
        }
        break;
      }
      case "grep": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "grep failed")
                .split("\n")[0]
                .slice(0, 120),
              isError: true,
            };
          }
          const output = typeof obj.output === "string" ? obj.output : "";
          const matchCount = Number(obj.matchCount || 0);
          if (matchCount === 0 || output === "(no matches)") {
            return { text: "No matches", isError: false };
          }
          const outputLines = output.split("\n").filter((l) => l.length > 0);
          const preview = outputLines.slice(0, 5).join("\n");
          const suffix =
            outputLines.length > 5 ? `\n… (${matchCount} matches)` : "";
          return {
            text: `${matchCount} match${matchCount !== 1 ? "es" : ""}`,
            isError: false,
            fullText: preview + suffix,
          };
        }
        break;
      }
      case "web_search": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Search failed")
                .split("\n")[0]
                .slice(0, 120),
              isError: true,
            };
          }
          const results = Array.isArray(obj.results)
            ? (obj.results as Array<Record<string, unknown>>)
            : [];
          if (results.length === 0) {
            return { text: "No results", isError: false };
          }
          const shown = results.slice(0, 5);
          const styledChunks = buildWebSearchStyledText(
            shown,
            results.length > 5 ? results.length : undefined,
            mode,
          );
          return {
            text: `${results.length} result${results.length !== 1 ? "s" : ""}`,
            isError: false,
            label: `${results.length} result${results.length !== 1 ? "s" : ""}`,
            styledText: styledChunks,
          };
        }
        break;
      }
      case "Glob": {
        if (Array.isArray(result)) {
          return { text: `Found ${result.length} files`, isError: false };
        }
        if (typeof result === "string") {
          const files = result.trim() ? result.split("\n").length : 0;
          return {
            text: files > 0 ? `Found ${files} files` : "No files found",
            isError: false,
          };
        }
        break;
      }
      case "Edit": {
        return { text: "Edited file", isError: false };
      }
      case "Write":
      case "write_file": {
        if (typeof result === "string") {
          const lines = result.split("\n").length;
          return { text: `Wrote ${lines} lines`, isError: false };
        }
        return { text: "File written", isError: false };
      }
      case "create_file": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Failed").slice(0, 120),
              isError: true,
            };
          }
          const filePath = String(obj.path || args?.path || "");
          const content = typeof args?.content === "string" ? args.content : "";
          if (content) {
            const lines = content.split("\n");
            const preview = lines.slice(0, 4).join("\n");
            const suffix =
              lines.length > 4 ? `\n… (${lines.length} lines)` : "";
            return {
              text: preview + suffix,
              isError: false,
              styledText:
                highlightCode(preview + suffix, filePath, mode) ?? undefined,
              fullText:
                content.length > 400 ? content.slice(0, 2000) : undefined,
            };
          }
          return { text: `Created ${filePath}`, isError: false };
        }
        break;
      }
      case "update_file": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Failed").slice(0, 120),
              isError: true,
            };
          }
          const filePath = String(obj.path || args?.path || "");
          const n = Number(obj.replacements ?? 1);
          const newContent =
            typeof args?.newContent === "string" ? args.newContent : "";
          if (newContent) {
            const lines = newContent.split("\n");
            const preview = lines.slice(0, 4).join("\n");
            const suffix =
              lines.length > 4 ? `\n… (${lines.length} lines)` : "";
            const codePreview = preview + suffix;
            return {
              text: `${n} replacement${n !== 1 ? "s" : ""}\n${codePreview}`,
              isError: false,
              label: `${n} replacement${n !== 1 ? "s" : ""}`,
              styledText:
                highlightCode(codePreview, filePath, mode) ?? undefined,
              fullText:
                newContent.length > 400 ? newContent.slice(0, 2000) : undefined,
            };
          }
          return {
            text: `${n} replacement${n !== 1 ? "s" : ""}`,
            isError: false,
          };
        }
        break;
      }

      case "list_files": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Failed to list files").slice(0, 120),
              isError: true,
            };
          }
          const files = Array.isArray(obj.files) ? (obj.files as string[]) : [];
          const total = Number(obj.totalFound || obj.count || files.length);
          const preview = files.slice(0, 15).join("\n");
          const suffix =
            files.length < total
              ? `\n… (${total} total)`
              : files.length > 15
                ? `\n… (${files.length} files)`
                : "";
          return {
            text: `${total} file${total !== 1 ? "s" : ""}`,
            isError: false,
            fullText: preview + suffix,
          };
        }
        break;
      }

      // Command execution — show exit code + stdout/stderr
      case "execute_command": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          const ok = obj.success !== false;
          const stdout = typeof obj.stdout === "string" ? obj.stdout : "";
          const stderr = typeof obj.stderr === "string" ? obj.stderr : "";
          const error = typeof obj.error === "string" ? obj.error : "";

          const output = stdout.replace(/^\(no output\)$/, "");
          const outputLines = output.split("\n").filter((l) => l.length > 0);
          const outputPreview = outputLines.slice(0, 3).join("\n");
          const outputSuffix =
            outputLines.length > 3 ? `\n… (${outputLines.length} lines)` : "";

          if (!ok) {
            const errLine = (error || stderr || "Command failed")
              .split("\n")[0]
              .slice(0, 120);
            const parts = [errLine, outputPreview + outputSuffix]
              .filter(Boolean)
              .join("\n");
            const fullParts = [
              output.slice(0, 2000),
              (stderr || error).slice(0, 2000),
            ]
              .filter(Boolean)
              .join("\n---\n");
            return {
              text: parts || "Command failed",
              isError: true,
              fullText: fullParts.length > 400 ? fullParts : undefined,
            };
          }

          if (!output) {
            return { text: "(no output)", isError: false };
          }
          return {
            text: outputPreview + outputSuffix,
            isError: false,
            fullText: output.length > 400 ? output.slice(0, 2000) : undefined,
          };
        }
        break;
      }

      // Task/Agent tools
      case "Task":
      case "task": {
        if (typeof result === "string") {
          return { text: result.slice(0, 60), isError: false };
        }
        return { text: "Task completed", isError: false };
      }

      // HTTP/Network tools
      case "crawl": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.urls && Array.isArray(obj.urls)) {
            return { text: `Found ${obj.urls.length} URLs`, isError: false };
          }
        }
        break;
      }

      // Security/Analysis tools
      case "smart_enumerate": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.endpoints && Array.isArray(obj.endpoints)) {
            return {
              text: `Found ${obj.endpoints.length} endpoints`,
              isError: false,
            };
          }
        }
        return { text: "Enumeration complete", isError: false };
      }
      case "get_attack_surface": {
        return { text: "Attack surface retrieved", isError: false };
      }
      case "nuclei_scan": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.findings && Array.isArray(obj.findings)) {
            return {
              text: `Found ${obj.findings.length} vulnerabilities`,
              isError: false,
            };
          }
        }
        return { text: "Scan complete", isError: false };
      }
      case "document_finding":
      case "document_vulnerability": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          // POC execution failure
          if (obj.pocFailed) {
            const errText = String(obj.stderr || obj.error || "POC failed");
            return {
              text: `POC failed (exit ${obj.exitCode}): ${errText.split("\n")[0].slice(0, 120)}`,
              isError: true,
              fullText:
                typeof obj.stdout === "string"
                  ? obj.stdout.slice(0, 2000)
                  : undefined,
            };
          }
          // Judge rejection
          if (obj.judgeRejected) {
            const reasoning = String(
              obj.judgeReasoning || "Finding rejected by judge",
            );
            return {
              text: reasoning.slice(0, 120),
              isError: true,
              fullText: Array.isArray(obj.judgeConcerns)
                ? (obj.judgeConcerns as string[]).join("\n")
                : undefined,
            };
          }
          if (obj.success === false) {
            const msg = String(obj.message || obj.error || "Failed").slice(
              0,
              120,
            );
            return { text: msg, isError: !obj.duplicate };
          }
          const finding =
            typeof obj.finding === "object" && obj.finding !== null
              ? (obj.finding as Record<string, unknown>)
              : null;
          const title = String(
            finding?.title || args?.title || "Finding documented",
          );
          const severity = finding?.severity ? `[${finding.severity}] ` : "";
          return { text: `${severity}${title}`, isError: false };
        }
        return { text: "Finding documented", isError: false };
      }
      case "analyze_scan": {
        return { text: "Analysis complete", isError: false };
      }
      case "fuzz_endpoint": {
        return { text: "Fuzzing complete", isError: false };
      }
      case "test_parameter": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (typeof obj.vulnerable === "boolean") {
            return {
              text: obj.vulnerable ? "Vulnerable" : "Not vulnerable",
              isError: false,
            };
          }
        }
        return { text: "Test complete", isError: false };
      }
      case "cve_lookup": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.cves && Array.isArray(obj.cves)) {
            return { text: `Found ${obj.cves.length} CVEs`, isError: false };
          }
        }
        return { text: "Lookup complete", isError: false };
      }
      case "enumerate_endpoints": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.endpoints && Array.isArray(obj.endpoints)) {
            return {
              text: `Found ${obj.endpoints.length} endpoints`,
              isError: false,
            };
          }
        }
        return { text: "Enumeration complete", isError: false };
      }
      case "generate_report": {
        return { text: "Report generated", isError: false };
      }
      case "check_testing_coverage": {
        return { text: "Coverage checked", isError: false };
      }
      case "validate_completeness": {
        return { text: "Validation complete", isError: false };
      }
      case "mutate_payload": {
        return { text: "Payload generated", isError: false };
      }
      case "record_test_result": {
        return { text: "Result recorded", isError: false };
      }
      case "update_attack_surface": {
        return { text: "Attack surface updated", isError: false };
      }
      case "record_credential": {
        return { text: "Credential recorded", isError: false };
      }
      case "update_endpoint_status": {
        return { text: "Status updated", isError: false };
      }
      case "record_verified_finding": {
        return { text: "Finding verified", isError: false };
      }

      // Browser tools
      case "browser_navigate": {
        return { text: "Page loaded", isError: false };
      }
      case "browser_screenshot": {
        return { text: "Screenshot taken", isError: false };
      }
      case "browser_evaluate": {
        return { text: "Evaluated", isError: false };
      }
      case "browser_console": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.console && Array.isArray(obj.console)) {
            return {
              text: `${obj.console.length} console messages`,
              isError: false,
            };
          }
        }
        return { text: "Console retrieved", isError: false };
      }

      // Memory tools
      case "list_memories": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Failed to list memories").slice(
                0,
                120,
              ),
              isError: true,
            };
          }
          const memories = Array.isArray(obj.memories)
            ? (obj.memories as Array<Record<string, unknown>>)
            : [];
          const count = Number(obj.count ?? memories.length);
          if (count === 0) {
            return { text: "No memories found", isError: false };
          }
          const preview = memories
            .slice(0, 8)
            .map((m) => {
              const cat = m.category ? `[${m.category}]` : "";
              return `${cat} ${m.title || m.id || "untitled"}`;
            })
            .join("\n");
          const suffix = count > 8 ? `\n… (${count} total)` : "";
          return {
            text: `${count} memor${count === 1 ? "y" : "ies"}`,
            isError: false,
            fullText: preview + suffix,
          };
        }
        break;
      }
      case "add_memory": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Failed to save memory").slice(0, 120),
              isError: true,
            };
          }
          const title = obj.title || args?.title || "memory";
          const cat = obj.category ? `[${obj.category}] ` : "";
          return { text: `${cat}Saved "${title}"`, isError: false };
        }
        break;
      }
      case "get_memory": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if (obj.success === false) {
            return {
              text: String(obj.error || "Memory not found").slice(0, 120),
              isError: true,
            };
          }
          const memory =
            typeof obj.memory === "object" && obj.memory !== null
              ? (obj.memory as Record<string, unknown>)
              : null;
          if (memory) {
            const title = String(memory.title || "untitled");
            const content =
              typeof memory.content === "string" ? memory.content : "";
            const lines = content.split("\n");
            const preview = lines.slice(0, 4).join("\n");
            const suffix =
              lines.length > 4 ? `\n… (${lines.length} lines)` : "";
            return {
              text: title,
              isError: false,
              fullText: content.length > 0 ? preview + suffix : undefined,
            };
          }
          return { text: "Memory retrieved", isError: false };
        }
        break;
      }

      // Utility tools
      case "scratchpad": {
        return { text: "Note saved", isError: false };
      }
    }
  }

  if (typeof result === "object" && result !== null) {
    const obj = result as Record<string, unknown>;

    // Error conditions
    if (obj.error) {
      return {
        text: `Error: ${String(obj.error).slice(0, 80)}`,
        isError: true,
      };
    }
    if (obj.success === false) {
      return {
        text: obj.message ? String(obj.message).slice(0, 80) : "Failed",
        isError: true,
      };
    }
    if (obj.blocked) {
      return {
        text: "Blocked by approval gate",
        isError: true,
      };
    }

    // HTTP responses
    if (obj.status || obj.statusCode) {
      const status = Number(obj.status || obj.statusCode);
      const isError = status >= 400;
      let fullText: string | undefined;
      if (obj.body && typeof obj.body === "string") {
        fullText = (obj.body as string).slice(0, 500);
      }
      return {
        text: `Status: ${status}`,
        isError,
        fullText,
      };
    }

    // Browser results
    if (obj.title) {
      return {
        text: `Page: ${String(obj.title).slice(0, 60)}`,
        isError: false,
      };
    }
    if (obj.screenshot) {
      return {
        text: `Screenshot saved: ${obj.screenshot}`,
        isError: false,
      };
    }
    if (obj.console && Array.isArray(obj.console)) {
      const consoleArr = obj.console as Array<{ type: string; text: string }>;
      return {
        text: `${consoleArr.length} console messages`,
        isError: false,
        fullText: consoleArr
          .slice(0, 20)
          .map((c) => `[${c.type}] ${c.text}`)
          .join("\n"),
      };
    }

    // Collections
    if (obj.endpoints && Array.isArray(obj.endpoints)) {
      const endpoints = obj.endpoints as Array<{
        method?: string;
        path: string;
      }>;
      return {
        text: `Found ${endpoints.length} endpoints`,
        isError: false,
        fullText: endpoints
          .slice(0, 15)
          .map((e) => `${e.method || "GET"} ${e.path}`)
          .join("\n"),
      };
    }
    if (obj.urls && Array.isArray(obj.urls)) {
      const urls = obj.urls as string[];
      return {
        text: `Found ${urls.length} URLs`,
        isError: false,
        fullText: urls.slice(0, 10).join("\n"),
      };
    }
    if (obj.links && Array.isArray(obj.links)) {
      const links = obj.links as string[];
      return {
        text: `Found ${links.length} links`,
        isError: false,
        fullText: links.slice(0, 10).join("\n"),
      };
    }

    // Generic object with keys
    const keys = Object.keys(obj).filter((k) => k !== "toolCallDescription");
    if (keys.length > 0) {
      return {
        text: `{${keys.slice(0, 4).join(", ")}}`,
        isError: false,
        fullText: JSON.stringify(obj, null, 2).slice(0, 1000),
      };
    }
  }

  // String result
  if (typeof result === "string") {
    if (result.length === 0) return null;
    const isError = result.toLowerCase().includes("error");
    return {
      text: result.slice(0, 100).replace(/\n/g, " "),
      isError,
      fullText: result.slice(0, 1000),
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Web search styled text helpers
// ---------------------------------------------------------------------------

const WS_COLORS: Record<
  ColorMode,
  { globe: RGBA; domain: RGBA; title: RGBA; snippet: RGBA }
> = {
  dark: {
    globe: RGBA.fromInts(106, 115, 125, 255), // gray
    domain: RGBA.fromInts(86, 182, 194, 255), // cyan
    title: RGBA.fromInts(97, 175, 239, 255), // blue
    snippet: RGBA.fromInts(140, 148, 160, 255), // muted
  },
  light: {
    globe: RGBA.fromInts(106, 115, 125, 255), // gray
    domain: RGBA.fromInts(28, 120, 134, 255), // darker cyan
    title: RGBA.fromInts(30, 100, 200, 255), // darker blue
    snippet: RGBA.fromInts(100, 108, 120, 255), // darker muted
  },
};

function chunk(text: string, fg?: RGBA): TextChunk {
  return { __isChunk: true, text, fg, attributes: 0 };
}

function extractDomain(url: string): string {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    return host;
  } catch {
    return url.split("/")[2]?.replace(/^www\./, "") || url.slice(0, 30);
  }
}

function buildWebSearchStyledText(
  results: Array<Record<string, unknown>>,
  totalCount?: number,
  mode: ColorMode = "dark",
): StyledText {
  const wsColors = WS_COLORS[mode];
  const chunks: TextChunk[] = [];
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const domain = extractDomain(String(r.url || ""));
    const title = String(r.title || "").slice(0, 70);

    if (i > 0) chunks.push(chunk("\n"));
    chunks.push(chunk("🌐 ", wsColors.globe));
    chunks.push(chunk(domain, wsColors.domain));
    chunks.push(chunk(" — ", wsColors.globe));
    chunks.push(chunk(title, wsColors.title));
  }
  if (totalCount && totalCount > results.length) {
    chunks.push(chunk(`\n… (${totalCount} total)`, wsColors.snippet));
  }
  return new StyledText(chunks);
}

/**
 * Format a result value for detailed display (with truncation).
 */
export function formatResultDetail(
  result: unknown,
  maxLength: number = 2000,
): string {
  try {
    const str = JSON.stringify(result, null, 2);
    if (str.length > maxLength) {
      return str.substring(0, maxLength) + "\n... (truncated)";
    }
    return str;
  } catch {
    return String(result);
  }
}
