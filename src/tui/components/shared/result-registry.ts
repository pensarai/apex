/**
 * Result Summary Registry
 *
 * Centralized logic for generating human-readable result summaries.
 * Handles HTTP status, errors, collections, browser results, etc.
 */

export interface ResultSummary {
  text: string;
  isError: boolean;
  /** Optional full text for expandable display */
  fullText?: string;
}

/**
 * Get a human-readable summary for a tool result.
 *
 * @param result - The raw tool result
 * @param toolName - Optional tool name for tool-specific summaries
 * @returns Summary object with text and error flag, or null if no summary available
 */
export function getResultSummary(
  result: unknown,
  toolName?: string
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

      // Command execution
      case "execute_command": {
        if (typeof result === "object" && result !== null) {
          const obj = result as Record<string, unknown>;
          if ("exitCode" in obj || "code" in obj) {
            const code = Number(obj.exitCode ?? obj.code ?? 0);
            return { text: `Exit ${code}`, isError: code !== 0 };
          }
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
            return { text: `Found ${obj.endpoints.length} endpoints`, isError: false };
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
            return { text: `Found ${obj.findings.length} vulnerabilities`, isError: false };
          }
        }
        return { text: "Scan complete", isError: false };
      }
      case "document_finding": {
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
            return { text: `Found ${obj.endpoints.length} endpoints`, isError: false };
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
            return { text: `${obj.console.length} console messages`, isError: false };
          }
        }
        return { text: "Console retrieved", isError: false };
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
      const endpoints = obj.endpoints as Array<{ method?: string; path: string }>;
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

/**
 * Format a result value for detailed display (with truncation).
 */
export function formatResultDetail(
  result: unknown,
  maxLength: number = 2000
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
