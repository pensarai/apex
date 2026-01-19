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
 * @returns Summary object with text and error flag, or null if no summary available
 */
export function getResultSummary(result: unknown): ResultSummary | null {
  if (result === null || result === undefined) {
    return null;
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
