/**
 * JavaScript endpoint extraction utilities
 */

import { resolveBackends } from "../../../tools/backends";
import type { ToolContext } from "../../offSecAgent/tools/types";

export interface ExtractJavascriptEndpointsParams {
  url: string;
  sessionCookie?: string;
  includeExternalJS?: boolean;
  /** Routes the page fetch through the caller's tool backend (design §3.2) — no bare `fetch`. */
  ctx: ToolContext;
}

export interface EndpointInfo {
  endpoint: string;
  pattern: string;
  source: string;
}

export interface ExtractJavascriptEndpointsResult {
  success: boolean;
  url?: string;
  endpoints?: EndpointInfo[];
  parameterizedPatterns?: string[];
  totalAjaxCalls?: number;
  externalJSFiles?: string[];
  filesAnalyzed?: number;
  message: string;
}

/**
 * Extract endpoint URLs from JavaScript code in a page using pattern matching.
 *
 * Uses regex patterns to find:
 * - AJAX calls ($.ajax, $.get, $.post)
 * - Fetch API calls
 * - Axios requests
 * - XMLHttpRequest calls
 * - URL assignments
 */
export async function extractJavascriptEndpoints(
  params: ExtractJavascriptEndpointsParams,
): Promise<ExtractJavascriptEndpointsResult> {
  try {
    const { url, sessionCookie, includeExternalJS = true, ctx } = params;

    // Fetch the page
    const pageResult = await resolveBackends(ctx).http.request({
      url,
      method: "GET",
      headers: sessionCookie ? { Cookie: sessionCookie } : undefined,
    });
    if (!pageResult.success) {
      return {
        success: false,
        message: `JavaScript extraction error: ${pageResult.error ?? "request failed"}`,
      };
    }
    const html = pageResult.body;

    // Regex patterns to extract endpoints
    const endpointPatterns = [
      // jQuery AJAX
      /\$\.ajax\s*\(\s*\{\s*url\s*:\s*['"]([^'"]+)['"]/g,
      /\$\.get\s*\(\s*['"]([^'"]+)['"]/g,
      /\$\.post\s*\(\s*['"]([^'"]+)['"]/g,
      /\$\.getJSON\s*\(\s*['"]([^'"]+)['"]/g,
      // Fetch API
      /fetch\s*\(\s*['"]([^'"]+)['"]/g,
      /fetch\s*\(\s*`([^`]+)`/g,
      // Axios
      /axios\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/g,
      // XMLHttpRequest
      /\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]/gi,
      // URL construction
      /url\s*[:=]\s*['"]([^'"]+)['"]/gi,
      /href\s*[:=]\s*['"]([^'"]+)['"]/gi,
      /action\s*[:=]\s*['"]([^'"]+)['"]/gi,
    ];

    const endpoints: EndpointInfo[] = [];
    const jsFiles: string[] = [];

    // Extract inline script content
    const scriptTagRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    for (
      let scriptMatch = scriptTagRegex.exec(html);
      scriptMatch !== null;
      scriptMatch = scriptTagRegex.exec(html)
    ) {
      const scriptContent = scriptMatch[1];

      // Apply all patterns to script content
      for (const pattern of endpointPatterns) {
        const patternCopy = new RegExp(pattern.source, pattern.flags);
        for (
          let match = patternCopy.exec(scriptContent);
          match !== null;
          match = patternCopy.exec(scriptContent)
        ) {
          const endpoint = match[1] || match[2];
          if (endpoint?.startsWith("/")) {
            endpoints.push({
              endpoint,
              pattern: `${pattern.source.substring(0, 30)}...`,
              source: "inline-script",
            });
          }
        }
      }
    }

    // Extract external JS file URLs
    if (includeExternalJS) {
      const scriptSrcRegex = /<script[^>]+src=['"]([^'"]+)['"]/gi;
      for (
        let srcMatch = scriptSrcRegex.exec(html);
        srcMatch !== null;
        srcMatch = scriptSrcRegex.exec(html)
      ) {
        jsFiles.push(srcMatch[1]);
      }
    }

    // Deduplicate endpoints
    const uniqueEndpoints = Array.from(
      new Set(endpoints.map((e) => e.endpoint)),
    ).map((ep) => endpoints.find((e) => e.endpoint === ep)!);

    // Parameterize endpoints (replace numeric IDs with {id})
    const parameterizedEndpoints = uniqueEndpoints.map((e) => ({
      ...e,
      pattern: e.endpoint.replace(/\/\d+/g, "/{id}"),
    }));

    return {
      success: true,
      url,
      endpoints: uniqueEndpoints,
      parameterizedPatterns: Array.from(
        new Set(parameterizedEndpoints.map((e) => e.pattern)),
      ),
      totalAjaxCalls: endpoints.length,
      externalJSFiles: jsFiles,
      filesAnalyzed: 1 + jsFiles.length,
      message: `Found ${uniqueEndpoints.length} unique endpoints in JavaScript (${endpoints.length} total calls).`,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      message: `JavaScript extraction error: ${message}`,
    };
  }
}
