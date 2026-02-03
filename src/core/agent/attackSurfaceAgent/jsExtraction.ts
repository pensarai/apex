/**
 * JavaScript endpoint extraction utilities
 */

export interface ExtractJavascriptEndpointsParams {
  url: string;
  sessionCookie?: string;
  includeExternalJS?: boolean;
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
  params: ExtractJavascriptEndpointsParams
): Promise<ExtractJavascriptEndpointsResult> {
  try {
    const { url, sessionCookie, includeExternalJS = true } = params;

    // Fetch the page
    const fetchRequest: RequestInit = { method: 'GET' };
    if (sessionCookie) {
      fetchRequest.headers = { 'Cookie': sessionCookie };
    }

    const pageResult = await fetch(url, fetchRequest);
    const html = await pageResult.text();

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
    let scriptMatch;
    while ((scriptMatch = scriptTagRegex.exec(html)) !== null) {
      const scriptContent = scriptMatch[1];

      // Apply all patterns to script content
      for (const pattern of endpointPatterns) {
        let match;
        const patternCopy = new RegExp(pattern.source, pattern.flags);
        while ((match = patternCopy.exec(scriptContent)) !== null) {
          const endpoint = match[1] || match[2];
          if (endpoint && endpoint.startsWith('/')) {
            endpoints.push({
              endpoint,
              pattern: pattern.source.substring(0, 30) + '...',
              source: 'inline-script'
            });
          }
        }
      }
    }

    // Extract external JS file URLs
    if (includeExternalJS) {
      const scriptSrcRegex = /<script[^>]+src=['"]([^'"]+)['"]/gi;
      let srcMatch;
      while ((srcMatch = scriptSrcRegex.exec(html)) !== null) {
        jsFiles.push(srcMatch[1]);
      }
    }

    // Deduplicate endpoints
    const uniqueEndpoints = Array.from(new Set(endpoints.map(e => e.endpoint)))
      .map(ep => endpoints.find(e => e.endpoint === ep)!);

    // Parameterize endpoints (replace numeric IDs with {id})
    const parameterizedEndpoints = uniqueEndpoints.map(e => ({
      ...e,
      pattern: e.endpoint.replace(/\/\d+/g, '/{id}')
    }));

    return {
      success: true,
      url,
      endpoints: uniqueEndpoints,
      parameterizedPatterns: Array.from(new Set(parameterizedEndpoints.map(e => e.pattern))),
      totalAjaxCalls: endpoints.length,
      externalJSFiles: jsFiles,
      filesAnalyzed: 1 + jsFiles.length,
      message: `Found ${uniqueEndpoints.length} unique endpoints in JavaScript (${endpoints.length} total calls).`,
    };
  } catch (error: any) {
    return {
      success: false,
      message: `JavaScript extraction error: ${error.message}`,
    };
  }
}
