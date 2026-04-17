/**
 * URL parsing utilities for extracting hosts and ports from target URLs
 */

export interface ParsedTarget {
  /** Hostname extracted from the URL */
  hostname: string;
  /** Port number (if specified), otherwise undefined */
  port?: number;
}

/**
 * Extract hostname and port from a target URL.
 * Handles various URL formats:
 * - https://example.com
 * - https://example.com:8080
 * - http://api.example.com:3000/path
 * - example.com (assumes https)
 * - example.com:8080 (assumes https)
 *
 * @param target - Target URL string
 * @returns Parsed hostname and optional port, or null if invalid
 */
export function parseTargetUrl(target: string): ParsedTarget | null {
  if (!target || !target.trim()) {
    return null;
  }

  let urlString = target.trim();

  // If no protocol, assume https
  if (!urlString.match(/^https?:\/\//i)) {
    urlString = `https://${urlString}`;
  }

  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    // Reject hostnames that are just protocol names or other non-host
    // strings — these arise when a bare "https" or similar token is
    // prepended with "https://" and parsed as "https://https".
    if (/^(https?|ftp|ftps|ssh|telnet|file|data|blob)$/i.test(hostname)) {
      return null;
    }

    // Extract port if explicitly specified (not default 80/443)
    let port: number | undefined;
    if (url.port) {
      port = parseInt(url.port, 10);
    }

    return {
      hostname,
      port,
    };
  } catch {
    return null;
  }
}

/**
 * Get the list of allowed hosts from a target URL.
 * If initialHosts are provided, the parsed hostname is added to them (if not already present).
 *
 * @param target - Target URL string
 * @param initialHosts - Existing list of allowed hosts
 * @returns Array of allowed hosts with target hostname included
 */
export function getAutoPopulatedHosts(
  target: string,
  initialHosts: string[] = [],
): string[] {
  const parsed = parseTargetUrl(target);
  if (!parsed) {
    return initialHosts;
  }

  const hosts = [...initialHosts];

  // Add parsed hostname if not already in the list
  if (!hosts.includes(parsed.hostname)) {
    hosts.push(parsed.hostname);
  }

  return hosts;
}

/**
 * Get the list of allowed ports from a target URL.
 * If initialPorts are provided, the parsed port is added to them (if not already present).
 *
 * @param target - Target URL string
 * @param initialPorts - Existing list of allowed ports
 * @returns Array of allowed ports with target port included (if specified)
 */
export function getAutoPopulatedPorts(
  target: string,
  initialPorts: number[] = [],
): number[] {
  const parsed = parseTargetUrl(target);
  if (!parsed || !parsed.port) {
    return initialPorts;
  }

  const ports = [...initialPorts];

  // Add parsed port if not already in the list
  if (!ports.includes(parsed.port)) {
    ports.push(parsed.port);
  }

  return ports;
}
