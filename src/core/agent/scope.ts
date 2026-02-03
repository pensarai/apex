/**
 * Scope constraints for pentesting agents
 * Defines what hosts, ports, and domains are in-scope for testing
 */

export interface ScopeConstraints {
  /**
   * Allowed hosts/domains for testing
   * e.g., ['localhost', 'example.com', '*.example.com']
   */
  allowedHosts?: string[];

  /**
   * Allowed ports for testing
   * e.g., [80, 443, 8080]
   */
  allowedPorts?: number[];

  /**
   * Strict scope enforcement
   * When true, prevents any testing outside allowedHosts/allowedPorts
   * When false, allows discovery but prioritizes in-scope targets
   */
  strictScope?: boolean;
}

/**
 * Check if a URL is within scope
 */
export function isUrlInScope(url: string, constraints?: ScopeConstraints): boolean {
  if (!constraints || !constraints.strictScope) {
    return true; // No constraints or not strict
  }

  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;
    const port = parsedUrl.port ? parseInt(parsedUrl.port) : (parsedUrl.protocol === 'https:' ? 443 : 80);

    // Check hostname
    if (constraints.allowedHosts && constraints.allowedHosts.length > 0) {
      const hostMatch = constraints.allowedHosts.some(allowedHost => {
        // Exact match
        if (hostname === allowedHost) {
          return true;
        }

        // Wildcard match (e.g., *.example.com)
        if (allowedHost.startsWith('*.')) {
          const domain = allowedHost.slice(2);
          return hostname.endsWith(domain);
        }

        return false;
      });

      if (!hostMatch) {
        return false;
      }
    }

    // Check port
    if (constraints.allowedPorts && constraints.allowedPorts.length > 0) {
      if (!constraints.allowedPorts.includes(port)) {
        return false;
      }
    }

    return true;
  } catch (error) {
    // Invalid URL
    return false;
  }
}

/**
 * Get scope description for prompts
 */
export function getScopeDescription(constraints?: ScopeConstraints): string {
  if (!constraints || !constraints.strictScope) {
    return "No scope restrictions. You may test any discovered targets.";
  }

  const parts: string[] = [];

  if (constraints.allowedHosts && constraints.allowedHosts.length > 0) {
    parts.push(`Allowed hosts: ${constraints.allowedHosts.join(', ')}`);
  }

  if (constraints.allowedPorts && constraints.allowedPorts.length > 0) {
    parts.push(`Allowed ports: ${constraints.allowedPorts.join(', ')}`);
  }

  parts.push("STRICT SCOPE ENFORCEMENT: Only test targets within the allowed hosts and ports.");
  parts.push("Do NOT perform port scans, subdomain enumeration on localhost, or test infrastructure services.");

  return parts.join('\n');
}
