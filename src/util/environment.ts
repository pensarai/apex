export interface EnvironmentContext {
  /** Auto-detected indicators from URL/target analysis */
  signals: string[];
  /** Human-readable summary for the LLM */
  description: string;
  /** Whether this appears to be a production environment */
  isProduction: boolean;
  /** Freeform operator-provided notes */
  userContext?: string;
}

/**
 * Patterns that indicate non-production environments.
 * Each entry: [regex applied to the full URL or hostname, signal label].
 */
const NON_PRODUCTION_PATTERNS: [RegExp, string][] = [
  // Subdomain / path keywords
  [/\bsandbox\b/i, "sandbox-keyword"],
  [/\bstaging\b/i, "staging-keyword"],
  [/\bdemo\b/i, "demo-keyword"],
  [/\bdev\b/i, "dev-keyword"],
  [/\btest\b/i, "test-keyword"],
  [/\bqa\b/i, "qa-keyword"],
  [/\buat\b/i, "uat-keyword"],
  [/\bpreview\b/i, "preview-keyword"],
  // Localhost / local development
  [/\blocalhost\b/i, "localhost"],
  [/^https?:\/\/127\.0\.0\.1/i, "loopback-address"],
  [/^https?:\/\/0\.0\.0\.0/i, "all-interfaces-address"],
  [/^https?:\/\/192\.168\./i, "private-network"],
  [/^https?:\/\/10\./i, "private-network"],
  [/^https?:\/\/172\.(1[6-9]|2\d|3[01])\./i, "private-network"],
  // Non-standard ports (common in dev/staging)
  [/:3000\b/, "non-standard-port-3000"],
  [/:8080\b/, "non-standard-port-8080"],
  [/:8443\b/, "non-standard-port-8443"],
  [/:5000\b/, "non-standard-port-5000"],
  // Platform-specific patterns
  [/\.herokuapp\.com$/i, "heroku-app"],
  [/\.vercel\.app$/i, "vercel-preview"],
  [/\.netlify\.app$/i, "netlify-preview"],
  [/\.ngrok\b/i, "ngrok-tunnel"],
  [/\.local\b/i, "local-domain"],
  // Protocol
  [/^http:\/\//i, "plain-http"],
];

/**
 * Detect environment context from target URLs and optional user context.
 *
 * Returns a structured EnvironmentContext with auto-detected signals
 * and a human-readable description for the CVSS scorer LLM.
 */
export function detectTargetEnvironment(
  targets: string[],
  userContext?: string,
): EnvironmentContext {
  const signals: string[] = [];

  for (const target of targets) {
    for (const [pattern, label] of NON_PRODUCTION_PATTERNS) {
      if (pattern.test(target) && !signals.includes(label)) {
        signals.push(label);
      }
    }
  }

  const isProduction = signals.length === 0;

  const description = buildDescription(
    targets,
    signals,
    isProduction,
    userContext,
  );

  return {
    signals,
    description,
    isProduction,
    ...(userContext ? { userContext } : {}),
  };
}

function buildDescription(
  targets: string[],
  signals: string[],
  isProduction: boolean,
  userContext?: string,
): string {
  const parts: string[] = [];

  if (isProduction) {
    parts.push(
      `Target appears to be a production environment. No non-production indicators detected in: ${targets.join(", ")}`,
    );
  } else {
    parts.push(
      `Target appears to be a NON-PRODUCTION environment. Detected indicators: ${signals.join(", ")}. Target(s): ${targets.join(", ")}`,
    );
  }

  if (userContext) {
    parts.push(`Operator-provided context: ${userContext}`);
  }

  return parts.join(". ");
}
