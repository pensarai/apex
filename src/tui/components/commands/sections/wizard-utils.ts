import type { SessionConfig } from "../../../../core/session";

/**
 * Parse host from a URL string (includes port if present).
 * e.g., "http://localhost:3001" → "localhost:3001"
 */
export function parseHostFromUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.host;
  } catch {
    try {
      const parsed = new URL(`https://${url}`);
      return parsed.host;
    } catch {
      return null;
    }
  }
}

interface AuthFields {
  loginUrl: string;
  username: string;
  password: string;
  instructions: string;
}

interface ScopeFields {
  allowedHosts: string[];
  allowedPorts?: string[];
  strictScope: boolean;
  enumerateSubdomains?: boolean;
}

interface HeadersFields {
  mode: "none" | "default" | "custom";
  customHeaders: Record<string, string>;
}

interface BuildSessionConfigOptions {
  sessionType?: "web-app";
  mode?: "auto" | "driver" | "operator";
  auth?: AuthFields;
  scope?: ScopeFields;
  headers?: HeadersFields;
  sourceCodeAccess?: boolean;
  cwd?: string;
}

/**
 * Pure function that builds a SessionConfig from wizard form state.
 * Shared between web-wizard and init-wizard.
 */
export function buildSessionConfig(
  options: BuildSessionConfigOptions,
): SessionConfig {
  const config: SessionConfig = {};

  if (options.sessionType) {
    config.sessionType = options.sessionType;
  }
  if (options.mode) {
    config.mode = options.mode;
  }

  // Auth
  if (options.auth) {
    const { auth } = options;
    if (auth.instructions || auth.username) {
      config.authenticationInstructions = auth.instructions;
      if (auth.username) {
        config.authCredentials = {
          username: auth.username,
          password: auth.password,
          loginUrl: auth.loginUrl || undefined,
        };
      }
    }
  }

  // Scope
  if (options.scope) {
    const { scope } = options;
    const hasPorts = (scope.allowedPorts?.length ?? 0) > 0;
    if (scope.allowedHosts.length > 0 || hasPorts) {
      config.scopeConstraints = {
        allowedHosts: scope.allowedHosts,
        ...(hasPorts && {
          allowedPorts: scope
            .allowedPorts!.map((p) => parseInt(p, 10))
            .filter((p) => !isNaN(p)),
        }),
        strictScope: scope.strictScope,
      };
    }
    if (scope.enumerateSubdomains) {
      config.enumerateSubdomains = true;
    }
  }

  // Source code access (whitebox mode)
  if (options.sourceCodeAccess && options.cwd?.trim()) {
    config.cwd = options.cwd.trim();
  }

  // Headers
  if (options.headers && options.headers.mode !== "default") {
    config.offensiveHeaders = {
      mode: options.headers.mode,
      headers:
        options.headers.mode === "custom"
          ? options.headers.customHeaders
          : undefined,
    };
  }

  return config;
}
