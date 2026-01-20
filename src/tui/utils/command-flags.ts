/**
 * Command Flag Parsing Utilities
 *
 * General-purpose flag parsing for CLI-style commands.
 * Supports: --flag value, --flag=value, --boolean-flag
 */

import { Session } from "../../core/session";
import { generateRandomName } from "../../util/name";
import type { OperatorMode, PermissionTier } from "../../core/operator";
import { createToolsetState } from "../../core/toolset";

// ============================================================================
// General Flag Parsing
// ============================================================================

export interface ParsedFlags {
  [key: string]: string | boolean | string[] | undefined;
}

export interface FlagSchema {
  [flagName: string]: {
    type: "string" | "boolean" | "array";
    aliases?: string[];
  };
}

/**
 * Parse CLI-style arguments into a flags object
 * Supports: --flag value, --flag=value, --boolean-flag
 */
export function parseFlags(args: string[], schema: FlagSchema): ParsedFlags {
  const result: ParsedFlags = {};
  let i = 0;

  // Build alias map
  const aliasMap: Record<string, string> = {};
  for (const [flagName, config] of Object.entries(schema)) {
    if (config.aliases) {
      for (const alias of config.aliases) {
        aliasMap[alias] = flagName;
      }
    }
  }

  while (i < args.length) {
    let arg = args[i];

    // Check for --flag or -f
    if (arg.startsWith("--") || (arg.startsWith("-") && arg.length === 2)) {
      let flagName: string;
      let value: string | undefined;

      // Handle --flag=value syntax
      if (arg.includes("=")) {
        const eqIdx = arg.indexOf("=");
        flagName = arg.slice(arg.startsWith("--") ? 2 : 1, eqIdx);
        value = arg.slice(eqIdx + 1);
      } else {
        flagName = arg.startsWith("--") ? arg.slice(2) : arg.slice(1);
      }

      // Resolve alias
      const resolvedName = aliasMap[flagName] || flagName;

      // Convert kebab-case to camelCase
      const camelName = resolvedName.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

      const config = schema[resolvedName] || schema[camelName];
      if (config) {
        if (config.type === "boolean") {
          result[camelName] = true;
        } else if (config.type === "array") {
          // For array type, value might be from next arg
          if (!value && i + 1 < args.length && !args[i + 1].startsWith("-")) {
            value = args[++i];
          }
          if (value) {
            if (!result[camelName]) {
              result[camelName] = [];
            }
            (result[camelName] as string[]).push(value);
          }
        } else {
          // String type
          if (!value && i + 1 < args.length && !args[i + 1].startsWith("-")) {
            value = args[++i];
          }
          if (value) {
            result[camelName] = value;
          }
        }
      } else {
        // Unknown flag - try to handle gracefully
        // Check if next arg looks like a value
        if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
          result[camelName] = args[++i];
        } else {
          result[camelName] = true;
        }
      }
    }
    i++;
  }

  return result;
}

// ============================================================================
// Web Command Specific Types and Parsing
// ============================================================================

export interface WebCommandFlags {
  // Basic options
  target?: string;
  name?: string;
  swarm?: boolean; // Use swarm mode instead of operator mode

  // Operator mode options (ignored if swarm)
  mode?: OperatorMode;
  tier?: number;

  // Auth options
  authUrl?: string;
  authUser?: string;
  authPass?: string;
  authInstructions?: string;

  // Scope options
  hosts?: string[];
  ports?: number[];
  strict?: boolean;

  // Headers options
  headersMode?: "none" | "default" | "custom";
  customHeaders?: Record<string, string>;

  // Model option
  model?: string;
}

/**
 * Schema for web command flags
 */
const webFlagSchema: FlagSchema = {
  target: { type: "string", aliases: ["t"] },
  name: { type: "string", aliases: ["n"] },
  swarm: { type: "boolean" },
  mode: { type: "string", aliases: ["m"] },
  tier: { type: "string" },
  "auth-url": { type: "string" },
  "auth-user": { type: "string" },
  "auth-pass": { type: "string" },
  "auth-instructions": { type: "string" },
  hosts: { type: "string" },
  ports: { type: "string" },
  strict: { type: "boolean" },
  headers: { type: "string" },
  header: { type: "array" },
  model: { type: "string" },
  // Legacy --auto flag maps to --swarm
  auto: { type: "boolean" },
};

/**
 * Parse web command arguments into WebCommandFlags
 */
export function parseWebFlags(args: string[]): WebCommandFlags {
  const raw = parseFlags(args, webFlagSchema);
  const flags: WebCommandFlags = {};

  // Basic options
  if (raw.target) flags.target = String(raw.target);
  if (raw.name) flags.name = String(raw.name);
  if (raw.swarm || raw.auto) flags.swarm = true;

  // Operator mode options
  if (raw.mode) {
    const mode = String(raw.mode).toLowerCase();
    if (mode === "plan" || mode === "manual" || mode === "auto") {
      flags.mode = mode as OperatorMode;
    }
  }
  if (raw.tier) {
    const tier = parseInt(String(raw.tier), 10);
    if (tier >= 1 && tier <= 5) {
      flags.tier = tier;
    }
  }

  // Auth options
  if (raw.authUrl) flags.authUrl = String(raw.authUrl);
  if (raw.authUser) flags.authUser = String(raw.authUser);
  if (raw.authPass) flags.authPass = String(raw.authPass);
  if (raw.authInstructions) flags.authInstructions = String(raw.authInstructions);

  // Scope options
  if (raw.hosts) {
    flags.hosts = String(raw.hosts).split(",").map((h) => h.trim()).filter(Boolean);
  }
  if (raw.ports) {
    flags.ports = String(raw.ports)
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !isNaN(p));
  }
  if (raw.strict) flags.strict = true;

  // Headers options
  if (raw.headers) {
    const hmode = String(raw.headers).toLowerCase();
    if (hmode === "none" || hmode === "default" || hmode === "custom") {
      flags.headersMode = hmode as "none" | "default" | "custom";
    }
  }
  if (raw.header && Array.isArray(raw.header)) {
    flags.customHeaders = {};
    for (const h of raw.header) {
      const colonIdx = h.indexOf(":");
      if (colonIdx > 0) {
        const name = h.slice(0, colonIdx).trim();
        const value = h.slice(colonIdx + 1).trim();
        flags.customHeaders[name] = value;
      }
    }
    // If we have custom headers, set mode to custom
    if (Object.keys(flags.customHeaders).length > 0 && !flags.headersMode) {
      flags.headersMode = "custom";
    }
  }

  // Model option
  if (raw.model) flags.model = String(raw.model);

  return flags;
}

/**
 * Check if flags have enough information to skip the wizard
 * Requires at least a target to skip wizard
 */
export function hasEnoughFlagsToSkipWizard(flags: WebCommandFlags): boolean {
  // Must have target to skip wizard
  if (!flags.target) return false;

  // For operator mode, need at least mode or tier set to indicate intent
  // to skip wizard (otherwise user may want to configure)
  if (!flags.swarm) {
    // Operator mode - skip wizard if any additional config is provided
    return !!(
      flags.mode ||
      flags.tier ||
      flags.authUrl ||
      flags.authUser ||
      flags.hosts ||
      flags.strict ||
      flags.headersMode ||
      flags.model
    );
  }

  // For swarm mode, just need target
  return true;
}

/**
 * Create an operator session from CLI flags
 */
export async function createOperatorSessionFromFlags(
  flags: WebCommandFlags
): Promise<Session.SessionInfo> {
  const sessionConfig: Session.SessionConfig = {
    sessionType: "web-app",
    mode: "operator",
    operatorSettings: {
      initialMode: flags.mode || "manual",
      autoApproveTier: (flags.tier || 2) as PermissionTier,
      enableSuggestions: true,
    },
    // Initialize toolset with full web-pentest tools
    toolsetState: createToolsetState("web-pentest"),
  };

  // Auth config
  if (flags.authInstructions || flags.authUser) {
    sessionConfig.authenticationInstructions = flags.authInstructions;
    if (flags.authUser) {
      sessionConfig.authCredentials = {
        username: flags.authUser,
        password: flags.authPass || "",
        loginUrl: flags.authUrl,
      };
    }
  }

  // Scope constraints
  if (flags.hosts?.length || flags.ports?.length || flags.strict) {
    sessionConfig.scopeConstraints = {
      allowedHosts: flags.hosts,
      allowedPorts: flags.ports,
      strictScope: flags.strict,
    };
  }

  // Headers config
  if (flags.headersMode && flags.headersMode !== "default") {
    sessionConfig.offensiveHeaders = {
      mode: flags.headersMode,
      headers: flags.headersMode === "custom" ? flags.customHeaders : undefined,
    };
  }

  const session = await Session.create({
    targets: [flags.target!],
    name: flags.name || generateRandomName(),
    config: sessionConfig,
  });

  return session;
}

/**
 * Create a swarm session from CLI flags
 */
export async function createSwarmSessionFromFlags(
  flags: WebCommandFlags
): Promise<Session.SessionInfo> {
  const sessionConfig: Session.SessionConfig = {
    sessionType: "web-app",
    mode: "auto",
    // Initialize toolset with full web-pentest tools
    toolsetState: createToolsetState("web-pentest"),
  };

  // Auth config
  if (flags.authInstructions || flags.authUser) {
    sessionConfig.authenticationInstructions = flags.authInstructions;
    if (flags.authUser) {
      sessionConfig.authCredentials = {
        username: flags.authUser,
        password: flags.authPass || "",
        loginUrl: flags.authUrl,
      };
    }
  }

  // Scope constraints
  if (flags.hosts?.length || flags.ports?.length || flags.strict) {
    sessionConfig.scopeConstraints = {
      allowedHosts: flags.hosts,
      allowedPorts: flags.ports,
      strictScope: flags.strict,
    };
  }

  // Headers config
  if (flags.headersMode && flags.headersMode !== "default") {
    sessionConfig.offensiveHeaders = {
      mode: flags.headersMode,
      headers: flags.headersMode === "custom" ? flags.customHeaders : undefined,
    };
  }

  const session = await Session.create({
    targets: [flags.target!],
    name: flags.name || generateRandomName(),
    config: sessionConfig,
  });

  return session;
}
