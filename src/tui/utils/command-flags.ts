/**
 * Command Flag Parsing Utilities
 *
 * General-purpose flag parsing for CLI-style commands.
 * Supports: --flag value, --flag=value, --boolean-flag
 */

import { readFileSync } from "fs";
import { isAbsolute, resolve } from "path";
import type { OperatorMode } from "../../core/operator";
import type { SessionConfig } from "../../core/session";
import { createToolsetState } from "../../core/toolset";
import { createThreatModelPrompt } from "../../core/utils/prompt";
import { parseTargetUrl } from "../../util/url";

/**
 * Combine resolved threat model and prompt into a single prompt string.
 * Threat model comes first (if present), then user prompt.
 * Returns undefined if both are empty.
 */
export function combinePromptParts(
  threatModel?: string,
  prompt?: string,
): string | undefined {
  const parts: string[] = [];
  if (threatModel) parts.push(threatModel);
  if (prompt) parts.push(prompt);
  return parts.length > 0 ? parts.join("\n\n") : undefined;
}

// ============================================================================
// Value Resolution
// ============================================================================

/**
 * Resolve a flag value that may be an inline string or a file reference.
 *
 * If `value` starts with `@`, the remainder is treated as a file path:
 * - Absolute paths are used as-is
 * - Relative paths are resolved against `process.cwd()`
 * - The file contents are returned as a UTF-8 string
 *
 * Otherwise the value is returned as-is.
 */
export function resolveFlagValue(value: string): string {
  if (value.startsWith("@")) {
    const filePath = value.slice(1);
    const resolved = isAbsolute(filePath)
      ? filePath
      : resolve(process.cwd(), filePath);
    return readFileSync(resolved, "utf-8");
  }
  return value;
}

/**
 * Resolve a threat model value and wrap it with a usage preamble.
 *
 * Uses `resolveFlagValue()` for `@file` support, then wraps the content
 * with instructions on how the pentest agent should use the threat model.
 */
export function resolveThreatModelPrompt(value: string): string {
  const content = resolveFlagValue(value);
  return createThreatModelPrompt(content);
}

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
    const arg = args[i];

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
      const camelName = resolvedName.replace(/-([a-z])/g, (_, c) =>
        c.toUpperCase(),
      );

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
  requireApproval?: boolean;
  autopilot?: boolean;

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

  // Internal flag to track if hosts was explicitly provided (not auto-populated)
  _hostsExplicitlyProvided?: boolean;
  // Sandbox option
  sandbox?: boolean;

  // Prompt option
  prompt?: string;

  // Threat model option
  threatModel?: string;

  // Task-driven mode (experimental — structured task tracking for training data)
  taskDriven?: boolean;
}

/**
 * Schema for web command flags
 */
const webFlagSchema: FlagSchema = {
  target: { type: "string", aliases: ["t"] },
  name: { type: "string", aliases: ["n"] },
  swarm: { type: "boolean" },
  mode: { type: "string", aliases: ["m"] },
  "require-approval": { type: "boolean" },
  "no-approval": { type: "boolean" },
  autopilot: { type: "boolean" },
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
  sandbox: { type: "boolean" },
  prompt: { type: "string" },
  "threat-model": { type: "string" },
  "task-driven": { type: "boolean" },
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
  if (raw.requireApproval) flags.requireApproval = true;
  if (raw.noApproval) flags.requireApproval = false;
  if (raw.autopilot) {
    flags.autopilot = true;
    flags.requireApproval = false;
  }

  // Auth options
  if (raw.authUrl) flags.authUrl = String(raw.authUrl);
  if (raw.authUser) flags.authUser = String(raw.authUser);
  if (raw.authPass) flags.authPass = String(raw.authPass);
  if (raw.authInstructions)
    flags.authInstructions = String(raw.authInstructions);

  // Scope options
  if (raw.hosts) {
    flags.hosts = String(raw.hosts)
      .split(",")
      .map((h) => h.trim())
      .filter(Boolean);
    flags._hostsExplicitlyProvided = true;
  }
  if (raw.ports) {
    flags.ports = String(raw.ports)
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !isNaN(p));
  }

  // Keep skipped-wizard CLI scope aligned with wizard auto-population.
  if (flags.target) {
    const parsed = parseTargetUrl(flags.target);
    if (parsed) {
      if (!flags.hosts?.includes(parsed.hostname)) {
        flags.hosts = [...(flags.hosts || []), parsed.hostname];
      }

      if (parsed.port && !flags.ports?.includes(parsed.port)) {
        flags.ports = [...(flags.ports || []), parsed.port];
      }
    }
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

  // Sandbox option
  if (raw.sandbox) flags.sandbox = true;

  // Prompt option — resolve @file references
  if (raw.prompt) flags.prompt = resolveFlagValue(String(raw.prompt));

  // Threat model option — resolve @file references and wrap with preamble
  if (raw.threatModel)
    flags.threatModel = resolveThreatModelPrompt(String(raw.threatModel));

  // Task-driven mode
  if (raw.taskDriven) flags.taskDriven = true;

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
      flags.requireApproval !== undefined ||
      flags.authUrl ||
      flags.authUser ||
      flags._hostsExplicitlyProvided ||
      flags.strict ||
      flags.headersMode ||
      flags.model
    );
  }

  // For swarm mode, just need target
  return true;
}

export interface SessionCreateParams {
  targets: string[];
  name?: string;
  config: SessionConfig;
}

/**
 * Build operator session config from CLI flags (no session creation).
 */
export function buildOperatorSessionConfig(
  flags: WebCommandFlags,
): SessionCreateParams {
  const sessionConfig: SessionConfig = {
    sessionType: "web-app",
    mode: "operator",
    operatorSettings: {
      initialMode: flags.mode || "manual",
      requireApproval: flags.requireApproval ?? true,
      enableSuggestions: true,
    },
    toolsetState: createToolsetState("web-pentest"),
  };

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

  if (flags.hosts?.length || flags.ports?.length || flags.strict) {
    sessionConfig.scopeConstraints = {
      allowedHosts: flags.hosts,
      allowedPorts: flags.ports,
      strictScope: flags.strict,
    };
  }

  if (flags.headersMode && flags.headersMode !== "default") {
    sessionConfig.offensiveHeaders = {
      mode: flags.headersMode,
      headers: flags.headersMode === "custom" ? flags.customHeaders : undefined,
    };
  }

  sessionConfig.agentCwd = flags.sandbox ? undefined : process.cwd();
  if (flags.taskDriven) sessionConfig.taskDriven = true;

  // Combine threat model and prompt into a single prompt field
  const combinedPrompt = combinePromptParts(flags.threatModel, flags.prompt);
  if (combinedPrompt) {
    sessionConfig.prompt = combinedPrompt;
  }

  return {
    targets: flags.target ? [flags.target] : [],
    name: flags.name || undefined,
    config: sessionConfig,
  };
}

/**
 * Build swarm session config from CLI flags (no session creation).
 */
export function buildSwarmSessionConfig(
  flags: WebCommandFlags,
): SessionCreateParams {
  const sessionConfig: SessionConfig = {
    sessionType: "web-app",
    mode: "auto",
    toolsetState: createToolsetState("web-pentest"),
  };

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

  if (flags.hosts?.length || flags.ports?.length || flags.strict) {
    sessionConfig.scopeConstraints = {
      allowedHosts: flags.hosts,
      allowedPorts: flags.ports,
      strictScope: flags.strict,
    };
  }

  if (flags.headersMode && flags.headersMode !== "default") {
    sessionConfig.offensiveHeaders = {
      mode: flags.headersMode,
      headers: flags.headersMode === "custom" ? flags.customHeaders : undefined,
    };
  }

  // Combine threat model and prompt into a single prompt field
  const combinedPrompt = combinePromptParts(flags.threatModel, flags.prompt);
  if (combinedPrompt) {
    sessionConfig.prompt = combinedPrompt;
  }

  return {
    targets: [flags.target!],
    name: flags.name || undefined,
    config: sessionConfig,
  };
}
