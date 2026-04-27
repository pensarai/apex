#!/usr/bin/env bun

/**
 * pensar burp — Manage Burp Suite MCP integration
 */

import { readFileSync } from "fs";
import { config as appConfig } from "../core/config";
import type { BurpMcpUserConfig } from "../core/config/config";
import {
  DEFAULT_BURP_MCP_SSE_URL,
  DEFAULT_BURP_MCP_TIMEOUT_MS,
  DEFAULT_BURP_PROXY_URL,
  isLocalBurpMcpUrl,
  normalizeBurpMcpUrl,
  resolveBurpSuiteConfig,
  sanitizeBurpConfigForDisplay,
} from "../core/agents/offSecAgent/tools/burpConfig";
import {
  BurpMcpSession,
  parseRawHttpTarget,
  redactSensitiveHttpText,
} from "../core/agents/offSecAgent/tools/burpMcp";
import { isHostAllowed } from "../core/agents/offSecAgent/tools/scopeGuard";

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function hasFlag(flag: string, argv: string[]): boolean {
  return argv.includes(flag);
}

function showHelp(): void {
  console.log(`pensar burp — Manage Burp Suite MCP integration

Usage:
  pensar burp status
  pensar burp tools
  pensar burp proxy-history --target <url-or-host> [--limit N] [--regex <pattern>]
  pensar burp repeater --request-file <file>
  pensar burp send --request-file <file>
  pensar burp config
  pensar burp config set --url <url> --enabled true|false

Options:
  --target <url-or-host>      In-scope target to filter proxy history
  --limit <n>                 Max history items (default: 20)
  --regex <pattern>           Additional regex for proxy history filtering
  --request-file <file>       Raw HTTP request file
  --url <url>                 Burp MCP SSE URL
  --transport <sse|stdio>     MCP transport (default: sse)
  --timeout-ms <ms>           MCP timeout
  --allow-config-mutation     Enable config-modifying Burp MCP tools
  -h, --help                  Show this help message`);
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function hostFromTarget(value: string): string {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).hostname;
  } catch {
    throw new Error(`Invalid target: ${value}`);
  }
}

function assertTargetAllowed(hostname: string, cfg: BurpMcpUserConfig): void {
  const allowed = cfg.allowedTargets ?? [];
  if (allowed.length > 0 && !isHostAllowed(hostname, allowed)) {
    throw new Error(
      `Target is outside configured scope. Allowed targets: ${allowed.join(", ")}`,
    );
  }
}

async function getResolvedSession(): Promise<BurpMcpSession> {
  const current = await appConfig.get();
  const resolved = resolveBurpSuiteConfig(undefined, current.burpMcp);
  if (!resolved) {
    throw new Error(
      "Burp MCP integration is disabled. Run `pensar burp config set --enabled true` first.",
    );
  }
  return new BurpMcpSession(resolved);
}

async function runStatus(): Promise<void> {
  const current = await appConfig.get();
  const resolved = resolveBurpSuiteConfig(undefined, current.burpMcp);
  if (!resolved) {
    console.log(
      JSON.stringify(
        {
          enabled: false,
          transport: current.burpMcp?.transport ?? "sse",
          sseUrl: current.burpMcp?.sseUrl ?? DEFAULT_BURP_MCP_SSE_URL,
        },
        null,
        2,
      ),
    );
    return;
  }

  const session = new BurpMcpSession(resolved);
  try {
    const tools = await session.listTools();
    const names = new Set(tools.map((t) => t.name));
    console.log(
      JSON.stringify(
        {
          ...sanitizeBurpConfigForDisplay(resolved),
          reachable: true,
          toolCount: tools.length,
          capabilities: {
            proxyHistory: names.has("get_proxy_http_history"),
            proxyHistoryRegex: names.has("get_proxy_http_history_regex"),
            repeater: names.has("create_repeater_tab"),
            intruder: names.has("send_to_intruder"),
            collaborator:
              names.has("generate_collaborator_payload") ||
              names.has("poll_collaborator_interactions"),
            intercept:
              names.has("get_proxy_intercept") ||
              names.has("set_proxy_intercept"),
          },
        },
        null,
        2,
      ),
    );
  } finally {
    await session.disconnect();
  }
}

async function runTools(): Promise<void> {
  const session = await getResolvedSession();
  try {
    const tools = await session.listTools();
    console.log(JSON.stringify(tools, null, 2));
  } finally {
    await session.disconnect();
  }
}

async function runConfig(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub !== "set") {
    const current = await appConfig.get();
    const resolved = resolveBurpSuiteConfig(undefined, current.burpMcp);
    console.log(
      JSON.stringify(
        resolved
          ? sanitizeBurpConfigForDisplay(resolved)
          : {
              enabled: current.burpMcp?.enabled ?? false,
              transport: current.burpMcp?.transport ?? "sse",
              sseUrl: current.burpMcp?.sseUrl ?? DEFAULT_BURP_MCP_SSE_URL,
              proxyUrl: current.burpMcp?.proxyUrl ?? DEFAULT_BURP_PROXY_URL,
              timeoutMs:
                current.burpMcp?.timeoutMs ?? DEFAULT_BURP_MCP_TIMEOUT_MS,
              allowConfigMutation:
                current.burpMcp?.allowConfigMutation ?? false,
              allowedTargets: current.burpMcp?.allowedTargets ?? [],
            },
        null,
        2,
      ),
    );
    return;
  }

  const current = await appConfig.get();
  const next: BurpMcpUserConfig = { ...(current.burpMcp ?? {}) };
  const enabled = parseBoolean(getFlag("--enabled", args));
  const url = getFlag("--url", args);
  const transport = getFlag("--transport", args);
  const timeoutMs = getFlag("--timeout-ms", args);
  const allowedTargets = getFlag("--allowed-targets", args);

  if (enabled !== undefined) next.enabled = enabled;
  if (url) next.sseUrl = normalizeBurpMcpUrl(url);
  if (transport === "sse" || transport === "stdio") next.transport = transport;
  if (timeoutMs) next.timeoutMs = parseInt(timeoutMs, 10);
  if (allowedTargets) {
    next.allowedTargets = allowedTargets
      .split(",")
      .map((target) => target.trim())
      .filter(Boolean);
  }
  if (hasFlag("--allow-config-mutation", args)) {
    next.allowConfigMutation = true;
  }

  await appConfig.update({ burpMcp: next });
  if (next.sseUrl && !isLocalBurpMcpUrl(next.sseUrl)) {
    console.warn(
      `Warning: Burp MCP URL is non-local (${next.sseUrl}). Ensure this endpoint is trusted.`,
    );
  }
  console.log(JSON.stringify({ burpMcp: next }, null, 2));
}

async function callFirstAvailable(
  session: BurpMcpSession,
  candidates: string[],
  args: Record<string, unknown>,
): Promise<{ toolName: string; result: string }> {
  for (const candidate of candidates) {
    if (await session.hasTool(candidate)) {
      return {
        toolName: candidate,
        result: await session.callTool(candidate, args),
      };
    }
  }
  throw new Error(
    `Burp MCP tool '${candidates[0]}' is not available. Check extension version or enabled permissions.`,
  );
}

async function runProxyHistory(args: string[]): Promise<void> {
  const target = getFlag("--target", args);
  if (!target) throw new Error("--target is required");
  const targetHost = hostFromTarget(target);
  const current = await appConfig.get();
  assertTargetAllowed(targetHost, current.burpMcp ?? {});

  const limit = parseInt(getFlag("--limit", args) ?? "20", 10);
  const regex = getFlag("--regex", args);
  const effectiveRegex = regex
    ? `(?=.*(?:${targetHost}))(?=.*(?:${regex}))`
    : targetHost;

  const session = await getResolvedSession();
  try {
    const { toolName, result } = await callFirstAvailable(
      session,
      ["get_proxy_http_history_regex"],
      { regex: effectiveRegex, count: limit, offset: 0 },
    );
    console.log(
      JSON.stringify(
        {
          toolName,
          target: targetHost,
          result: redactSensitiveHttpText(result),
        },
        null,
        2,
      ),
    );
  } finally {
    await session.disconnect();
  }
}

async function runRepeater(args: string[]): Promise<void> {
  const requestFile = getFlag("--request-file", args);
  if (!requestFile) throw new Error("--request-file is required");
  const content = readFileSync(requestFile, "utf-8");
  const target = parseRawHttpTarget(content);
  if (!target) {
    throw new Error(
      "Raw request must include a Host header or explicit target fields.",
    );
  }
  const current = await appConfig.get();
  assertTargetAllowed(target.targetHostname, current.burpMcp ?? {});

  const session = await getResolvedSession();
  try {
    const { toolName, result } = await callFirstAvailable(
      session,
      ["create_repeater_tab"],
      {
        content,
        targetHostname: target.targetHostname,
        targetPort: target.targetPort,
        usesHttps: target.usesHttps,
      },
    );
    console.log(JSON.stringify({ toolName, result }, null, 2));
  } finally {
    await session.disconnect();
  }
}

async function runSend(args: string[]): Promise<void> {
  const requestFile = getFlag("--request-file", args);
  if (!requestFile) throw new Error("--request-file is required");
  const content = readFileSync(requestFile, "utf-8");
  const target = parseRawHttpTarget(content);
  if (!target) {
    throw new Error(
      "Raw request must include a Host header or explicit target fields.",
    );
  }
  const current = await appConfig.get();
  assertTargetAllowed(target.targetHostname, current.burpMcp ?? {});

  const session = await getResolvedSession();
  try {
    const { toolName, result } = await callFirstAvailable(
      session,
      ["send_http_request", "send_http1_request", "send_request"],
      {
        content,
        targetHostname: target.targetHostname,
        targetPort: target.targetPort,
        usesHttps: target.usesHttps,
      },
    );
    console.log(
      JSON.stringify(
        { toolName, result: redactSensitiveHttpText(result) },
        null,
        2,
      ),
    );
  } finally {
    await session.disconnect();
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];
  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    showHelp();
    return;
  }

  try {
    if (sub === "status") await runStatus();
    else if (sub === "tools") await runTools();
    else if (sub === "config") await runConfig(args.slice(1));
    else if (sub === "proxy-history") await runProxyHistory(args.slice(1));
    else if (sub === "repeater") await runRepeater(args.slice(1));
    else if (sub === "send") await runSend(args.slice(1));
    else throw new Error(`Unknown burp command '${sub}'`);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

main();
