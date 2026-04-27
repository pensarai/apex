import type { BurpSuiteIntegrationConfig } from "../../../session";
import type { BurpMcpUserConfig } from "../../../config/config";

export const DEFAULT_BURP_PROXY_URL = "http://127.0.0.1:8080";
export const DEFAULT_BURP_MCP_SSE_URL = "http://127.0.0.1:9876/sse";
export const DEFAULT_BURP_MCP_PROXY_COMMAND = "java";
export const DEFAULT_BURP_MCP_TIMEOUT_MS = 15_000;

export type ResolvedBurpSuiteConfig = {
  enabled: true;
  transport: "sse" | "stdio";
  proxyUrl: string;
  sseUrl: string;
  /** Backwards-compatible alias for older call sites. */
  mcpSseUrl: string;
  mcpProxyCommand: string;
  mcpProxyArgs?: string[];
  timeoutMs: number;
  allowedTargets: string[];
  allowConfigMutation: boolean;
  ignoreTlsErrors: boolean;
  warnings: string[];
};

function isLocalHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".localhost")
  );
}

export function isLocalBurpMcpUrl(url: string): boolean {
  try {
    return isLocalHostname(new URL(url).hostname);
  } catch {
    return false;
  }
}

export function normalizeBurpMcpUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Burp MCP URL must use http or https.");
  }
  return parsed.toString().replace(/\/$/, "");
}

export function sanitizeBurpConfigForDisplay(config: ResolvedBurpSuiteConfig) {
  return {
    enabled: true,
    transport: config.transport,
    sseUrl: config.sseUrl,
    proxyUrl: config.proxyUrl,
    timeoutMs: config.timeoutMs,
    allowedTargets: config.allowedTargets,
    allowConfigMutation: config.allowConfigMutation,
    ignoreTlsErrors: config.ignoreTlsErrors,
    warnings: config.warnings,
  };
}

export function resolveBurpSuiteConfig(
  config: BurpSuiteIntegrationConfig | undefined,
  userConfig?: BurpMcpUserConfig | undefined,
): ResolvedBurpSuiteConfig | undefined {
  const enabled = config?.enabled ?? userConfig?.enabled ?? false;
  if (!enabled) return undefined;

  const warnings: string[] = [];
  const rawSseUrl =
    config?.sseUrl ??
    config?.mcpSseUrl ??
    userConfig?.sseUrl ??
    DEFAULT_BURP_MCP_SSE_URL;
  const sseUrl = normalizeBurpMcpUrl(rawSseUrl);

  if (!isLocalBurpMcpUrl(sseUrl)) {
    warnings.push(
      `Burp MCP URL is non-local (${sseUrl}). Ensure this is intentional and trusted.`,
    );
  }

  const transport = config?.transport ?? userConfig?.transport ?? "sse";
  const mcpProxyArgs = config?.mcpProxyArgs ?? userConfig?.stdioArgs;

  return {
    enabled: true,
    transport,
    proxyUrl:
      config?.proxyUrl ?? userConfig?.proxyUrl ?? DEFAULT_BURP_PROXY_URL,
    sseUrl,
    mcpSseUrl: sseUrl,
    mcpProxyCommand:
      config?.mcpProxyCommand ??
      userConfig?.stdioCommand ??
      DEFAULT_BURP_MCP_PROXY_COMMAND,
    mcpProxyArgs,
    timeoutMs:
      config?.timeoutMs ?? userConfig?.timeoutMs ?? DEFAULT_BURP_MCP_TIMEOUT_MS,
    allowedTargets: config?.allowedTargets ?? userConfig?.allowedTargets ?? [],
    allowConfigMutation:
      config?.allowConfigMutation ?? userConfig?.allowConfigMutation ?? false,
    ignoreTlsErrors:
      config?.ignoreTlsErrors ?? userConfig?.ignoreTlsErrors ?? false,
    warnings,
  };
}
