import { tool } from "ai";
import { z } from "zod";
import { appendFileSync, mkdirSync } from "fs";
import { join } from "path";
import { GenericMcpClient, type McpToolDefinition } from "../../../mcp/client";
import type { ToolContext } from "./types";
import {
  resolveBurpSuiteConfig,
  type ResolvedBurpSuiteConfig,
} from "./burpConfig";
import {
  getAllowedHosts,
  isHostAllowed,
  ScopeViolationError,
} from "./scopeGuard";

const CONFIG_MUTATION_TOOL_PATTERN =
  /\b(set|update|modify|export|import).*config\b/i;
const MAX_BURP_RESULT_CHARS = 12_000;

export function extractMcpText(result: unknown): string {
  if (result && typeof result === "object" && "content" in result) {
    const content = (result as { content?: unknown }).content;
    if (Array.isArray(content)) {
      return content
        .map((item) => {
          if (item && typeof item === "object" && "text" in item) {
            return String((item as { text: unknown }).text);
          }
          return JSON.stringify(item);
        })
        .join("\n");
    }
  }

  if (typeof result === "string") return result;
  return JSON.stringify(result, null, 2) ?? String(result);
}

export function parseRawHttpTarget(content: string): {
  targetHostname: string;
  targetPort: number;
  usesHttps: boolean;
} | null {
  const hostMatch = content.match(/^Host:\s*([^\r\n]+)$/im);
  if (!hostMatch) return null;

  const host = hostMatch[1].trim();
  const [hostname, portText] = host.split(":");
  if (!hostname) return null;

  const parsedPort = portText ? parseInt(portText, 10) : undefined;
  const targetPort =
    typeof parsedPort === "number" && Number.isFinite(parsedPort)
      ? parsedPort
      : 80;
  return {
    targetHostname: hostname,
    targetPort,
    usesHttps: targetPort === 443,
  };
}

export function redactSensitiveHttpText(text: string): string {
  return text
    .replace(
      /^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|Api-Key):\s*.*$/gim,
      "$1: <redacted>",
    )
    .replace(
      /("(?:password|passwd|token|secret|apiKey|accessToken|refreshToken)"\s*:\s*)"[^"]*"/gi,
      '$1"<redacted>"',
    );
}

function truncateResult(text: string): string {
  if (text.length <= MAX_BURP_RESULT_CHARS) return text;
  return `${text.slice(0, MAX_BURP_RESULT_CHARS)}\n\n(truncated Burp MCP result; full response omitted to avoid storing excessive proxy data)`;
}

function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(args).map(([key, value]) => {
      if (typeof value === "string") {
        return [key, redactSensitiveHttpText(value).slice(0, 2_000)];
      }
      return [key, value];
    }),
  );
}

function summarizeBurpResult(result: string): string {
  const redacted = redactSensitiveHttpText(result);
  return truncateResult(redacted);
}

function resolveRawHttpTarget(input: {
  content: string;
  targetHostname?: string;
  targetPort?: number;
  usesHttps?: boolean;
}):
  | {
      success: true;
      targetHostname: string;
      targetPort: number;
      usesHttps: boolean;
    }
  | { success: false; error: string } {
  const parsed = parseRawHttpTarget(input.content);
  const targetHostname = input.targetHostname ?? parsed?.targetHostname;
  const targetPort = input.targetPort ?? parsed?.targetPort;
  const usesHttps = input.usesHttps ?? parsed?.usesHttps;

  if (!targetHostname || targetPort == null || usesHttps == null) {
    return {
      success: false,
      error:
        "targetHostname, targetPort, and usesHttps are required when the raw request has no usable Host header.",
    };
  }

  return {
    success: true,
    targetHostname,
    targetPort,
    usesHttps,
  };
}

export class BurpMcpSession {
  private client: GenericMcpClient;
  private toolsCache: McpToolDefinition[] | null = null;

  constructor(private readonly config: ResolvedBurpSuiteConfig) {
    this.client = new GenericMcpClient({
      name: "apex-burp",
      version: "1.0.0",
      transport: config.transport,
      url: config.sseUrl,
      command: config.mcpProxyCommand,
      args: config.mcpProxyArgs,
      timeoutMs: config.timeoutMs,
    });
  }

  async disconnect(): Promise<void> {
    await this.client.disconnect();
  }

  async listTools(): Promise<McpToolDefinition[]> {
    if (!this.toolsCache) {
      this.toolsCache = (await this.client.listTools()).sort((a, b) =>
        a.name.localeCompare(b.name),
      );
    }
    return this.toolsCache;
  }

  async listToolNames(): Promise<string[]> {
    return (await this.listTools()).map((tool) => tool.name);
  }

  async hasTool(toolName: string): Promise<boolean> {
    return (await this.listToolNames()).includes(toolName);
  }

  async callTool(
    toolName: string,
    args: Record<string, unknown>,
    abortSignal?: AbortSignal,
  ): Promise<string> {
    if (!(await this.hasTool(toolName))) {
      throw new Error(
        `Burp MCP tool '${toolName}' is not available. Check the Burp MCP extension version or enabled permissions.`,
      );
    }

    if (
      !this.config.allowConfigMutation &&
      CONFIG_MUTATION_TOOL_PATTERN.test(toolName)
    ) {
      throw new Error(
        `Burp MCP tool '${toolName}' can modify Burp configuration. Set allowConfigMutation explicitly before using config-modifying tools.`,
      );
    }

    const result = await this.client.callTool(toolName, args, abortSignal);
    return extractMcpText(result);
  }
}

function createUnavailableTool(description: string) {
  return tool({
    description,
    inputSchema: z.object({
      toolCallDescription: z.string().describe("Why you need to use Burp"),
    }),
    execute: async () => ({
      success: false,
      error: "Burp Suite integration is not enabled for this session.",
    }),
  });
}

export const BURP_TOOL_NAMES = [
  "burp_check_connection",
  "burp_get_proxy_http_history",
  "burp_search_proxy_http_history",
  "burp_get_proxy_websocket_history",
  "burp_send_to_repeater",
  "burp_send_to_intruder",
  "burp_send_http_request",
  "burp_generate_collaborator_payload",
  "burp_poll_collaborator_interactions",
  "burp_get_proxy_intercept_state",
  "burp_set_proxy_intercept_state",
  "burp_get_scanner_issues",
] as const;

export type BurpToolName = (typeof BURP_TOOL_NAMES)[number];

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function scopedHistoryRegex(ctx: ToolContext): string | undefined {
  const allowedHosts = getAllowedHosts(ctx);
  if (allowedHosts.length === 0) return undefined;
  return allowedHosts.map(escapeRegex).join("|");
}

function assertRawHttpTargetInScope(
  target: { targetHostname: string },
  ctx: ToolContext,
): void {
  const allowedHosts = getAllowedHosts(ctx);
  if (allowedHosts.length === 0) return;
  if (!isHostAllowed(target.targetHostname, allowedHosts)) {
    throw new ScopeViolationError(target.targetHostname, allowedHosts);
  }
}

function writeBurpActionLog(
  ctx: ToolContext,
  entry: {
    toolName: string;
    target?: string;
    args: Record<string, unknown>;
    success: boolean;
    resultSummary?: string;
    error?: string;
  },
): void {
  try {
    const dir = join(ctx.session.logsPath, "burp");
    mkdirSync(dir, { recursive: true });
    appendFileSync(
      join(dir, "actions.jsonl"),
      `${JSON.stringify({
        timestamp: new Date().toISOString(),
        ...entry,
        args: sanitizeArgs(entry.args),
      })}\n`,
    );
  } catch {
    // Burp logging should never make the user-facing action fail.
  }
}

export function createBurpToolset(ctx: ToolContext) {
  const burp = resolveBurpSuiteConfig(ctx.session.config?.burpSuite);

  if (!burp) {
    return Object.fromEntries(
      BURP_TOOL_NAMES.map((name) => [
        name,
        createUnavailableTool(`${name} is unavailable until Burp is enabled.`),
      ]),
    ) as Record<BurpToolName, ReturnType<typeof createUnavailableTool>>;
  }

  const session = new BurpMcpSession(burp);
  if (ctx.abortSignal) {
    const onAbort = () => session.disconnect().catch(() => {});
    ctx.abortSignal.addEventListener("abort", onAbort, { once: true });
  }

  const callBurp = async (
    toolName: string,
    args: Record<string, unknown>,
    target?: string,
  ) => {
    try {
      const text = await session.callTool(toolName, args, ctx.abortSignal);
      const result = summarizeBurpResult(text);
      writeBurpActionLog(ctx, {
        toolName,
        target,
        args,
        success: true,
        resultSummary: result.slice(0, 1_000),
      });
      return { success: true, result };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      writeBurpActionLog(ctx, {
        toolName,
        target,
        args,
        success: false,
        error: message,
      });
      return {
        success: false,
        error: message,
      };
    }
  };

  const callFirstAvailable = async (
    toolNames: string[],
    args: Record<string, unknown>,
    target?: string,
  ) => {
    for (const toolName of toolNames) {
      if (await session.hasTool(toolName)) {
        return callBurp(toolName, args, target);
      }
    }
    return {
      success: false,
      error: `Burp MCP tool '${toolNames[0]}' is not available. Check the Burp MCP extension version or enabled permissions.`,
    };
  };

  return {
    burp_check_connection: tool({
      description:
        "Verify the Burp MCP connection and return the MCP tool names exposed by Burp.",
      inputSchema: z.object({
        toolCallDescription: z
          .string()
          .describe("Why you are checking the Burp MCP connection"),
      }),
      execute: async () => {
        try {
          const tools = await session.listTools();
          return {
            success: true,
            endpoint: burp.sseUrl,
            transport: burp.transport,
            warnings: burp.warnings,
            toolCount: tools.length,
            tools,
          };
        } catch (error: unknown) {
          return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      },
    }),

    burp_get_proxy_http_history: tool({
      description:
        "Read paginated items from Burp Proxy HTTP history. Community edition can expose proxy history when Burp MCP history access is allowed.",
      inputSchema: z.object({
        count: z.number().default(20).describe("Number of history items"),
        offset: z.number().default(0).describe("History offset"),
        toolCallDescription: z
          .string()
          .describe("Why you need to inspect Burp HTTP history"),
      }),
      execute: async ({ count, offset }) => {
        const regex = scopedHistoryRegex(ctx);
        if (regex && (await session.hasTool("get_proxy_http_history_regex"))) {
          return callBurp("get_proxy_http_history_regex", {
            regex,
            count,
            offset,
          });
        }
        if (regex) {
          return {
            success: false,
            error:
              "Target-scoped Burp history requires the get_proxy_http_history_regex tool, which is not available.",
          };
        }
        return callBurp("get_proxy_http_history", { count, offset });
      },
    }),

    burp_search_proxy_http_history: tool({
      description:
        "Search Burp Proxy HTTP history with a regex and return paginated matching items.",
      inputSchema: z.object({
        regex: z.string().describe("Regex to match against HTTP history items"),
        count: z.number().default(20).describe("Number of matching items"),
        offset: z.number().default(0).describe("Match offset"),
        toolCallDescription: z
          .string()
          .describe("Why you need to search Burp HTTP history"),
      }),
      execute: async ({ regex, count, offset }) => {
        const scoped = scopedHistoryRegex(ctx);
        const effectiveRegex = scoped
          ? `(?=.*(?:${scoped}))(?=.*(?:${regex}))`
          : regex;
        return callBurp("get_proxy_http_history_regex", {
          regex: effectiveRegex,
          count,
          offset,
        });
      },
    }),

    burp_get_proxy_websocket_history: tool({
      description:
        "Read paginated items from Burp Proxy WebSocket history when available.",
      inputSchema: z.object({
        count: z.number().default(20).describe("Number of history items"),
        offset: z.number().default(0).describe("History offset"),
        toolCallDescription: z
          .string()
          .describe("Why you need to inspect Burp WebSocket history"),
      }),
      execute: async ({ count, offset }) =>
        callBurp("get_proxy_websocket_history", { count, offset }),
    }),

    burp_send_to_repeater: tool({
      description:
        "Create a Burp Repeater tab from a raw HTTP/1.1 request. The Host header is used when target fields are omitted.",
      inputSchema: z.object({
        content: z
          .string()
          .describe("Raw HTTP request content with CRLF or LF line endings"),
        tabName: z.string().optional().describe("Optional Repeater tab name"),
        targetHostname: z.string().optional(),
        targetPort: z.number().optional(),
        usesHttps: z.boolean().optional(),
        toolCallDescription: z
          .string()
          .describe("Why this request should be sent to Repeater"),
      }),
      execute: async ({
        content,
        tabName,
        targetHostname,
        targetPort,
        usesHttps,
      }) => {
        const target = resolveRawHttpTarget({
          content,
          targetHostname,
          targetPort,
          usesHttps,
        });
        if (!target.success) return target;
        try {
          assertRawHttpTargetInScope(target, ctx);
        } catch (error) {
          return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
          };
        }

        return callBurp(
          "create_repeater_tab",
          {
            tabName,
            content,
            targetHostname: target.targetHostname,
            targetPort: target.targetPort,
            usesHttps: target.usesHttps,
          },
          target.targetHostname,
        );
      },
    }),

    burp_send_to_intruder: tool({
      description:
        "Send a raw HTTP/1.1 request to Burp Intruder. Availability depends on Burp edition and MCP tool exposure.",
      inputSchema: z.object({
        content: z
          .string()
          .describe("Raw HTTP request content with CRLF or LF line endings"),
        tabName: z.string().optional().describe("Optional Intruder tab name"),
        targetHostname: z.string().optional(),
        targetPort: z.number().optional(),
        usesHttps: z.boolean().optional(),
        toolCallDescription: z
          .string()
          .describe("Why this request should be sent to Intruder"),
      }),
      execute: async ({
        content,
        tabName,
        targetHostname,
        targetPort,
        usesHttps,
      }) => {
        const target = resolveRawHttpTarget({
          content,
          targetHostname,
          targetPort,
          usesHttps,
        });
        if (!target.success) return target;
        try {
          assertRawHttpTargetInScope(target, ctx);
        } catch (error) {
          return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
          };
        }

        return callBurp(
          "send_to_intruder",
          {
            tabName,
            content,
            targetHostname: target.targetHostname,
            targetPort: target.targetPort,
            usesHttps: target.usesHttps,
          },
          target.targetHostname,
        );
      },
    }),

    burp_send_http_request: tool({
      description:
        "Send a raw HTTP request through Burp MCP when the server exposes a request-sending tool. Respects Apex scope and Burp target approval.",
      inputSchema: z.object({
        content: z
          .string()
          .describe("Raw HTTP request content with CRLF or LF line endings"),
        targetHostname: z.string().optional(),
        targetPort: z.number().optional(),
        usesHttps: z.boolean().optional(),
        toolCallDescription: z
          .string()
          .describe("Why this request should be sent through Burp"),
      }),
      execute: async ({ content, targetHostname, targetPort, usesHttps }) => {
        const target = resolveRawHttpTarget({
          content,
          targetHostname,
          targetPort,
          usesHttps,
        });
        if (!target.success) return target;
        try {
          assertRawHttpTargetInScope(target, ctx);
        } catch (error) {
          return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
          };
        }
        return callFirstAvailable(
          ["send_http_request", "send_http1_request", "send_request"],
          {
            content,
            targetHostname: target.targetHostname,
            targetPort: target.targetPort,
            usesHttps: target.usesHttps,
          },
          target.targetHostname,
        );
      },
    }),

    burp_generate_collaborator_payload: tool({
      description:
        "Generate a Burp Collaborator payload when available. Use only for authorized out-of-band testing.",
      inputSchema: z.object({
        toolCallDescription: z
          .string()
          .describe("Why an out-of-band Collaborator payload is needed"),
      }),
      execute: async () =>
        callFirstAvailable(["generate_collaborator_payload"], {}),
    }),

    burp_poll_collaborator_interactions: tool({
      description:
        "Poll Burp Collaborator interactions when available and relevant to the current authorized test.",
      inputSchema: z.object({
        toolCallDescription: z
          .string()
          .describe("Why you need to poll Collaborator interactions"),
      }),
      execute: async () =>
        callFirstAvailable(["poll_collaborator_interactions"], {}),
    }),

    burp_get_proxy_intercept_state: tool({
      description: "Read Burp Proxy intercept state when exposed by Burp MCP.",
      inputSchema: z.object({
        toolCallDescription: z
          .string()
          .describe("Why you need to read proxy intercept state"),
      }),
      execute: async () =>
        callFirstAvailable(
          ["get_proxy_intercept", "get_proxy_intercept_state"],
          {},
        ),
    }),

    burp_set_proxy_intercept_state: tool({
      description:
        "Set Burp Proxy intercept state when exposed by Burp MCP. Use only when the operator explicitly asks for it.",
      inputSchema: z.object({
        enabled: z
          .boolean()
          .describe("Whether proxy intercept should be enabled"),
        toolCallDescription: z
          .string()
          .describe("Why changing proxy intercept state is needed"),
      }),
      execute: async ({ enabled }) =>
        callFirstAvailable(
          ["set_proxy_intercept", "set_proxy_intercept_state"],
          { enabled },
        ),
    }),

    burp_get_scanner_issues: tool({
      description:
        "Read Burp Scanner issues when available. Burp Community usually does not expose scanner issues.",
      inputSchema: z.object({
        count: z.number().default(20).describe("Number of issues"),
        offset: z.number().default(0).describe("Issue offset"),
        toolCallDescription: z
          .string()
          .describe("Why you need to inspect Burp scanner issues"),
      }),
      execute: async ({ count, offset }) => {
        const available = await session
          .listToolNames()
          .catch(() => [] as string[]);
        if (!available.includes("get_scanner_issues")) {
          return {
            success: false,
            error:
              "Burp Scanner issues are not available from this Burp MCP server. This is expected on Burp Community.",
          };
        }
        return callBurp("get_scanner_issues", { count, offset });
      },
    }),
  };
}
