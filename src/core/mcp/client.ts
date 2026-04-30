import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

export type McpTransportType = "sse" | "stdio";

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    title?: string;
  };
}

export interface McpClientConfig {
  name: string;
  version: string;
  transport: McpTransportType;
  url?: string;
  command?: string;
  args?: string[];
  timeoutMs?: number;
}

export interface McpClientFactories {
  createClient?: () => Pick<
    Client,
    "connect" | "close" | "listTools" | "callTool"
  >;
  createStreamableHttpTransport?: (url: URL) => Transport;
  createSseTransport?: (url: URL) => Transport;
  createStdioTransport?: (opts: {
    command: string;
    args?: string[];
  }) => Transport;
}

export class McpError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalCause?: unknown,
  ) {
    super(message);
    this.name = "McpError";
  }
}

export class McpConnectionError extends McpError {
  constructor(message: string, cause?: unknown) {
    super(message, "MCP_CONNECTION_ERROR", cause);
    this.name = "McpConnectionError";
  }
}

export class McpTimeoutError extends McpError {
  constructor(message: string, cause?: unknown) {
    super(message, "MCP_TIMEOUT", cause);
    this.name = "McpTimeoutError";
  }
}

export class McpToolError extends McpError {
  constructor(
    message: string,
    public readonly toolName: string,
    cause?: unknown,
  ) {
    super(message, "MCP_TOOL_ERROR", cause);
    this.name = "McpToolError";
  }
}

const DEFAULT_TIMEOUT_MS = 15_000;

export function withMcpTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new McpTimeoutError(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

export class GenericMcpClient {
  private client: Pick<
    Client,
    "connect" | "close" | "listTools" | "callTool"
  > | null = null;
  private transport: Transport | null = null;
  private connectionPromise: Promise<void> | null = null;

  constructor(
    private readonly config: McpClientConfig,
    private readonly factories: McpClientFactories = {},
  ) {}

  private get timeoutMs(): number {
    return this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private createClient() {
    return (
      this.factories.createClient?.() ??
      new Client({ name: this.config.name, version: this.config.version })
    );
  }

  private async connectHttp(
    client: Pick<Client, "connect">,
  ): Promise<Transport> {
    if (!this.config.url) {
      throw new McpConnectionError("MCP SSE URL is required");
    }

    const url = new URL(this.config.url);
    const streamable =
      this.factories.createStreamableHttpTransport?.(url) ??
      new StreamableHTTPClientTransport(url);

    try {
      await withMcpTimeout(
        client.connect(streamable),
        this.timeoutMs,
        `MCP connection timed out after ${this.timeoutMs}ms`,
      );
      return streamable;
    } catch (streamableError) {
      const sse =
        this.factories.createSseTransport?.(url) ?? new SSEClientTransport(url);
      try {
        await withMcpTimeout(
          client.connect(sse),
          this.timeoutMs,
          `MCP SSE connection timed out after ${this.timeoutMs}ms`,
        );
        return sse;
      } catch (sseError) {
        throw new McpConnectionError(
          `MCP server is not reachable at ${this.config.url}`,
          sseError instanceof McpTimeoutError ? sseError : streamableError,
        );
      }
    }
  }

  private async connectStdio(
    client: Pick<Client, "connect">,
  ): Promise<Transport> {
    if (!this.config.command) {
      throw new McpConnectionError("MCP stdio command is required");
    }

    const transport =
      this.factories.createStdioTransport?.({
        command: this.config.command,
        args: this.config.args,
      }) ??
      new StdioClientTransport({
        command: this.config.command,
        args: this.config.args,
        stderr: "pipe",
      });

    await withMcpTimeout(
      client.connect(transport),
      this.timeoutMs,
      `MCP stdio connection timed out after ${this.timeoutMs}ms`,
    );
    return transport;
  }

  async connect(): Promise<void> {
    if (this.client) return;
    if (this.connectionPromise) return this.connectionPromise;

    this.connectionPromise = (async () => {
      const client = this.createClient();
      try {
        const transport =
          this.config.transport === "stdio"
            ? await this.connectStdio(client)
            : await this.connectHttp(client);
        this.client = client;
        this.transport = transport;
      } catch (error) {
        this.client = null;
        this.transport = null;
        this.connectionPromise = null;
        if (error instanceof McpError) throw error;
        throw new McpConnectionError(
          error instanceof Error ? error.message : String(error),
          error,
        );
      }
    })();

    return this.connectionPromise;
  }

  async disconnect(): Promise<void> {
    const client = this.client;
    const transport = this.transport;
    this.client = null;
    this.transport = null;
    this.connectionPromise = null;

    try {
      await client?.close();
    } finally {
      await transport?.close?.();
    }
  }

  async listTools(): Promise<McpToolDefinition[]> {
    await this.connect();
    try {
      const result = await withMcpTimeout(
        this.client!.listTools(),
        this.timeoutMs,
        `MCP list tools timed out after ${this.timeoutMs}ms`,
      );
      return result.tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      }));
    } catch (error) {
      if (error instanceof McpError) throw error;
      throw new McpToolError(
        error instanceof Error ? error.message : String(error),
        "listTools",
        error,
      );
    }
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
    abortSignal?: AbortSignal,
  ): Promise<unknown> {
    if (abortSignal?.aborted) {
      throw new McpToolError("MCP tool call aborted", name);
    }

    await this.connect();
    const controller = new AbortController();
    let cleanup: (() => void) | undefined;

    if (abortSignal) {
      const onAbort = () => controller.abort(abortSignal.reason);
      abortSignal.addEventListener("abort", onAbort, { once: true });
      cleanup = () => abortSignal.removeEventListener("abort", onAbort);
    }

    try {
      return await withMcpTimeout(
        this.client!.callTool({ name, arguments: args }, undefined, {
          signal: controller.signal,
        }),
        this.timeoutMs,
        `MCP tool "${name}" timed out after ${this.timeoutMs}ms`,
      );
    } catch (error) {
      if (error instanceof McpError) throw error;
      throw new McpToolError(
        error instanceof Error ? error.message : String(error),
        name,
        error,
      );
    } finally {
      cleanup?.();
    }
  }
}
