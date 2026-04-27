import { describe, expect, it } from "vitest";
import { GenericMcpClient, McpConnectionError, McpToolError } from "./client";

function createMockClient(options?: {
  connectFails?: boolean;
  tools?: Array<{ name: string; description?: string; inputSchema?: unknown }>;
  toolResult?: unknown;
}) {
  return {
    connect: async () => {
      if (options?.connectFails) throw new Error("connect failed");
    },
    close: async () => {},
    listTools: async () => ({
      tools: options?.tools ?? [{ name: "ping", description: "Ping" }],
    }),
    callTool: async ({ name }: { name: string }) => {
      if (name === "fail") throw new Error("tool failed");
      return options?.toolResult ?? { content: [{ type: "text", text: "ok" }] };
    },
  };
}

function createMockTransport() {
  return {
    start: async () => {},
    close: async () => {},
    send: async () => {},
  };
}

describe("GenericMcpClient", () => {
  it("lists tools through the configured transport", async () => {
    const client = new GenericMcpClient(
      {
        name: "test",
        version: "1.0.0",
        transport: "sse",
        url: "http://127.0.0.1:9876/sse",
      },
      {
        createClient: () =>
          createMockClient({
            tools: [{ name: "first" }, { name: "second" }],
          }) as never,
        createStreamableHttpTransport: () => createMockTransport() as never,
      },
    );

    await expect(client.listTools()).resolves.toMatchObject([
      { name: "first" },
      { name: "second" },
    ]);
  });

  it("falls back from streamable HTTP to legacy SSE", async () => {
    let attempts = 0;
    const client = new GenericMcpClient(
      {
        name: "test",
        version: "1.0.0",
        transport: "sse",
        url: "http://127.0.0.1:9876/sse",
      },
      {
        createClient: () =>
          ({
            ...createMockClient(),
            connect: async () => {
              attempts++;
              if (attempts === 1) throw new Error("streamable unsupported");
            },
          }) as never,
        createStreamableHttpTransport: () => createMockTransport() as never,
        createSseTransport: () => createMockTransport() as never,
      },
    );

    await expect(client.listTools()).resolves.toHaveLength(1);
    expect(attempts).toBe(2);
  });

  it("surfaces connection and tool errors with structured error classes", async () => {
    const connection = new GenericMcpClient(
      {
        name: "test",
        version: "1.0.0",
        transport: "sse",
        url: "http://127.0.0.1:9876/sse",
      },
      {
        createClient: () => createMockClient({ connectFails: true }) as never,
        createStreamableHttpTransport: () => createMockTransport() as never,
        createSseTransport: () => createMockTransport() as never,
      },
    );
    await expect(connection.listTools()).rejects.toBeInstanceOf(
      McpConnectionError,
    );

    const tool = new GenericMcpClient(
      {
        name: "test",
        version: "1.0.0",
        transport: "sse",
        url: "http://127.0.0.1:9876/sse",
      },
      {
        createClient: () => createMockClient() as never,
        createStreamableHttpTransport: () => createMockTransport() as never,
      },
    );
    await expect(tool.callTool("fail", {})).rejects.toBeInstanceOf(
      McpToolError,
    );
  });
});
