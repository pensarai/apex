/**
 * Playwright MCP Browser Tools
 *
 * Provides browser automation via Playwright MCP server for vulnerability testing.
 * Used for XSS validation, form-based attacks, and evidence collection.
 *
 * NOTE: These tools are only available in Operator mode (HITL) - not in autonomous mode.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { tool } from "ai";
import { z } from "zod";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import type { Logger } from "../logger";

// Types for tool results
export interface BrowserNavigateResult {
  success: boolean;
  url: string;
  title?: string;
  error?: string;
}

export interface BrowserScreenshotResult {
  success: boolean;
  path?: string;
  error?: string;
}

export interface BrowserClickResult {
  success: boolean;
  error?: string;
}

export interface BrowserFillResult {
  success: boolean;
  error?: string;
}

export interface BrowserEvaluateResult {
  success: boolean;
  result?: unknown;
  error?: string;
}

export interface BrowserConsoleResult {
  success: boolean;
  messages: Array<{ type: string; text: string }>;
  error?: string;
}

// Input schemas for browser tools
const BrowserNavigateInput = z.object({
  url: z.string().describe("Full URL to navigate to"),
  toolCallDescription: z.string().describe("Why you are navigating to this URL"),
});

const BrowserScreenshotInput = z.object({
  filename: z.string().describe("Descriptive filename for screenshot (without extension), e.g., 'xss-payload-executed'"),
  toolCallDescription: z.string().describe("What evidence this screenshot captures"),
});

const BrowserClickInput = z.object({
  element: z.string().describe("Description of element to click, e.g., 'Submit button' or 'Login link'"),
  toolCallDescription: z.string().describe("Why you are clicking this element"),
});

const BrowserFillInput = z.object({
  element: z.string().describe("Description of form field, e.g., 'Username field' or 'Search input'"),
  value: z.string().describe("Value to fill (can be XSS payload, SQLi, credentials, etc.)"),
  toolCallDescription: z.string().describe("Why you are filling this field with this value"),
});

const BrowserEvaluateInput = z.object({
  script: z.string().describe("JavaScript code to execute in browser"),
  toolCallDescription: z.string().describe("What you are testing with this script"),
});

const BrowserConsoleInput = z.object({
  toolCallDescription: z.string().describe("Why you need to check console messages"),
});

// MCP Client singleton management
interface PlaywrightMcpClient {
  client: Client;
  transport: StdioClientTransport;
  isConnected: boolean;
}

let mcpClient: PlaywrightMcpClient | null = null;

/**
 * Initialize or return existing MCP client connection
 */
export async function initializeMcpClient(): Promise<Client> {
  if (mcpClient?.isConnected) {
    return mcpClient.client;
  }

  const transport = new StdioClientTransport({
    command: "npx",
    args: ["@playwright/mcp@latest", "--headless"],
  });

  const client = new Client({
    name: "apex-pentest-browser",
    version: "1.0.0",
  });

  await client.connect(transport);
  mcpClient = { client, transport, isConnected: true };

  return client;
}

/**
 * Disconnect and cleanup MCP client
 */
export async function disconnectMcpClient(): Promise<void> {
  if (mcpClient?.isConnected) {
    try {
      await mcpClient.client.callTool({ name: "browser_close", arguments: {} });
    } catch {
      // Ignore cleanup errors
    }
    try {
      await mcpClient.client.close();
    } catch {
      // Ignore close errors
    }
    mcpClient.isConnected = false;
    mcpClient = null;
  }
}

/**
 * Check if client is currently connected
 */
export function isClientConnected(): boolean {
  return mcpClient?.isConnected ?? false;
}

/**
 * Create browser automation tools for pentest operations
 *
 * @param targetUrl - Base target URL for context in descriptions
 * @param evidenceDir - Directory to save screenshots
 * @param logger - Optional logger for error reporting
 * @param abortSignal - Optional abort signal for cleanup
 */
export function createBrowserTools(
  targetUrl: string,
  evidenceDir: string,
  logger?: Logger,
  abortSignal?: AbortSignal
) {
  // Setup abort handler for cleanup
  abortSignal?.addEventListener("abort", () => {
    disconnectMcpClient().catch(() => {});
  });

  // Ensure evidence directory exists
  if (!existsSync(evidenceDir)) {
    mkdirSync(evidenceDir, { recursive: true });
  }

  const browser_navigate = tool({
    description: `Navigate the browser to a URL.

Use this to load pages for XSS testing, form interaction, or authentication flows.
Target base URL: ${targetUrl}

Example use cases:
- Navigate to login page before testing auth bypass
- Load a page with reflected parameters for XSS testing
- Visit a page to capture its current state`,
    inputSchema: BrowserNavigateInput,
    execute: async ({ url, toolCallDescription }): Promise<BrowserNavigateResult> => {
      try {
        const client = await initializeMcpClient();
        const result = await client.callTool({
          name: "browser_navigate",
          arguments: { url },
        });
        const content = result.content as Array<{ type: string; text?: string }>;
        const textContent = content?.find((c) => c.type === "text");
        return {
          success: true,
          url,
          title: textContent?.text || "",
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_navigate failed: ${message}`);
        return { success: false, url, error: message };
      }
    },
  });

  const browser_screenshot = tool({
    description: `Take a screenshot of the current browser page for evidence collection.

Use this to document:
- Successful XSS execution (alert boxes, DOM changes)
- Authentication bypass results
- Error messages revealing sensitive info
- Any visual proof of vulnerability

Screenshots are saved to the evidence directory with the filename you specify.`,
    inputSchema: BrowserScreenshotInput,
    execute: async ({ filename, toolCallDescription }): Promise<BrowserScreenshotResult> => {
      try {
        const client = await initializeMcpClient();
        const result = await client.callTool({
          name: "browser_take_screenshot",
          arguments: {},
        });

        const content = result.content as Array<{ type: string; data?: string; mimeType?: string }>;
        const imageContent = content?.find((c) => c.type === "image");

        if (imageContent?.data) {
          const screenshotPath = join(evidenceDir, `${filename}.png`);
          const dir = dirname(screenshotPath);
          if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true });
          }
          writeFileSync(screenshotPath, Buffer.from(imageContent.data, "base64"));
          return { success: true, path: screenshotPath };
        }

        return { success: false, error: "No screenshot data returned" };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_screenshot failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_click = tool({
    description: `Click on an element in the browser.

Use element descriptions or accessibility labels to identify what to click.
Examples: "Submit button", "Login link", "Close dialog"

Use this for:
- Submitting forms with payloads
- Navigating through multi-step flows
- Triggering JavaScript event handlers`,
    inputSchema: BrowserClickInput,
    execute: async ({ element, toolCallDescription }): Promise<BrowserClickResult> => {
      try {
        const client = await initializeMcpClient();
        await client.callTool({
          name: "browser_click",
          arguments: { element },
        });
        return { success: true };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_click failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_fill = tool({
    description: `Fill a form field with a value.

Use this for:
- Injecting XSS payloads into input fields
- Testing SQL injection in form inputs
- Entering credentials for auth testing
- Filling search boxes with test payloads

The element should be described by its label or placeholder text.
Examples: "Username field", "Search input", "Email address"`,
    inputSchema: BrowserFillInput,
    execute: async ({ element, value, toolCallDescription }): Promise<BrowserFillResult> => {
      try {
        const client = await initializeMcpClient();
        await client.callTool({
          name: "browser_type",
          arguments: { element, text: value },
        });
        return { success: true };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_fill failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_evaluate = tool({
    description: `Execute JavaScript in the browser context.

WARNING: This is an intrusive action - scripts will execute in the page context.

Use this for:
- Validating XSS execution (check if injected script ran)
- Extracting DOM data (document.cookie, localStorage)
- Testing for DOM-based vulnerabilities
- Checking JavaScript variable values
- Verifying CSP bypass

Examples:
- "document.cookie" - Extract cookies
- "localStorage.getItem('token')" - Check for stored tokens
- "window.xssExecuted" - Check if XSS payload set a marker`,
    inputSchema: BrowserEvaluateInput,
    execute: async ({ script, toolCallDescription }): Promise<BrowserEvaluateResult> => {
      try {
        const client = await initializeMcpClient();
        const result = await client.callTool({
          name: "browser_evaluate",
          arguments: { expression: script },
        });
        const content = result.content as Array<{ type: string; text?: string }>;
        const textContent = content?.find((c) => c.type === "text");
        return {
          success: true,
          result: textContent?.text,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_evaluate failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_console = tool({
    description: `Get browser console messages.

Essential for XSS detection:
- Check for JavaScript errors from injected payloads
- Detect console.log outputs from XSS execution
- Identify CSP violations
- See warnings about blocked content

Look for:
- Your XSS payload's console output
- "Content Security Policy" violations
- JavaScript errors indicating payload parsing`,
    inputSchema: BrowserConsoleInput,
    execute: async ({ toolCallDescription }): Promise<BrowserConsoleResult> => {
      try {
        const client = await initializeMcpClient();
        const result = await client.callTool({
          name: "browser_console_messages",
          arguments: {},
        });
        const content = result.content as Array<{ type: string; text?: string }>;
        const textContent = content?.find((c) => c.type === "text");

        let messages: Array<{ type: string; text: string }> = [];
        if (textContent?.text) {
          try {
            messages = JSON.parse(textContent.text);
          } catch {
            messages = [{ type: "log", text: textContent.text }];
          }
        }

        return { success: true, messages };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_console failed: ${message}`);
        return { success: false, messages: [], error: message };
      }
    },
  });

  return {
    browser_navigate,
    browser_screenshot,
    browser_click,
    browser_fill,
    browser_evaluate,
    browser_console,
  };
}
