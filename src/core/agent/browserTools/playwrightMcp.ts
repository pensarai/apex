/**
 * Playwright MCP Browser Tools
 *
 * Provides browser automation via Playwright MCP server.
 *
 * Two modes:
 * - "pentest": Automated pentesting agent - XSS validation, form-based attacks, evidence collection
 * - "operator": User-driven operator mode - SPA reconnaissance, authenticated flows, attack surface mapping
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
  result?: unknown;
  error?: string;
}

export interface BrowserScreenshotResult {
  success: boolean;
  path?: string;
  message?: string;
  error?: string;
}

export interface BrowserClickResult {
  success: boolean;
  element?: string;
  result?: unknown;
  error?: string;
}

export interface BrowserFillResult {
  success: boolean;
  element?: string;
  result?: unknown;
  error?: string;
}

export interface BrowserEvaluateResult {
  success: boolean;
  script?: string;
  result?: unknown;
  error?: string;
}

export interface BrowserConsoleResult {
  success: boolean;
  messages?: Array<{ type: string; text: string }>;
  result?: unknown;
  error?: string;
}

// Input schemas for browser tools
const BrowserNavigateInput = z.object({
  url: z.string().describe("Full URL to navigate to"),
  toolCallDescription: z.string().describe("Why you are navigating to this URL"),
});

const BrowserScreenshotInput = z.object({
  filename: z.string().describe("Descriptive filename for screenshot (without extension)"),
  toolCallDescription: z.string().describe("What evidence this screenshot captures"),
});

const BrowserClickInput = z.object({
  element: z.string().describe("Description of element to click, e.g., 'Submit button' or 'Login link'"),
  toolCallDescription: z.string().describe("Why you are clicking this element"),
});

const BrowserFillInput = z.object({
  element: z.string().describe("Description of form field, e.g., 'Username field' or 'Search input'"),
  value: z.string().describe("Value to fill into the field"),
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
let mcpClient: Client | null = null;
let mcpTransport: StdioClientTransport | null = null;
let isConnecting = false;
let connectionPromise: Promise<Client> | null = null;

/**
 * Initialize or return existing MCP client connection
 * Handles race conditions when multiple tools try to connect simultaneously
 */
export async function initializeMcpClient(): Promise<Client> {
  // If already connected, return existing client
  if (mcpClient) {
    return mcpClient;
  }

  // If connection is in progress, wait for it
  if (isConnecting && connectionPromise) {
    return connectionPromise;
  }

  // Start new connection
  isConnecting = true;
  connectionPromise = (async () => {
    try {
      const transport = new StdioClientTransport({
        command: "npx",
        args: ["@playwright/mcp@latest", "--headless"],
        stderr: "pipe",
      });

      const client = new Client({
        name: "apex-browser-agent",
        version: "1.0.0",
      });

      await client.connect(transport);

      mcpClient = client;
      mcpTransport = transport;

      return client;
    } catch (error) {
      isConnecting = false;
      connectionPromise = null;
      throw error;
    }
  })();

  return connectionPromise;
}

/**
 * Disconnect and cleanup MCP client
 */
export async function disconnectMcpClient(): Promise<void> {
  if (mcpClient) {
    try {
      await mcpClient.callTool({ name: "browser_close", arguments: {} });
    } catch {
      // Ignore cleanup errors
    }
  }
  if (mcpTransport) {
    try {
      await mcpTransport.close();
    } catch {
      // Ignore close errors
    }
  }
  mcpClient = null;
  mcpTransport = null;
  isConnecting = false;
  connectionPromise = null;
}

/**
 * Check if client is currently connected
 */
export function isClientConnected(): boolean {
  return mcpClient !== null;
}

/**
 * Call a tool on the MCP server and extract the result
 */
async function callMcpTool(
  toolName: string,
  args: Record<string, unknown>
): Promise<unknown> {
  const client = await initializeMcpClient();
  const result = await client.callTool({
    name: toolName,
    arguments: args,
  });

  // Extract content from the result
  if (result && "content" in result && Array.isArray(result.content)) {
    // Check for image content first (screenshots)
    const imageContent = result.content.find(
      (c: { type: string }) => c.type === "image"
    );
    if (imageContent && "data" in imageContent) {
      return { type: "image", data: imageContent.data };
    }

    // Then check for text content
    const textContent = result.content.find(
      (c: { type: string }) => c.type === "text"
    );
    if (textContent && "text" in textContent) {
      try {
        return JSON.parse(textContent.text as string);
      } catch {
        return textContent.text;
      }
    }
    return result.content;
  }

  return result;
}

// Mode-specific descriptions
const PENTEST_DESCRIPTIONS = {
  navigate: `Navigate the browser to a URL.

Use this to load pages for XSS testing, form interaction, or authentication flows.

Example use cases:
- Navigate to login page before testing auth bypass
- Load a page with reflected parameters for XSS testing
- Visit a page to capture its current state`,

  screenshot: `Take a screenshot of the current browser page for evidence collection.

Use this to document:
- Successful XSS execution (alert boxes, DOM changes)
- Authentication bypass results
- Error messages revealing sensitive info
- Any visual proof of vulnerability

Screenshots are saved to the evidence directory with the filename you specify.`,

  click: `Click on an element in the browser.

Use element descriptions or accessibility labels to identify what to click.
Examples: "Submit button", "Login link", "Close dialog"

Use this for:
- Submitting forms with payloads
- Navigating through multi-step flows
- Triggering JavaScript event handlers`,

  fill: `Fill a form field with a value.

Use this for:
- Injecting XSS payloads into input fields
- Testing SQL injection in form inputs
- Entering credentials for auth testing
- Filling search boxes with test payloads

The element should be described by its label or placeholder text.
Examples: "Username field", "Search input", "Email address"`,

  evaluate: `Execute JavaScript in the browser context.

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

  console: `Get browser console messages.

Essential for XSS detection:
- Check for JavaScript errors from injected payloads
- Detect console.log outputs from XSS execution
- Identify CSP violations
- See warnings about blocked content

Look for:
- Your XSS payload's console output
- "Content Security Policy" violations
- JavaScript errors indicating payload parsing`,
};

const OPERATOR_DESCRIPTIONS = {
  navigate: `Navigate the browser to a URL to load and render a page.

Use this to load SPAs, JavaScript-heavy pages, or any page that requires full browser rendering.
The page will be fully loaded and JavaScript executed before returning.`,

  screenshot: `Take a screenshot of the current page for evidence/documentation.

Use this to document:
- Exposed admin panels or sensitive pages
- Interesting error pages or debug information
- Visual proof of discovered vulnerabilities
- Login pages and authentication flows`,

  click: `Click on an element in the page by describing it.

Use this to:
- Navigate through multi-step flows
- Expand collapsed menus or sections
- Click buttons, links, or interactive elements
- Submit forms

The element is identified by a natural language description.`,

  fill: `Fill a form field with a value.

Use this to:
- Enter credentials for authenticated reconnaissance
- Fill search boxes or input fields
- Enter test data into forms

The field is identified by a natural language description.`,

  evaluate: `Execute JavaScript in the browser context to extract information.

CRITICAL for SPA reconnaissance - use this to extract:
- React Router routes: window.__REACT_ROUTER_VERSION__
- Next.js data: window.__NEXT_DATA__ (reveals all page routes and API endpoints)
- Vue Router routes: window.__VUE_ROUTER__?.options?.routes
- API configuration: window.API_URL, window.API_BASE_URL, window.config
- Application state: window.__REDUX_STATE__, window.__INITIAL_STATE__
- All links on page: Array.from(document.querySelectorAll('a')).map(a => a.href)
- Service worker routes: navigator.serviceWorker?.controller

The JavaScript is executed in the page context and the result is returned.`,

  console: `Get console messages from the browser.

Use this to check for:
- Leaked API keys or secrets in console output
- Debug messages revealing internal URLs or endpoints
- Error messages exposing application structure
- Warnings about deprecated endpoints
- Network request failures revealing API patterns`,
};

export type BrowserToolMode = "pentest" | "operator";

/**
 * Create browser automation tools
 *
 * @param targetUrl - Base target URL for context in descriptions
 * @param evidenceDir - Directory to save screenshots
 * @param mode - "pentest" for automated pentesting, "operator" for user-driven reconnaissance
 * @param logger - Optional logger for error reporting
 * @param abortSignal - Optional abort signal for cleanup
 */
export function createBrowserTools(
  targetUrl: string,
  evidenceDir: string,
  mode: BrowserToolMode = "pentest",
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

  const descriptions = mode === "pentest" ? PENTEST_DESCRIPTIONS : OPERATOR_DESCRIPTIONS;

  const browser_navigate = tool({
    description: `${descriptions.navigate}\n\nTarget base URL: ${targetUrl}`,
    inputSchema: BrowserNavigateInput,
    execute: async ({ url, toolCallDescription }): Promise<BrowserNavigateResult> => {
      try {
        const result = await callMcpTool("browser_navigate", { url });
        return {
          success: true,
          url,
          result,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_navigate failed: ${message}`);
        return { success: false, url, error: message };
      }
    },
  });

  const browser_screenshot = tool({
    description: descriptions.screenshot,
    inputSchema: BrowserScreenshotInput,
    execute: async ({ filename, toolCallDescription }): Promise<BrowserScreenshotResult> => {
      try {
        const result = await callMcpTool("browser_screenshot", {});

        // Handle image data from MCP response
        if (result && typeof result === "object" && "data" in result) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
          const screenshotFilename = `${filename}_${timestamp}.png`;
          const screenshotPath = join(evidenceDir, screenshotFilename);
          const dir = dirname(screenshotPath);
          if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true });
          }
          writeFileSync(screenshotPath, Buffer.from((result as { data: string }).data, "base64"));
          return { success: true, path: screenshotPath, message: `Screenshot saved to ${screenshotPath}` };
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
    description: descriptions.click,
    inputSchema: BrowserClickInput,
    execute: async ({ element, toolCallDescription }): Promise<BrowserClickResult> => {
      try {
        const result = await callMcpTool("browser_click", { element });
        return { success: true, element, result };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_click failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_fill = tool({
    description: descriptions.fill,
    inputSchema: BrowserFillInput,
    execute: async ({ element, value, toolCallDescription }): Promise<BrowserFillResult> => {
      try {
        // Note: Playwright MCP uses "browser_type" for filling fields
        const result = await callMcpTool("browser_type", { element, text: value });
        return { success: true, element, result };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_fill failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_evaluate = tool({
    description: descriptions.evaluate,
    inputSchema: BrowserEvaluateInput,
    execute: async ({ script, toolCallDescription }): Promise<BrowserEvaluateResult> => {
      try {
        const result = await callMcpTool("browser_evaluate", { expression: script });
        return { success: true, script, result };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_evaluate failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_console = tool({
    description: descriptions.console,
    inputSchema: BrowserConsoleInput,
    execute: async ({ toolCallDescription }): Promise<BrowserConsoleResult> => {
      try {
        const result = await callMcpTool("browser_console_messages", {});

        // Parse console messages if they're in JSON format
        let messages: Array<{ type: string; text: string }> | undefined;
        if (typeof result === "string") {
          try {
            messages = JSON.parse(result);
          } catch {
            messages = [{ type: "log", text: result }];
          }
        } else if (Array.isArray(result)) {
          messages = result as Array<{ type: string; text: string }>;
        }

        return { success: true, messages, result };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_console failed: ${message}`);
        return { success: false, error: message };
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
