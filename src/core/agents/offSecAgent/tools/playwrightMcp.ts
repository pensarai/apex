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
import { createRequire } from "module";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import type { Logger } from "../../../logger";

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
  toolCallDescription: z
    .string()
    .describe("Why you are navigating to this URL"),
});

const BrowserScreenshotInput = z.object({
  filename: z
    .string()
    .describe("Descriptive filename for screenshot (without extension)"),
  toolCallDescription: z
    .string()
    .describe("What evidence this screenshot captures"),
});

const BrowserClickInput = z.object({
  element: z
    .string()
    .describe(
      "Description of element to click, e.g., 'Submit button' or 'Login link'",
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e5'). If provided, uses exact element reference for precise clicking.",
    ),
  toolCallDescription: z.string().describe("Why you are clicking this element"),
});

const BrowserFillInput = z.object({
  element: z
    .string()
    .describe(
      "Description of form field, e.g., 'Username field' or 'Search input'",
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e3'). If provided, uses exact element reference for precise filling.",
    ),
  value: z.string().describe("Value to fill into the field"),
  toolCallDescription: z
    .string()
    .describe("Why you are filling this field with this value"),
});

const BrowserSnapshotInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to get the page snapshot"),
});

const BrowserEvaluateInput = z.object({
  script: z.string().describe("JavaScript code to execute in browser"),
  toolCallDescription: z
    .string()
    .describe("What you are testing with this script"),
});

const BrowserConsoleInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to check console messages"),
});

const BrowserGetCookiesInput = z.object({
  urls: z
    .array(z.string())
    .optional()
    .describe(
      "Optional list of URLs to get cookies for. If not provided, gets all cookies.",
    ),
  toolCallDescription: z
    .string()
    .describe("Why you need to extract cookies from the browser"),
});

const MCP_CONNECT_TIMEOUT_MS = 30_000;
const MCP_TOOL_CALL_TIMEOUT_MS = 60_000;

/**
 * Race a promise against a timeout. Rejects with a descriptive error
 * if the timeout fires first.
 */
function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------------------
// Module-level default headless setting (used when not explicitly provided)
// ---------------------------------------------------------------------------

let defaultHeadless = true;

/**
 * Configure the default headless mode for new browser sessions.
 * Call this BEFORE any browser tools are created.
 * Default is headless=true for normal operation.
 */
export function setHeadlessMode(headless: boolean): void {
  defaultHeadless = headless;
}

const MCP_CONNECT_TIMEOUT_MS = 30_000;
const MCP_TOOL_CALL_TIMEOUT_MS = 60_000;

/**
 * Isolated MCP browser session.
 *
 * Each instance owns its own Playwright MCP child-process and browser.
 * Create one per agent so concurrent agents never collide on the same
 * browser context.
 *
 * Incorporates all robustness features: connection timeouts, force-kill
 * of stuck processes, dead-transport detection, and per-call abort
 * signal + timeout support.
 */
export class PlaywrightMcpSession {
  private mcpClient: Client | null = null;
  private mcpTransport: StdioClientTransport | null = null;
  private mcpProcess: import("child_process").ChildProcess | null = null;
  private connectionPromise: Promise<Client> | null = null;
  private disconnecting = false;
  private readonly headless: boolean;

  constructor(headless = true) {
    this.headless = headless;
  }

  /** Immediately reset all instance state. Synchronous — no I/O. */
  private resetState(): void {
    this.mcpClient = null;
    this.mcpTransport = null;
    this.mcpProcess = null;
    this.connectionPromise = null;
    this.disconnecting = false;
  }

  /**
   * Force-kill the MCP child process. Sends SIGKILL directly — no graceful
   * shutdown, no waiting. Used during disconnect and error recovery so the
   * agent is never blocked on a hung Playwright process.
   */
  private forceKillProcess(): void {
    const proc = this.mcpProcess;
    if (!proc || proc.exitCode !== null) return;

    try {
      if (proc.pid) {
        try {
          process.kill(-proc.pid, "SIGKILL");
        } catch {
          proc.kill("SIGKILL");
        }
      } else {
        proc.kill("SIGKILL");
      }
    } catch {
      // Already dead — fine
    }
  }

  /**
   * Initialize or return existing MCP client connection for this session.
   * Handles race conditions when multiple tools within the same agent
   * try to connect simultaneously. Detects dead transports and
   * auto-reconnects.
   */
  async initialize(): Promise<Client> {
    if (this.mcpClient) {
      if ((this.mcpClient as unknown as { transport?: unknown }).transport) {
        return this.mcpClient;
      }
      this.forceKillProcess();
      this.resetState();
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = (async () => {
      try {
        const require_ = createRequire(import.meta.url);
        const mcpPkgJsonPath = require_.resolve("@playwright/mcp/package.json");
        const cliPath = join(dirname(mcpPkgJsonPath), "cli.js");

        const args = [cliPath, "--isolated"];
        if (this.headless) {
          args.push("--headless");
        }

        // Disable Chromium sandbox when running as root (e.g., in Docker/ECS containers).
        if (process.getuid?.() === 0) {
          args.push("--no-sandbox");
        }

        const transport = new StdioClientTransport({
          command: "node",
          args,
          stderr: "pipe",
        });

        const client = new Client({
          name: "apex-browser-agent",
          version: "1.0.0",
        });

        // Hook into transport to capture the child process reference
        const origStart = transport.start.bind(transport);
        transport.start = async () => {
          await origStart();
          this.mcpProcess =
            (
              transport as unknown as {
                _process?: import("child_process").ChildProcess;
              }
            )._process ?? null;
        };

        await withTimeout(
          client.connect(transport),
          MCP_CONNECT_TIMEOUT_MS,
          "MCP client connection timed out",
        );

        this.mcpClient = client;
        this.mcpTransport = transport;

        client.onclose = () => {
          if (this.mcpClient === client) {
            this.resetState();
          }
        };

        return client;
      } catch (error) {
        this.forceKillProcess();
        this.resetState();
        throw error;
      }
    })();

    return this.connectionPromise;
  }

  /**
   * Disconnect and cleanup this session's MCP client and browser.
   *
   * Designed to NEVER hang: resets state synchronously, then kills
   * the transport and process. Does NOT call browser_close (which
   * could block for 60 s if the server is hung).
   */
  async disconnect(): Promise<void> {
    if (this.disconnecting) return;
    this.disconnecting = true;

    const transport = this.mcpTransport;
    const client = this.mcpClient;

    this.resetState();
    this.disconnecting = true; // re-set because resetState clears it

    if (client) {
      try {
        await client.close();
      } catch {
        // Ignore — may already be closed
      }
    }

    if (transport) {
      try {
        await transport.close();
      } catch {
        // Ignore — may already be closed
      }
    }

    this.forceKillProcess();
    this.disconnecting = false;
  }

  /** Check if this session's client is currently connected. */
  isConnected(): boolean {
    return this.mcpClient !== null;
  }

  /**
   * Call a tool on this session's MCP server and extract the result.
   *
   * Each call is guarded by:
   * 1. The SDK's native abort signal (properly cancels the request)
   * 2. An outer timeout (in case the SDK's cancellation gets stuck)
   * 3. Auto-reconnection on transport errors
   */
  async callTool(
    toolName: string,
    args: Record<string, unknown>,
    abortSignal?: AbortSignal,
  ): Promise<unknown> {
    if (abortSignal?.aborted) {
      throw new Error("Browser tool call aborted");
    }

    let client: Client;
    try {
      client = await withTimeout(
        this.initialize(),
        MCP_CONNECT_TIMEOUT_MS,
        "MCP client initialization timed out",
      );
    } catch (error) {
      this.forceKillProcess();
      this.resetState();
      throw error;
    }

    const callController = new AbortController();
    let abortCleanup: (() => void) | undefined;

    if (abortSignal) {
      const handler = () => callController.abort(abortSignal.reason);
      if (abortSignal.aborted) {
        callController.abort(abortSignal.reason);
      } else {
        abortSignal.addEventListener("abort", handler, { once: true });
        abortCleanup = () => abortSignal.removeEventListener("abort", handler);
      }
    }

    const timeoutTimer = setTimeout(
      () =>
        callController.abort(
          new Error(
            `Browser tool "${toolName}" timed out after ${MCP_TOOL_CALL_TIMEOUT_MS / 1000}s`,
          ),
        ),
      MCP_TOOL_CALL_TIMEOUT_MS,
    );

    try {
      const result = await client.callTool(
        { name: toolName, arguments: args },
        undefined,
        { signal: callController.signal },
      );

      if (result && "content" in result && Array.isArray(result.content)) {
        const imageContent = result.content.find(
          (c: { type: string }) => c.type === "image",
        );
        if (imageContent && "data" in imageContent) {
          return { type: "image", data: imageContent.data };
        }

        const textContent = result.content.find(
          (c: { type: string }) => c.type === "text",
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
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      const isConnectionDead =
        msg.includes("Not connected") ||
        msg.includes("Connection closed") ||
        msg.includes("EPIPE") ||
        msg.includes("write after end");

      if (isConnectionDead && this.mcpClient === client) {
        this.forceKillProcess();
        this.resetState();
      }

      throw error;
    } finally {
      clearTimeout(timeoutTimer);
      abortCleanup?.();
    }
  }
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

export type BrowserToolMode = "pentest" | "operator" | "auth";

// Auth mode descriptions - focused on authentication flows
const AUTH_DESCRIPTIONS = {
  navigate: `Navigate the browser to a login page or auth endpoint.

Use this to load login forms, OAuth authorization pages, or SPA apps that require browser rendering.
The page will be fully loaded and JavaScript executed before returning.`,

  screenshot: `Take a screenshot of the current page for evidence of authentication state.

Use this to document:
- Successful login confirmation
- Error messages or failed auth attempts
- Multi-factor authentication prompts`,

  click: `Click on an element in the page by describing it.

Use this to:
- Submit login forms
- Click "Sign in" or "Login" buttons
- Navigate through OAuth consent flows
- Click "Remember me" checkboxes`,

  fill: `Fill a form field with a value.

Use this to:
- Enter username/email in login forms
- Enter password in password fields
- Fill OTP/verification codes (if provided)`,

  evaluate: `Execute JavaScript in the browser context to extract auth tokens.

CRITICAL for SPA authentication - use this to extract:
- localStorage tokens: localStorage.getItem('token')
- sessionStorage tokens: sessionStorage.getItem('access_token')
- Cookies: document.cookie
- Application state: window.__INITIAL_STATE__?.auth

Returns the result of the JavaScript execution.`,

  console: `Get console messages from the browser.

Use this to check for:
- Authentication errors logged to console
- Token validation messages
- API response logging`,
};

/**
 * Create browser automation tools backed by a **dedicated** Playwright MCP
 * session. Every invocation spins up its own MCP child-process / browser so
 * that concurrent agents never share a browser context.
 *
 * @param targetUrl - Base target URL for context in descriptions
 * @param evidenceDir - Directory to save screenshots
 * @param mode - "pentest" for automated pentesting, "operator" for user-driven reconnaissance, "auth" for authentication flows
 * @param logger - Optional logger for error reporting
 * @param abortSignal - Optional abort signal for cleanup
 * @param headless - Override headless mode for this session (defaults to the
 *   value set by {@link setHeadlessMode}, which itself defaults to `true`)
 */
export function createBrowserTools(
  targetUrl: string,
  evidenceDir: string,
  mode: BrowserToolMode = "pentest",
  logger?: Logger,
  abortSignal?: AbortSignal,
  headless?: boolean,
) {
  const session = new PlaywrightMcpSession(headless ?? defaultHeadless);

  abortSignal?.addEventListener("abort", () => {
    session.disconnect().catch(() => {});
  });

  // Ensure evidence directory exists
  if (!existsSync(evidenceDir)) {
    mkdirSync(evidenceDir, { recursive: true });
  }

  const descriptions =
    mode === "pentest"
      ? PENTEST_DESCRIPTIONS
      : mode === "auth"
        ? AUTH_DESCRIPTIONS
        : OPERATOR_DESCRIPTIONS;

  const browser_navigate = tool({
    description: `${descriptions.navigate}\n\nTarget base URL: ${targetUrl}`,
    inputSchema: BrowserNavigateInput,
    execute: async ({
      url,
      toolCallDescription,
    }): Promise<BrowserNavigateResult> => {
      try {
        const result = await session.callTool(
          "browser_navigate",
          { url },
          abortSignal,
        );
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
    execute: async ({
      filename,
      toolCallDescription,
    }): Promise<BrowserScreenshotResult> => {
      try {
        const result = await session.callTool(
          "browser_take_screenshot",
          {},
          abortSignal,
        );

        // Extract base64 image data from various response formats
        let base64Data: string | undefined;

        if (result && typeof result === "object") {
          const r = result as Record<string, unknown>;

          // Format 1: { type: "image", data: "<base64>" } — from callTool's image extraction
          if ("data" in r && typeof r.data === "string") {
            base64Data = r.data;
          }

          // Format 2: Raw MCP content array — [{type:"image", data:"...", mimeType:"..."}]
          if (!base64Data && Array.isArray(result)) {
            const imgItem = (result as Array<Record<string, unknown>>).find(
              (c) => c.type === "image" && typeof c.data === "string",
            );
            if (imgItem) {
              base64Data = imgItem.data as string;
            }
          }
        }

        if (base64Data) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
          const screenshotFilename = `${filename}_${timestamp}.png`;
          const screenshotPath = join(evidenceDir, screenshotFilename);
          const dir = dirname(screenshotPath);
          if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true });
          }
          writeFileSync(screenshotPath, Buffer.from(base64Data, "base64"));
          return {
            success: true,
            path: screenshotPath,
            message: `Screenshot saved to ${screenshotPath}`,
          };
        }

        // Log the actual response shape to aid debugging
        const resultShape =
          result === null
            ? "null"
            : Array.isArray(result)
              ? `array(${(result as unknown[]).length})`
              : typeof result === "object"
                ? `object(${Object.keys(result as Record<string, unknown>).join(",")})`
                : typeof result;
        return {
          success: false,
          error: `No screenshot data returned (response type: ${resultShape})`,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_screenshot failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_snapshot = tool({
    description: `Get the accessibility snapshot of the current page.

IMPORTANT: Call this BEFORE using browser_click or browser_fill to get element references (refs).
The snapshot returns an accessibility tree with elements marked like [ref=e5].
Use these refs in browser_click and browser_fill for precise element targeting.

Example workflow:
1. Call browser_snapshot to get the page structure
2. Find the element you need (e.g., "textbox 'Email'" with [ref=e3])
3. Call browser_fill with ref="e3" to fill that specific element`,
    inputSchema: BrowserSnapshotInput,
    execute: async ({
      toolCallDescription,
    }): Promise<{ success: boolean; snapshot?: string; error?: string }> => {
      try {
        const result = await session.callTool(
          "browser_snapshot",
          {},
          abortSignal,
        );
        return {
          success: true,
          snapshot:
            typeof result === "string"
              ? result
              : JSON.stringify(result, null, 2),
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_snapshot failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_click = tool({
    description:
      descriptions.click +
      `\n\nIMPORTANT: For reliable clicking, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserClickInput,
    execute: async ({
      element,
      ref,
      toolCallDescription,
    }): Promise<BrowserClickResult> => {
      try {
        const args: Record<string, unknown> = { element };
        if (ref) {
          args.ref = ref;
        }
        const result = await session.callTool(
          "browser_click",
          args,
          abortSignal,
        );
        return { success: true, element, result };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_click failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  const browser_fill = tool({
    description:
      descriptions.fill +
      `\n\nIMPORTANT: For reliable form filling, first call browser_snapshot to get element refs, then pass the ref parameter.`,
    inputSchema: BrowserFillInput,
    execute: async ({
      element,
      ref,
      value,
      toolCallDescription,
    }): Promise<BrowserFillResult> => {
      try {
        // Note: Playwright MCP uses "browser_type" for filling fields
        const args: Record<string, unknown> = { element, text: value };
        if (ref) {
          args.ref = ref;
        }
        const result = await session.callTool(
          "browser_type",
          args,
          abortSignal,
        );
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
    execute: async ({
      script,
      toolCallDescription,
    }): Promise<BrowserEvaluateResult> => {
      try {
        // Playwright MCP's browser_evaluate expects a `function` param with a
        // function expression like `() => document.cookie`. Wrap raw expressions
        // that aren't already function-shaped.
        const isFunction =
          /^\s*(async\s+)?\(/.test(script) ||
          /^\s*(async\s+)?function\s*\(/.test(script);
        const fnScript = isFunction ? script : `() => (${script})`;

        const result = await session.callTool(
          "browser_evaluate",
          { function: fnScript },
          abortSignal,
        );
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
        const result = await session.callTool(
          "browser_console_messages",
          {},
          abortSignal,
        );

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

  const browser_get_cookies = tool({
    description: `Extract cookies from the browser context, including httpOnly cookies.

CRITICAL: Use this after successful browser authentication to get session cookies that can be used in HTTP requests.

Returns all cookies including:
- Session cookies (often httpOnly, not accessible via document.cookie)
- Authentication tokens
- CSRF tokens

The returned cookies can be formatted as a Cookie header for use with http_request tool.`,
    inputSchema: BrowserGetCookiesInput,
    execute: async ({
      urls,
      toolCallDescription,
    }): Promise<{
      success: boolean;
      cookies?: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        httpOnly: boolean;
        secure: boolean;
      }>;
      cookieHeader?: string;
      error?: string;
    }> => {
      try {
        // Playwright MCP doesn't expose a dedicated cookie tool, so we use
        // browser_run_code to call the Playwright context API directly.
        // This gets ALL cookies including httpOnly ones.
        const urlFilter =
          urls && urls.length > 0 ? JSON.stringify(urls) : "undefined";
        const code = `async (page) => { const cookies = await page.context().cookies(${urlFilter === "undefined" ? "" : urlFilter}); return cookies; }`;

        const result = await session.callTool(
          "browser_run_code",
          { code },
          abortSignal,
        );

        let cookies: Array<{
          name: string;
          value: string;
          domain: string;
          path: string;
          httpOnly: boolean;
          secure: boolean;
        }> = [];

        if (typeof result === "string") {
          // Playwright MCP wraps results as "### Result\n<value>\n\n### Ran Playwright code\n...".
          // Strip the prefix and any trailing Playwright output sections.
          const stripped = result
            .replace(/^###\s*Result\s*\n?/, "")
            .replace(/\n\n###[\s\S]*$/, "")
            .trim();
          try {
            const parsed = JSON.parse(stripped);
            if (Array.isArray(parsed)) {
              cookies = parsed;
            } else if (typeof parsed === "string") {
              cookies = JSON.parse(parsed);
            }
          } catch {
            const jsonMatch = stripped.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
              try {
                cookies = JSON.parse(jsonMatch[0]);
              } catch {
                // Could not parse
              }
            }
          }
        } else if (Array.isArray(result)) {
          cookies = result as typeof cookies;
        } else if (
          result &&
          typeof result === "object" &&
          "cookies" in result
        ) {
          cookies = (result as { cookies: typeof cookies }).cookies;
        }

        const cookieHeader = cookies
          .map((c) => `${c.name}=${c.value}`)
          .join("; ");

        return {
          success: true,
          cookies,
          cookieHeader,
        };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        logger?.error(`browser_get_cookies failed: ${message}`);
        return { success: false, error: message };
      }
    },
  });

  return {
    browser_navigate,
    browser_snapshot,
    browser_screenshot,
    browser_click,
    browser_fill,
    browser_evaluate,
    browser_console,
    browser_get_cookies,
  };
}
