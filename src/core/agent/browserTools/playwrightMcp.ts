/**
 * Playwright MCP Browser Tools
 *
 * Provides browser automation via Playwright MCP server.
 *
 * Two modes:
 * - "pentest": Automated pentesting agent - XSS validation, form-based attacks, evidence collection
 * - "operator": User-driven operator mode - SPA reconnaissance, authenticated flows, attack surface mapping
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { tool } from 'ai';
import { z } from 'zod';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import type { Logger } from '../logger';

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
  url: z.string().describe('Full URL to navigate to'),
  toolCallDescription: z
    .string()
    .describe('Why you are navigating to this URL'),
});

const BrowserScreenshotInput = z.object({
  filename: z
    .string()
    .describe('Descriptive filename for screenshot (without extension)'),
  toolCallDescription: z
    .string()
    .describe('What evidence this screenshot captures'),
});

const BrowserClickInput = z.object({
  element: z
    .string()
    .describe(
      "Description of element to click, e.g., 'Submit button' or 'Login link'"
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e5'). If provided, uses exact element reference for precise clicking."
    ),
  toolCallDescription: z.string().describe('Why you are clicking this element'),
});

const BrowserFillInput = z.object({
  element: z
    .string()
    .describe(
      "Description of form field, e.g., 'Username field' or 'Search input'"
    ),
  ref: z
    .string()
    .optional()
    .describe(
      "Element reference from browser_snapshot (e.g., 'e3'). If provided, uses exact element reference for precise filling."
    ),
  value: z.string().describe('Value to fill into the field'),
  toolCallDescription: z
    .string()
    .describe('Why you are filling this field with this value'),
});

const BrowserSnapshotInput = z.object({
  toolCallDescription: z
    .string()
    .describe('Why you need to get the page snapshot'),
});

const BrowserEvaluateInput = z.object({
  script: z.string().describe('JavaScript code to execute in browser'),
  toolCallDescription: z
    .string()
    .describe('What you are testing with this script'),
});

const BrowserConsoleInput = z.object({
  toolCallDescription: z
    .string()
    .describe('Why you need to check console messages'),
});

const BrowserGetCookiesInput = z.object({
  urls: z
    .array(z.string())
    .optional()
    .describe(
      'Optional list of URLs to get cookies for. If not provided, gets all cookies.'
    ),
  toolCallDescription: z
    .string()
    .describe('Why you need to extract cookies from the browser'),
});

// MCP Client singleton management
let mcpClient: Client | null = null;
let mcpTransport: StdioClientTransport | null = null;
let isConnecting = false;
let connectionPromise: Promise<Client> | null = null;
let configuredHeadless = true;

/**
 * Configure headless mode for the next browser session.
 * Call this BEFORE any browser tools are used.
 * Default is headless=true for normal operation.
 */
export function setHeadlessMode(headless: boolean): void {
  configuredHeadless = headless;
}

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
      const args = ['@playwright/mcp@latest', '--isolated'];
      if (configuredHeadless) {
        args.push('--headless');
      }

      // Disable Chromium sandbox when running as root (e.g., in Docker/ECS containers).
      // Chrome refuses to run as root with sandboxing enabled.
      if (process.getuid?.() === 0) {
        args.push('--no-sandbox');
      }

      const transport = new StdioClientTransport({
        command: 'npx',
        args,
        stderr: 'pipe',
      });

      const client = new Client({
        name: 'apex-browser-agent',
        version: '1.0.0',
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
      await mcpClient.callTool({ name: 'browser_close', arguments: {} });
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
  if (result && 'content' in result && Array.isArray(result.content)) {
    // Check for image content first (screenshots)
    const imageContent = result.content.find(
      (c: { type: string }) => c.type === 'image'
    );
    if (imageContent && 'data' in imageContent) {
      return { type: 'image', data: imageContent.data };
    }

    // Then check for text content
    const textContent = result.content.find(
      (c: { type: string }) => c.type === 'text'
    );
    if (textContent && 'text' in textContent) {
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

export type BrowserToolMode = 'pentest' | 'operator' | 'auth';

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
 * Create browser automation tools
 *
 * @param targetUrl - Base target URL for context in descriptions
 * @param evidenceDir - Directory to save screenshots
 * @param mode - "pentest" for automated pentesting, "operator" for user-driven reconnaissance, "auth" for authentication flows
 * @param logger - Optional logger for error reporting
 * @param abortSignal - Optional abort signal for cleanup
 */
export function createBrowserTools(
  targetUrl: string,
  evidenceDir: string,
  mode: BrowserToolMode = 'pentest',
  logger?: Logger,
  abortSignal?: AbortSignal
) {
  // Setup abort handler for cleanup
  abortSignal?.addEventListener('abort', () => {
    disconnectMcpClient().catch(() => {});
  });

  // Ensure evidence directory exists
  if (!existsSync(evidenceDir)) {
    mkdirSync(evidenceDir, { recursive: true });
  }

  const descriptions =
    mode === 'pentest'
      ? PENTEST_DESCRIPTIONS
      : mode === 'auth'
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
        const result = await callMcpTool('browser_navigate', { url });
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
        const result = await callMcpTool('browser_screenshot', {});

        // Handle image data from MCP response
        if (result && typeof result === 'object' && 'data' in result) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const screenshotFilename = `${filename}_${timestamp}.png`;
          const screenshotPath = join(evidenceDir, screenshotFilename);
          const dir = dirname(screenshotPath);
          if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true });
          }
          writeFileSync(
            screenshotPath,
            Buffer.from((result as { data: string }).data, 'base64')
          );
          return {
            success: true,
            path: screenshotPath,
            message: `Screenshot saved to ${screenshotPath}`,
          };
        }

        return { success: false, error: 'No screenshot data returned' };
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
        const result = await callMcpTool('browser_snapshot', {});
        return {
          success: true,
          snapshot:
            typeof result === 'string'
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
        const result = await callMcpTool('browser_click', args);
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
        const result = await callMcpTool('browser_type', args);
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
        const result = await callMcpTool('browser_evaluate', {
          expression: script,
        });
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
        const result = await callMcpTool('browser_console_messages', {});

        // Parse console messages if they're in JSON format
        let messages: Array<{ type: string; text: string }> | undefined;
        if (typeof result === 'string') {
          try {
            messages = JSON.parse(result);
          } catch {
            messages = [{ type: 'log', text: result }];
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
        const args: Record<string, unknown> = {};
        if (urls && urls.length > 0) {
          args.urls = urls;
        }
        const result = await callMcpTool('browser_get_cookies', args);

        // Parse cookies from result
        let cookies: Array<{
          name: string;
          value: string;
          domain: string;
          path: string;
          httpOnly: boolean;
          secure: boolean;
        }> = [];
        if (Array.isArray(result)) {
          cookies = result as typeof cookies;
        } else if (typeof result === 'string') {
          try {
            cookies = JSON.parse(result);
          } catch {
            // Result might be in a different format
          }
        } else if (
          result &&
          typeof result === 'object' &&
          'cookies' in result
        ) {
          cookies = (result as { cookies: typeof cookies }).cookies;
        }

        // Build Cookie header string
        const cookieHeader = cookies
          .map((c) => `${c.name}=${c.value}`)
          .join('; ');

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
