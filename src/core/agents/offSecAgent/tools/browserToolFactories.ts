import { tool } from "ai";
import { z } from "zod";
import type {
  BrowserBackend,
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserCookiesResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
  BrowserSnapshotResult,
} from "../../../tools/backends/types";

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

const BrowserSnapshotInput = z.object({
  toolCallDescription: z
    .string()
    .describe("Why you need to get the page snapshot"),
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

export function createBackendBrowserToolFactories(
  backend: BrowserBackend,
  {
    targetUrl,
    mode = "operator",
  }: { targetUrl: string; mode?: BrowserToolMode },
) {
  const descriptions =
    mode === "pentest"
      ? PENTEST_DESCRIPTIONS
      : mode === "auth"
        ? AUTH_DESCRIPTIONS
        : OPERATOR_DESCRIPTIONS;

  return {
    browser_navigate: () =>
      tool({
        description:
          descriptions.navigate + `\n\nTarget base URL: ${targetUrl}`,
        inputSchema: BrowserNavigateInput,
        execute: ({ url }): Promise<BrowserNavigateResult> =>
          backend.navigate(url),
      }),

    browser_screenshot: () =>
      tool({
        description: descriptions.screenshot,
        inputSchema: BrowserScreenshotInput,
        execute: ({ filename }): Promise<BrowserScreenshotResult> =>
          backend.screenshot({ filename }),
      }),

    browser_snapshot: () =>
      tool({
        description: `Get the accessibility snapshot of the current page.

IMPORTANT: Call this BEFORE using browser_click or browser_fill to get element references (refs).
The snapshot returns an accessibility tree with elements marked like [ref=e5].
Use these refs in browser_click and browser_fill for precise element targeting.

Example workflow:
1. Call browser_snapshot to get the page structure
2. Find the element you need (e.g., "textbox 'Email'" with [ref=e3])
3. Call browser_fill with ref="e3" to fill that specific element`,
        inputSchema: BrowserSnapshotInput,
        execute: (): Promise<BrowserSnapshotResult> => backend.snapshot(),
      }),

    browser_click: () =>
      tool({
        description:
          descriptions.click +
          `\n\nIMPORTANT: For reliable clicking, first call browser_snapshot to get element refs, then pass the ref parameter.`,
        inputSchema: BrowserClickInput,
        execute: ({ element, ref }): Promise<BrowserClickResult> =>
          backend.click({ element, ref }),
      }),

    browser_fill: () =>
      tool({
        description:
          descriptions.fill +
          `\n\nIMPORTANT: For reliable form filling, first call browser_snapshot to get element refs, then pass the ref parameter.`,
        inputSchema: BrowserFillInput,
        execute: ({ element, ref, value }): Promise<BrowserFillResult> =>
          backend.fill({ element, ref, value }),
      }),

    browser_evaluate: () =>
      tool({
        description: descriptions.evaluate,
        inputSchema: BrowserEvaluateInput,
        execute: ({ script }): Promise<BrowserEvaluateResult> =>
          backend.evaluate({ script }),
      }),

    browser_console: () =>
      tool({
        description: descriptions.console,
        inputSchema: BrowserConsoleInput,
        execute: (): Promise<BrowserConsoleResult> => backend.console(),
      }),

    browser_get_cookies: () =>
      tool({
        description: `Extract cookies from the browser context, including httpOnly cookies.

CRITICAL: Use this after successful browser authentication to get session cookies that can be used in HTTP requests.

Returns all cookies including:
- Session cookies (often httpOnly, not accessible via document.cookie)
- Authentication tokens
- CSRF tokens

The returned cookies can be formatted as a Cookie header for use with http_request tool.`,
        inputSchema: BrowserGetCookiesInput,
        execute: ({ urls }): Promise<BrowserCookiesResult> =>
          backend.getCookies({ urls }),
      }),
  };
}
