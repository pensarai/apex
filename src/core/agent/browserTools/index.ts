/**
 * Browser Tools Module
 *
 * Exports Playwright MCP-based browser automation tools for vulnerability testing.
 * These tools are available in Operator mode (HITL) only.
 */

export {
  createBrowserTools,
  initializeMcpClient,
  disconnectMcpClient,
  isClientConnected,
  setHeadlessMode,
  setExtraHttpHeaders,
  type BrowserNavigateResult,
  type BrowserScreenshotResult,
  type BrowserClickResult,
  type BrowserFillResult,
  type BrowserEvaluateResult,
  type BrowserConsoleResult,
  type CreateBrowserToolsOptions,
  type BrowserToolMode,
} from "./playwrightMcp";
