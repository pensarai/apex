/**
 * Unified Session Component
 *
 * Single component handling both "chat" and "operator" modes.
 * Consolidates ChatView and OperatorDashboard into one implementation.
 *
 * Uses existing infrastructure:
 * - SessionProvider for session data
 * - AgentProvider for model/tokens
 * - useMessageState for O(1) message updates
 *
 * Features:
 * - Mode-aware layout (sidebar visible in operator mode)
 * - Inline approval rendering
 * - Streaming message support
 * - State persistence for resume
 */

import { type SessionInfo } from "../../core/session";

import type { ModelInfo } from "../../core/ai";

// Session sub-components

// ============================================
// Types
// ============================================

export interface SessionProps {
  /** Session info */
  session: SessionInfo;
  /** Display mode */
  mode: "chat" | "operator";
  /** Model to use (if not using AgentProvider default) */
  model?: ModelInfo;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
  /** If true, synthesize operator context from swarm session data */
  openAsOperator?: boolean;
  /** Initial directive to send when agent is ready */
  initialDirective?: string;
  /** Callback when exiting session */
  onExit?: () => void;
}

// ============================================
// Helper Functions
// ============================================

/**
 * Parse port from target URL or IP:port string
 */
function parsePortFromTarget(target: string): number | null {
  try {
    const url = new URL(target);
    if (url.port) return parseInt(url.port, 10);
    if (url.protocol === "https:") return 443;
    if (url.protocol === "http:") return 80;
  } catch {
    const match = target.match(/:(\d+)$/);
    if (match) return parseInt(match[1], 10);
  }
  return null;
}

/**
 * Extract hostname from target URL
 */
function parseHostFromTarget(target: string): string {
  try {
    const url = new URL(target);
    return url.hostname;
  } catch {
    return target.replace(/:(\d+)$/, "");
  }
}

// Re-export sub-components for external use
export { Header } from "../components/chat/header";
export { MessageList } from "../components/chat/message-list";
export { InputArea } from "../components/chat/input-area";
export {
  Sidebar,
  useSidebarState,
  type SidebarState,
} from "../components/chat/sidebar";
export { InlineApprovalPrompt } from "../components/chat/approval-inline";
export { ToolMessage } from "../components/chat/tool-message";
export {
  LoadingIndicator,
  type LoadingState,
} from "../components/chat/loading-indicator";
