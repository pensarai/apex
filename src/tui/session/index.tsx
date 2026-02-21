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
