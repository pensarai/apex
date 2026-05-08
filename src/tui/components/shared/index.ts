/**
 * Shared TUI Components and Utilities
 *
 * Re-exports for commonly used utilities across TUI components.
 */

// Action labels
export { deriveActionLabel, deriveApprovedActionLabel } from "./action-label";
export { ApprovalInputArea, InlineApprovalPrompt } from "./approval-prompt";
export { AsciiSpinner } from "./ascii-spinner";
// Components
export {
  type ControlItem,
  DialogControls,
  type DialogControlsProps,
} from "./dialog-controls";
// Markdown utilities
export { markdownToStyledText } from "./markdown";
export {
  MarkdownViewer,
  useMarkdownRenderNode,
  useMarkdownSyntaxStyle,
} from "./markdown-viewer";
// State management
export { useMessageState } from "./message-reducer";
export { MessageRenderer } from "./message-renderer";
// Message utilities
export {
  extractStreamableContent,
  formatResult,
  getMessageContent,
  getStableMessageKey,
  tryParsePartialJson,
} from "./message-utils";
// Input components
export {
  type AutocompleteOption,
  PromptInput,
  type PromptInputRef,
} from "./prompt-input";
export {
  formatResultDetail,
  getResultSummary,
  type ResultSummary,
} from "./result-registry";
// Registries
export {
  getArgsPreview,
  getToolDisplayLabel,
  getToolSummary,
  hasToolSummary,
  registerToolSummary,
} from "./tool-registry";
export { ToolRenderer } from "./tool-renderer";
// Type guards
export {
  isCompletedTool,
  isErroredTool,
  isPendingTool,
  isToolMessage,
  type ToolDisplayMessage,
} from "./type-guards";
