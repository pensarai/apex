/**
 * Shared TUI Components and Utilities
 *
 * Re-exports for commonly used utilities across TUI components.
 */

// Markdown utilities
export { markdownToStyledText } from "./markdown";
export {
  MarkdownViewer,
  useMarkdownSyntaxStyle,
  useMarkdownRenderNode,
} from "./markdown-viewer";

// Message utilities
export {
  getStableMessageKey,
  getMessageContent,
  formatResult,
  tryParsePartialJson,
  extractStreamableContent,
} from "./message-utils";

// Type guards
export {
  isToolMessage,
  isPendingTool,
  isCompletedTool,
  isErroredTool,
  type ToolDisplayMessage,
} from "./type-guards";

// Registries
export {
  getToolSummary,
  registerToolSummary,
  hasToolSummary,
  getArgsPreview,
  getToolDisplayLabel,
} from "./tool-registry";
export {
  getResultSummary,
  formatResultDetail,
  type ResultSummary,
} from "./result-registry";

// Components
export {
  DialogControls,
  type ControlItem,
  type DialogControlsProps,
} from "./dialog-controls";
export { AsciiSpinner } from "./ascii-spinner";
export { ToolRenderer } from "./tool-renderer";
export { MessageRenderer } from "./message-renderer";
export { InlineApprovalPrompt, ApprovalInputArea } from "./approval-prompt";

// State management
export { useMessageState } from "./message-reducer";

// Input components
export { PromptInput, type PromptInputRef } from "./prompt-input";
export { type AutocompleteOption } from "./prompt-input";

// Action labels
export { deriveActionLabel, deriveApprovedActionLabel } from "./action-label";
