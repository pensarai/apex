/**
 * Shared TUI Components and Utilities
 *
 * Re-exports for commonly used utilities across TUI components.
 */

// Action labels
export { deriveActionLabel, deriveApprovedActionLabel } from "./action-label";
export { AsciiSpinner } from "./ascii-spinner";
// Components
export {
  type ControlItem,
  DialogControls,
} from "./dialog-controls";
// Markdown utilities
export { markdownToStyledText } from "./markdown";
export {
  useMarkdownRenderNode,
  useMarkdownSyntaxStyle,
} from "./markdown-viewer";
export { MessageRenderer } from "./message-renderer";
// Message utilities
export { getStableMessageKey, tryParsePartialJson } from "./message-utils";
// Input components
export {
  type AutocompleteOption,
  PromptInput,
  type PromptInputRef,
} from "./prompt-input";
// Registries
export {
  getArgsPreview,
  getToolDisplayLabel,
  getToolSummary,
} from "./tool-registry";
// Type guards
export { isToolMessage } from "./type-guards";
