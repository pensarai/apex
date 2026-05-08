/**
 * Shared TUI Components and Utilities
 *
 * Re-exports for commonly used utilities across TUI components.
 */

// Markdown utilities
export { markdownToStyledText } from "./markdown";
export {
  useMarkdownSyntaxStyle,
  useMarkdownRenderNode,
} from "./markdown-viewer";

// Message utilities
export {
  getStableMessageKey,
  tryParsePartialJson,
  extractStreamableContent,
} from "./message-utils";

// Type guards
export { isToolMessage, type ToolDisplayMessage } from "./type-guards";

// Registries
export {
  getToolSummary,
  getArgsPreview,
  getToolDisplayLabel,
} from "./tool-registry";

// Components
export {
  DialogControls,
  type ControlItem,
  type DialogControlsProps,
} from "./dialog-controls";
export { AsciiSpinner } from "./ascii-spinner";
export { MessageRenderer } from "./message-renderer";

// Input components
export { PromptInput, type PromptInputRef } from "./prompt-input";
export { type AutocompleteOption } from "./prompt-input";

// Action labels
export { deriveActionLabel, deriveApprovedActionLabel } from "./action-label";
