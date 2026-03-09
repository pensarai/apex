/**
 * Centralized registry of all global keybindings in the application
 */

export interface Keybinding {
  key: string;
  description: string;
}

export const keybindings: Keybinding[] = [
  {
    key: "Ctrl+C",
    description: "Clear input / Exit application (press twice)",
  },
  {
    key: "Ctrl+K",
    description: "Toggle console",
  },
  // {
  //   key: "Ctrl+N",
  //   description: "Create new session"
  // },
  {
    key: "Ctrl+S",
    description: "Show sessions",
  },
  {
    key: "Ctrl+Y",
    description: "Copy selected (or last) message to clipboard",
  },
  {
    key: "Ctrl+Up/Down",
    description: "Navigate messages for copying",
  },
  {
    key: "Escape",
    description: "Return to home",
  },
  {
    key: "Tab",
    description: "Next item",
  },
  {
    key: "Shift+Tab",
    description: "Previous item",
  },
  {
    key: "?",
    description: "Show keyboard shortcuts",
  },
];
