import type { Route } from "../context/route";
import { shouldHandlePromptSensitiveShortcut } from "./guards";
import {
  createKeybindingRegistry,
  type KeybindingRuntimeContext,
  type RegisteredKeybinding,
} from "./system";

export interface KeybindingDependencies {
  refocusPrompt: () => void;
  ctrlCPressTime: number | null;
  setCtrlCPressTime: (time: number | null) => void;
  setShowExitWarning: (show: boolean) => void;
  setInputKey: (fn: (prev: number) => number) => void;
  setShowSessionsDialog: (show: boolean) => void;
  setShowShortcutsDialog: (show: boolean) => void;
  setExternalDialogOpen: (open: boolean) => void;
  setFocusIndex: (fn: (prev: number) => number) => void;
  navigableItems: string[];
  /** Optional: Toggle tools panel visibility (session context only) */
  setShowToolsPanel?: (show: boolean) => void;
}

export interface KeybindingActionContext extends KeybindingRuntimeContext {
  route: Route;
  navigate: (route: Route) => void;
  toggleConsole: () => void;
  clearPromptInput: () => void;
  blurPrompt: () => void;
  exitApp: () => void;
}

export type KeybindingEntry = RegisteredKeybinding<KeybindingActionContext>;

export function createKeybindings(
  deps: KeybindingDependencies,
): KeybindingEntry[] {
  const {
    refocusPrompt,
    ctrlCPressTime,
    setCtrlCPressTime,
    setShowExitWarning,
    setInputKey,
    setShowSessionsDialog,
    setShowShortcutsDialog,
    setExternalDialogOpen,
    setFocusIndex,
    navigableItems,
    setShowToolsPanel,
  } = deps;

  const registry = createKeybindingRegistry<KeybindingActionContext>();

  registry.register({
    id: "exit-on-double-ctrl-c",
    combo: "ctrl+c",
    description: "Exit (press twice)",
    scope: "global",
    priority: 100,
    handler: async (context) => {
      const { exitApp } = context;
      const now = Date.now();
      const lastPress = ctrlCPressTime;

      if (lastPress && now - lastPress < 1000) {
        exitApp();
      } else {
        setInputKey((prev) => prev + 1);
        setCtrlCPressTime(now);
        setShowExitWarning(true);
      }
    },
  });

  registry.register({
    id: "toggle-console",
    combo: "ctrl+k",
    description: "Toggle console",
    scope: "global",
    priority: 90,
    handler: async (context) => {
      context.toggleConsole();
    },
  });

  registry.register({
    id: "navigate-home-on-escape",
    combo: "escape",
    description: "Return to home",
    scope: "global",
    priority: 80,
    when: ({ dialogStackDepth, externalDialogOpen }) =>
      dialogStackDepth === 0 && !externalDialogOpen,
    handler: async (context) => {
      const { route, navigate } = context;

      const isHome = route.type === "base" && route.path === "home";
      const isWeb = route.type === "base" && route.path === "web";
      const isOperator = route.type === "base" && route.path === "operator";
      const isSession = route.type === "pentest" || route.type === "operator";

      if (!isHome && !isWeb && !isOperator && !isSession) {
        navigate({
          type: "base",
          path: "home",
        });
        refocusPrompt();
      }
    },
  });

  registry.register({
    id: "show-sessions",
    combo: "ctrl+s",
    description: "Show sessions",
    scope: "global",
    priority: 70,
    when: ({ routeType, routePath }) =>
      routeType === "base" && routePath === "home",
    handler: async () => {
      setShowSessionsDialog(true);
    },
  });

  registry.register({
    id: "show-shortcuts-dialog",
    combo: "?",
    description: "Show keyboard shortcuts",
    scope: "prompt",
    priority: 70,
    when: ({ isPromptFocused, promptValue }) =>
      shouldHandlePromptSensitiveShortcut({
        combo: "?",
        isPromptFocused,
        promptValue,
      }),
    handler: async (context) => {
      context.clearPromptInput();
      context.blurPrompt();
      setExternalDialogOpen(true);
      setShowShortcutsDialog(true);
    },
  });

  registry.register({
    id: "focus-next-item",
    combo: "tab",
    description: "Next focusable item",
    scope: "global",
    priority: 60,
    handler: async () => {
      setFocusIndex((prev) => (prev + 1) % navigableItems.length);
    },
  });

  registry.register({
    id: "focus-previous-item",
    combo: "shift+tab",
    description: "Previous focusable item",
    scope: "prompt",
    priority: 60,
    when: ({ isPromptFocused, promptValue }) =>
      shouldHandlePromptSensitiveShortcut({
        combo: "shift+tab",
        isPromptFocused,
        promptValue,
      }),
    handler: async () => {
      setFocusIndex(
        (prev) => (prev - 1 + navigableItems.length) % navigableItems.length,
      );
    },
  });

  registry.register({
    id: "toggle-tools-panel",
    combo: "ctrl+t",
    description: "Toggle tools panel",
    scope: "session",
    priority: 60,
    when: ({ routeType }) =>
      routeType === "pentest" && Boolean(setShowToolsPanel),
    handler: async () => {
      setShowToolsPanel?.(true);
    },
  });

  return registry.list();
}
