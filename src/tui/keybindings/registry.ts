import { useRenderer } from "@opentui/react";
import { useDialog } from "../context/dialog";
import { useFocus } from "../context/focus";
import { useInput } from "../context/input";
import { useRoute } from "../context/route";

export interface KeybindingEntry {
  combo: string;
  description: string;
  fn: () => Promise<void>;
}

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
  onExit: () => Promise<void>;
  /** Optional: Toggle tools panel visibility (session context only) */
  setShowToolsPanel?: (show: boolean) => void;
}

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
    onExit,
    setShowToolsPanel,
  } = deps;

  const route = useRoute();
  const renderer = useRenderer();
  const { promptRef } = useFocus();
  const { inputValue, setInputValue, clearInput } = useInput();
  const { stack, externalDialogOpen } = useDialog();

  return [
    {
      combo: "ctrl+c",
      description: "Exit (press twice)",
      fn: async () => {
        const now = Date.now();
        const lastPress = ctrlCPressTime;

        if (lastPress && now - lastPress < 1000) {
          await onExit();
        } else {
          setInputKey((prev) => prev + 1);
          setCtrlCPressTime(now);
          setShowExitWarning(true);
        }
      },
    },
    {
      combo: "ctrl+k",
      description: "Toggle console",
      fn: async () => {
        renderer.console.toggle();
      },
    },
    {
      combo: "escape",
      description: "Return to home",
      fn: async () => {
        if (stack.length > 0 || externalDialogOpen) {
          return;
        }

        const isHome = route.data.type === "base" && route.data.path === "home";
        const isOperator =
          route.data.type === "base" && route.data.path === "operator";
        const isSession =
          route.data.type === "pentest" || route.data.type === "operator";

        if (!isHome && !isOperator && !isSession) {
          route.navigate({
            type: "base",
            path: "home",
          });
          refocusPrompt();
        }
      },
    },
    {
      combo: "ctrl+s",
      description: "Show sessions",
      fn: async () => {
        if (route.data.type === "base" && route.data.path === "home") {
          setShowSessionsDialog(true);
        }
      },
    },
    {
      combo: "?",
      description: "Show keyboard shortcuts",
      fn: async () => {
        clearInput();
        promptRef.current?.blur();
        setExternalDialogOpen(true);
        setShowShortcutsDialog(true);
      },
    },
    {
      combo: "tab",
      description: "Next focusable item",
      fn: async () => {
        setFocusIndex((prev) => (prev + 1) % navigableItems.length);
      },
    },
    {
      combo: "shift+tab",
      description: "Previous focusable item",
      fn: async () => {
        setFocusIndex(
          (prev) => (prev - 1 + navigableItems.length) % navigableItems.length,
        );
      },
    },
    {
      combo: "ctrl+t",
      description: "Toggle tools panel",
      fn: async () => {
        // Only works in session context
        if (route.data.type === "pentest" && setShowToolsPanel) {
          setShowToolsPanel(true);
        }
      },
    },
  ];
}
