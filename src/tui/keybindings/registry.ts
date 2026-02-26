import { useRenderer } from "@opentui/react";
import { useMemo } from "react";
import { useRoute } from "../context/route";
import { useFocus } from "../context/focus";
import { useInput } from "../context/input";
import { useUIState } from "../context/ui-state";
import { useDialog } from "../context/dialog";

export interface KeybindingEntry {
  combo: string;
  description: string;
  fn: () => Promise<void>;
}

export interface UseKeybindingsOptions {
  /** Optional: Toggle tools panel visibility (session context only) */
  setShowToolsPanel?: (show: boolean) => void;
}

// Keep the old interface exported for backwards compatibility with the barrel export
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

export function useKeybindings(
  options?: UseKeybindingsOptions,
): KeybindingEntry[] {
  const {
    ctrlCPressTime,
    setCtrlCPressTime,
    setShowExitWarning,
    setInputKey,
    setShowSessionsDialog,
    setShowShortcutsDialog,
    setFocusIndex,
    navigableItems,
  } = useUIState();

  const { refocusPrompt } = useFocus();
  const { setExternalDialogOpen } = useDialog();
  const route = useRoute();
  const renderer = useRenderer();
  const { promptRef } = useFocus();
  const { clearInput } = useInput();

  const setShowToolsPanel = options?.setShowToolsPanel;

  return useMemo(
    () => [
      {
        combo: "ctrl+c",
        description: "Exit (press twice)",
        fn: async () => {
          const now = Date.now();
          const lastPress = ctrlCPressTime;

          if (lastPress && now - lastPress < 1000) {
            renderer.destroy();
            process.exit(0);
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
          const isHome =
            route.data.type === "base" && route.data.path === "home";
          const isWeb = route.data.type === "base" && route.data.path === "web";
          const isOperator =
            route.data.type === "base" && route.data.path === "operator";
          const isSession = route.data.type === "pentest";

          if (!isHome && !isWeb && !isOperator && !isSession) {
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
            (prev) =>
              (prev - 1 + navigableItems.length) % navigableItems.length,
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
    ],
    [
      ctrlCPressTime,
      setCtrlCPressTime,
      setShowExitWarning,
      setInputKey,
      setShowSessionsDialog,
      setShowShortcutsDialog,
      setFocusIndex,
      navigableItems,
      refocusPrompt,
      setExternalDialogOpen,
      route,
      renderer,
      promptRef,
      clearInput,
      setShowToolsPanel,
    ],
  );
}

// Keep the old createKeybindings export name for the barrel re-export
export const createKeybindings = useKeybindings;
