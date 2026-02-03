
import { useRenderer } from "@opentui/react";
import { useRoute, type Route } from "../context/route";
import { useFocus } from "../context/focus";
import { useInput } from "../context/input";

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
    /** Optional: Toggle tools panel visibility (session context only) */
    setShowToolsPanel?: (show: boolean) => void;
}

export function createKeybindings(deps: KeybindingDependencies): KeybindingEntry[] {
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

    const route = useRoute();
    const renderer = useRenderer();
    const { promptRef } = useFocus();
    const { inputValue, setInputValue, clearInput } = useInput();

    return [
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
                const isHome = route.data.type === "base" && route.data.path === "home";
                const isWeb = route.data.type === "base" && route.data.path === "web";
                const isOperator = route.data.type === "base" && route.data.path === "operator";
                const isSession = route.data.type === "session";

                if (!isHome && !isWeb && !isOperator && !isSession) {
                    route.navigate({
                        type: "base",
                        path: "home"
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
                setFocusIndex((prev) => (prev - 1 + navigableItems.length) % navigableItems.length);
            },
        },
        {
            combo: "ctrl+t",
            description: "Toggle tools panel",
            fn: async () => {
                // Only works in session context
                if (route.data.type === "session" && setShowToolsPanel) {
                    setShowToolsPanel(true);
                }
            },
        },
    ];
}