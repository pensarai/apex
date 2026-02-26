import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  type ReactNode,
} from "react";

interface UIStateContextValue {
  focusIndex: number;
  setFocusIndex: (fn: (prev: number) => number) => void;
  ctrlCPressTime: number | null;
  setCtrlCPressTime: (time: number | null) => void;
  showExitWarning: boolean;
  setShowExitWarning: (show: boolean) => void;
  inputKey: number;
  setInputKey: (fn: (prev: number) => number) => void;
  showSessionsDialog: boolean;
  setShowSessionsDialog: (show: boolean) => void;
  showShortcutsDialog: boolean;
  setShowShortcutsDialog: (show: boolean) => void;
  navigableItems: string[];
}

const UIStateContext = createContext<UIStateContextValue | null>(null);

export function useUIState(): UIStateContextValue {
  const context = useContext(UIStateContext);
  if (!context) {
    throw new Error("useUIState must be used within UIStateProvider");
  }
  return context;
}

interface UIStateProviderProps {
  children: ReactNode;
}

const NAVIGABLE_ITEMS = ["command-input"];

export function UIStateProvider({ children }: UIStateProviderProps) {
  const [focusIndex, setFocusIndex] = useState(0);
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0);
  const [showSessionsDialog, setShowSessionsDialog] = useState(false);
  const [showShortcutsDialog, setShowShortcutsDialog] = useState(false);

  // Wrap setFocusIndex and setInputKey to accept updater functions
  const wrappedSetFocusIndex = useCallback(
    (fn: (prev: number) => number) => setFocusIndex(fn),
    [],
  );

  const wrappedSetInputKey = useCallback(
    (fn: (prev: number) => number) => setInputKey(fn),
    [],
  );

  const value = useMemo(
    () => ({
      focusIndex,
      setFocusIndex: wrappedSetFocusIndex,
      ctrlCPressTime,
      setCtrlCPressTime,
      showExitWarning,
      setShowExitWarning,
      inputKey,
      setInputKey: wrappedSetInputKey,
      showSessionsDialog,
      setShowSessionsDialog,
      showShortcutsDialog,
      setShowShortcutsDialog,
      navigableItems: NAVIGABLE_ITEMS,
    }),
    [
      focusIndex,
      wrappedSetFocusIndex,
      ctrlCPressTime,
      showExitWarning,
      inputKey,
      wrappedSetInputKey,
      showSessionsDialog,
      showShortcutsDialog,
    ],
  );

  return (
    <UIStateContext.Provider value={value}>{children}</UIStateContext.Provider>
  );
}
