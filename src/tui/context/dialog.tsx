import type { Renderable } from "@opentui/core";
import { useKeyboard, useRenderer } from "@opentui/react";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useRef,
  useState,
} from "react";
import { useTheme } from "../theme";
import { useDimensions } from "./dimensions";

interface DialogProps {
  size?: "medium" | "large" | "xlarge";
  onClose: () => void;
  /** Hide the escape dismiss hint and prevent click-outside close */
  hideEsc?: boolean;
  children?: ReactNode;
}

const DIALOG_WIDTHS: Record<string, number> = {
  medium: 60,
  large: 80,
  xlarge: 120,
};

export function Dialog({
  size = "medium",
  onClose,
  hideEsc = false,
  children,
}: DialogProps) {
  const dimensions = useDimensions();
  const renderer = useRenderer();
  const { colors: themeColors } = useTheme();
  return (
    <box
      onMouseUp={async () => {
        if (hideEsc) return;
        if (renderer.getSelection()) return;
        onClose?.();
      }}
      width={dimensions.width}
      height={dimensions.height}
      alignItems="center"
      justifyContent="center"
      position="absolute"
      paddingTop={2}
      paddingBottom={2}
      left={0}
      top={0}
      backgroundColor={themeColors.backgroundOverlay}
    >
      <box
        onMouseUp={async (e: { stopPropagation: () => void }) => {
          if (renderer.getSelection()) return;
          e.stopPropagation();
        }}
        width={DIALOG_WIDTHS[size] ?? 60}
        maxWidth={dimensions.width - 2}
        maxHeight={dimensions.height - 4}
        overflow="scroll"
        backgroundColor={themeColors.backgroundElement}
        flexDirection="column"
        flexGrow={0}
      >
        {children}
      </box>
    </box>
  );
}

interface DialogStackItem {
  element: ReactNode;
  onClose?: () => void;
  /** When true, the dialog content handles Escape itself; the provider skips its handler. */
  selfHandlesEscape?: boolean;
}

interface ReplaceOptions {
  onClose?: () => void;
  /** When true, the dialog content handles Escape itself; the provider skips its handler. */
  selfHandlesEscape?: boolean;
  /** Override the dialog size for this replacement (defaults to "medium"). */
  size?: "medium" | "large" | "xlarge";
}

interface DialogContextValue {
  clear: () => void;
  replace: (element: ReactNode, options?: ReplaceOptions) => void;
  stack: DialogStackItem[];
  size: "medium" | "large" | "xlarge";
  setSize: (size: "medium" | "large" | "xlarge") => void;
  externalDialogOpen: boolean;
  setExternalDialogOpen: (open: boolean) => void;
}

const DialogContext = createContext<DialogContextValue | null>(null);

export function DialogProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<DialogStackItem[]>([]);
  const [size, setSize] = useState<"medium" | "large" | "xlarge">("medium");
  const [externalDialogOpen, setExternalDialogOpen] = useState(false);
  const renderer = useRenderer();
  const focusRef = useRef<Renderable | null>(null);

  const refocus = useCallback(() => {
    setTimeout(() => {
      const focus = focusRef.current;
      if (!focus) return;
      if (focus.isDestroyed) return;

      function find(item: Renderable): boolean {
        for (const child of item.getChildren()) {
          if (child === focus) return true;
          if (find(child)) return true;
        }
        return false;
      }

      const found = find(renderer.root);
      if (!found) return;
      focus.focus();
    }, 1);
  }, [renderer]);

  const clear = useCallback(() => {
    for (const item of stack) {
      if (item.onClose) item.onClose();
    }
    setSize("medium");
    setStack([]);
    refocus();
  }, [stack, refocus]);

  const replace = useCallback(
    (element: ReactNode, options?: ReplaceOptions) => {
      if (stack.length === 0) {
        focusRef.current = renderer.currentFocusedRenderable;
      }
      for (const item of stack) {
        if (item.onClose) item.onClose();
      }
      setSize(options?.size ?? "medium");
      setStack([
        {
          element,
          onClose: options?.onClose,
          selfHandlesEscape: options?.selfHandlesEscape,
        },
      ]);
    },
    [stack, renderer],
  );

  useKeyboard((evt) => {
    if (evt.name === "escape" && stack.length > 0) {
      const current = stack[stack.length - 1];
      if (current?.selfHandlesEscape) return;
      current?.onClose?.();
      setStack(stack.slice(0, -1));
      evt.preventDefault();
      refocus();
    }
  });

  const value: DialogContextValue = {
    clear,
    replace,
    stack,
    size,
    setSize,
    externalDialogOpen,
    setExternalDialogOpen,
  };

  return (
    <DialogContext.Provider value={value}>
      {children}
      <box position="absolute">
        {stack.length > 0 && (
          <Dialog onClose={clear} size={size}>
            {stack[stack.length - 1]!.element}
          </Dialog>
        )}
      </box>
    </DialogContext.Provider>
  );
}

export function useDialog() {
  const value = useContext(DialogContext);
  if (!value) {
    throw new Error("useDialog must be used within a DialogProvider");
  }
  return value;
}
