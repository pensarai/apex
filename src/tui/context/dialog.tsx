import {
  useKeyboard,
  useRenderer,
  useTerminalDimensions,
} from "@opentui/react";
import {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
  useRef,
  type ReactNode,
} from "react";
import { type Renderable } from "@opentui/core";
import { colors } from "../theme";

interface DialogProps {
  size?: "medium" | "large";
  onClose: () => void;
  children?: ReactNode;
}

export function Dialog({ size = "medium", onClose, children }: DialogProps) {
  const dimensions = useTerminalDimensions();
  const renderer = useRenderer();

  return (
    <box
      onMouseUp={async () => {
        if (renderer.getSelection()) return;
        onClose?.();
      }}
      width={dimensions.width}
      height={dimensions.height}
      alignItems="center"
      position="absolute"
      paddingTop={dimensions.height / 4}
      left={0}
      top={0}
      backgroundColor={colors.modalOverlay}
    >
      <box
        onMouseUp={async (e: { stopPropagation: () => void }) => {
          if (renderer.getSelection()) return;
          e.stopPropagation();
        }}
        width={size === "large" ? 80 : 60}
        maxWidth={dimensions.width - 2}
        backgroundColor={colors.backgroundElement}
        paddingTop={1}
      >
        {children}
      </box>
    </box>
  );
}

interface DialogStackItem {
  element: ReactNode;
  onClose?: () => void;
}

interface DialogContextValue {
  clear: () => void;
  replace: (element: ReactNode, onClose?: () => void) => void;
  stack: DialogStackItem[];
  size: "medium" | "large";
  setSize: (size: "medium" | "large") => void;
  externalDialogOpen: boolean;
  setExternalDialogOpen: (open: boolean) => void;
}

const DialogContext = createContext<DialogContextValue | null>(null);

export function DialogProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<DialogStackItem[]>([]);
  const [size, setSize] = useState<"medium" | "large">("medium");
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
    setStack((prev) => {
      for (const item of prev) {
        if (item.onClose) item.onClose();
      }
      return [];
    });
    setSize("medium");
    refocus();
  }, [refocus]);

  const replace = useCallback(
    (element: ReactNode, onClose?: () => void) => {
      setStack((prev) => {
        if (prev.length === 0) {
          focusRef.current = renderer.currentFocusedRenderable;
        }
        for (const item of prev) {
          if (item.onClose) item.onClose();
        }
        return [{ element, onClose }];
      });
      setSize("medium");
    },
    [renderer],
  );

  useKeyboard((evt) => {
    if (evt.name === "escape") {
      setStack((prev) => {
        if (prev.length === 0) return prev;
        const current = prev[prev.length - 1];
        current?.onClose?.();
        evt.preventDefault();
        refocus();
        return prev.slice(0, -1);
      });
    }
  });

  const value: DialogContextValue = useMemo(
    () => ({
      clear,
      replace,
      stack,
      size,
      setSize,
      externalDialogOpen,
      setExternalDialogOpen,
    }),
    [clear, replace, stack, size, externalDialogOpen],
  );

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
