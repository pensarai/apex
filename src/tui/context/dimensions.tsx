import { createContext, useContext, type ReactNode } from "react";
import { useTerminalDimensions } from "@opentui/react";

interface Dimensions {
  width: number;
  height: number;
}

const DimensionsContext = createContext<Dimensions | null>(null);

export function TerminalDimensionsProvider({
  children,
}: {
  children: ReactNode;
}) {
  const dimensions = useTerminalDimensions();
  return (
    <DimensionsContext.Provider value={dimensions}>
      {children}
    </DimensionsContext.Provider>
  );
}

export function useDimensions(): Dimensions {
  const ctx = useContext(DimensionsContext);
  if (!ctx)
    throw new Error(
      "useDimensions() must be used within <TerminalDimensionsProvider>",
    );
  return ctx;
}
