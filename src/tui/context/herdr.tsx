import { createContext, type ReactNode, useContext } from "react";
import type { createHerdrReporter } from "../../core/integrations/herdr";

type HerdrReporter = ReturnType<typeof createHerdrReporter>;

// Embedded hosts and component tests do not own a Herdr pane.
const noopReporter: HerdrReporter = {
  report: () => {},
  release: () => Promise.resolve(),
};

const HerdrContext = createContext<HerdrReporter>(noopReporter);

export function HerdrProvider({
  reporter,
  children,
}: {
  reporter: HerdrReporter;
  children: ReactNode;
}) {
  return (
    <HerdrContext.Provider value={reporter}>{children}</HerdrContext.Provider>
  );
}

export function useHerdr(): HerdrReporter {
  return useContext(HerdrContext);
}
