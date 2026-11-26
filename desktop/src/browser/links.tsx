import { createContext } from "react";
import type { BrowserLink } from "./contract";

export type { BrowserLink } from "./contract";

export const BrowserLinkContext = createContext<
  ((link: BrowserLink) => Promise<void>) | undefined
>(undefined);
