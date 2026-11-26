export type BrowserLink =
  | { type: "open-file"; path: string; sessionId?: string }
  | { type: "navigate"; url: string };

export function isBrowserFile(path: string) {
  return /\.(?:html?|xhtml|svg|pdf)$/i.test(path);
}

export type BrowserInput =
  | BrowserLink
  | { type: "back" | "forward" | "reload" }
  | { type: "new-tab"; url?: string }
  | { type: "select-tab" | "close-tab"; id: string }
  | { type: "dialog"; accept: boolean; text?: string };

export interface BrowserState {
  status: "idle" | "starting" | "ready" | "error";
  url: string;
  title: string;
  tabs: { id: string; title: string; url: string }[];
  activeTab?: string;
  canGoBack: boolean;
  canGoForward: boolean;
  agentActive: boolean;
  error?: string;
  dialog?: { type: string; message: string; defaultValue: string };
}
export interface BrowserViewDescriptor {
  id: string;
  url: string;
  partition: string;
}
export type BrowserEvent =
  | { type: "state"; state: BrowserState }
  | { type: "views"; views: BrowserViewDescriptor[] };
