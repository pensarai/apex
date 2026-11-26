import type { BrowserEvent } from "../browser/contract";
import { api, browserEvents, operatorEvents } from "../view/bridge";
import type { OperatorMessages, OperatorSessionRequests } from "./contract";
import type { OperatorFrame } from "./live";

export type OperatorClient = {
  [K in keyof OperatorSessionRequests]: (
    params: OperatorSessionRequests[K]["params"],
  ) => Promise<OperatorSessionRequests[K]["response"]>;
} & {
  subscribeBrowser: (receive: (event: BrowserEvent) => void) => () => void;
  subscribe: (receive: (frame: OperatorFrame) => void) => () => void;
};

export function createOperatorClient(tabId: string): OperatorClient {
  return {
    operatorBrowserAttach: (params) =>
      api.operatorBrowserAttach({ ...params, tabId }),
    operatorBrowserWatch: (params) =>
      api.operatorBrowserWatch({ ...params, tabId }),
    operatorBrowserUnwatch: (params) =>
      api.operatorBrowserUnwatch({ ...params, tabId }),
    operatorBrowserInput: (params) =>
      api.operatorBrowserInput({ ...params, tabId }),
    subscribeBrowser: (receive) => {
      const listener = (event: Event) => {
        const payload = (
          event as CustomEvent<OperatorMessages["operatorBrowser"]>
        ).detail;
        if (payload.tabId === tabId) receive(payload.event);
      };
      browserEvents.addEventListener("browser", listener);
      return () => browserEvents.removeEventListener("browser", listener);
    },
    operatorSkills: () => api.operatorSkills({ tabId }),
    operatorGoal: (params) => api.operatorGoal({ ...params, tabId }),
    operatorAttackSurface: (params) =>
      api.operatorAttackSurface({ ...params, tabId }),
    operatorArguments: (params) => api.operatorArguments({ ...params, tabId }),
    operatorWatch: (params) => api.operatorWatch({ ...params, tabId }),
    operatorUnwatch: (params) => api.operatorUnwatch({ ...params, tabId }),
    operatorState: () => api.operatorState({ tabId }),
    operatorStart: (params) => api.operatorStart({ ...params, tabId }),
    operatorResume: (params) => api.operatorResume({ ...params, tabId }),
    operatorAction: (params) => api.operatorAction({ ...params, tabId }),
    operatorScreenshot: (params) =>
      api.operatorScreenshot({ ...params, tabId }),
    subscribe: (receive) => {
      const listener = (event: Event) => {
        const payload = (
          event as CustomEvent<OperatorMessages["operatorSnapshot"]>
        ).detail;
        if (payload.tabId === tabId) receive(payload.frame);
      };
      operatorEvents.addEventListener("snapshot", listener);
      return () => operatorEvents.removeEventListener("snapshot", listener);
    },
  };
}
