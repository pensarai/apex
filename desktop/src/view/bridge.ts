import { Electroview } from "electrobun/view";
import type { DesktopRPC } from "../shared";

export const operatorEvents = new EventTarget();
export const runEvents = new EventTarget();
export const terminalEvents = new EventTarget();
const rpc = Electroview.defineRPC<DesktopRPC>({
  maxRequestTime: 60_000,
  handlers: {
    messages: {
      operatorSnapshot: (snapshot) =>
        operatorEvents.dispatchEvent(
          new CustomEvent("snapshot", { detail: snapshot }),
        ),
      runView: (event) =>
        runEvents.dispatchEvent(new CustomEvent("view", { detail: event })),
      output: ({ bytes }) =>
        terminalEvents.dispatchEvent(
          new CustomEvent("output", { detail: bytes }),
        ),
      exited: ({ code }) =>
        terminalEvents.dispatchEvent(
          new CustomEvent("exited", { detail: code }),
        ),
    },
  },
});
new Electroview({ rpc });
export const api = rpc.request;
export const send = rpc.send;
