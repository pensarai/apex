import { FitAddon } from "@xterm/addon-fit";
import { Terminal as Xterm } from "@xterm/xterm";
import { useEffect, useRef } from "react";
import { api, send, terminalEvents } from "./bridge";
import "@xterm/xterm/css/xterm.css";

export interface TerminalLaunch {
  id?: string;
}
export function Terminal({
  launch,
  visible,
  onExit,
}: {
  launch: TerminalLaunch;
  visible: boolean;
  onExit: (message: string) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const term = useRef<Xterm>(null);
  useEffect(() => {
    if (!box.current) return;
    const container = box.current;
    const terminal = new Xterm({
      fontFamily: '"Berkeley Mono", monospace',
      fontSize: 13,
      scrollback: 2000,
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(container);
    term.current = terminal;
    const resize = () => {
      if (container.clientWidth && container.clientHeight) fit.fit();
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(container);
    const output = (event: Event) => {
      const raw = atob((event as CustomEvent<string>).detail);
      terminal.write(Uint8Array.from(raw, (c) => c.charCodeAt(0)));
    };
    const exited = (event: Event) =>
      onExit(
        `Terminal exited with code ${(event as CustomEvent<number>).detail}.`,
      );
    terminalEvents.addEventListener("output", output);
    terminalEvents.addEventListener("exited", exited);
    terminal.onData((data) => send.input({ data }));
    terminal.onResize((size) => send.resize(size));
    void api
      .startTerminal({
        id: launch.id,
        cols: terminal.cols,
        rows: terminal.rows,
      })
      .catch((e) => onExit(String(e)));
    terminal.focus();
    return () => {
      terminalEvents.removeEventListener("output", output);
      terminalEvents.removeEventListener("exited", exited);
      observer.disconnect();
      terminal.dispose();
      term.current = null;
    };
  }, [launch, onExit]);
  useEffect(() => {
    if (visible) term.current?.focus();
  }, [visible]);
  return (
    <div
      ref={box}
      className="terminal"
      hidden={!visible}
      aria-label="Interactive Apex terminal"
    />
  );
}
