import "./settings.css";
import { useEffect } from "react";
import {
  obfuscate,
  setObfuscationEnabled,
} from "../../../src/core/obfuscation";
import themeData from "../../node_modules/.cache/apex-themes.json";
import { api } from "../view/bridge";
import type { Appearance } from "./contract";

export const themes: Record<
  string,
  { name: string; light: Record<string, string>; dark: Record<string, string> }
> = themeData;
const tokens = {
  canvas: "background",
  "canvas-zero": "backgroundPanel",
  surface: "backgroundPanel",
  "surface-2": "backgroundElement",
  "surface-3": "backgroundSelected",
  border: "border",
  "border-strong": "borderActive",
  fg: "text",
  "fg-2": "text",
  "fg-3": "textMuted",
  "fg-4": "textMuted",
  accent: "primary",
} as const;

export async function runAppearanceCommand(
  command: "obfuscate" | "theme",
  args: readonly string[],
): Promise<string> {
  const value = await api.desktopAppearance();
  const argument = args[0]?.toLowerCase();
  if (command === "obfuscate") {
    if (!argument || argument === "toggle") value.obfuscate = !value.obfuscate;
    else if (argument === "on" || argument === "enable") value.obfuscate = true;
    else if (argument === "off" || argument === "disable")
      value.obfuscate = false;
    else throw new Error("Use /obfuscate on, off, or toggle.");
  } else if (argument === "mode") {
    const mode = args[1];
    value.mode =
      mode === "dark" || mode === "light" || mode === "auto"
        ? mode
        : value.mode === "light"
          ? "dark"
          : "light";
  } else {
    const theme = Object.keys(themes).find((t) => t.toLowerCase() === argument);
    if (!theme) throw new Error("Unknown theme.");
    value.theme = theme;
  }
  const settings = await api.changeSettings({ kind: "appearance", value });
  window.dispatchEvent(
    new CustomEvent("apex:appearance", { detail: settings.appearance }),
  );
  window.dispatchEvent(new CustomEvent("apex:settings", { detail: settings }));
  return command === "obfuscate"
    ? `Obfuscation ${value.obfuscate ? "enabled" : "disabled"}.`
    : `Theme ${value.theme} · ${value.mode}`;
}

function redactDisplay() {
  const originals = new WeakMap<Text, { source: string; display: string }>();
  const titles = new WeakMap<Element, { source: string; display: string }>();
  function title(el: Element) {
    const source = el.getAttribute("title");
    if (source === null || source === titles.get(el)?.display) return;
    const display = obfuscate(source);
    if (display !== source) {
      titles.set(el, { source, display });
      el.setAttribute("title", display);
    } else titles.delete(el);
  }
  function update(node: Node) {
    if (node instanceof Text) {
      if (node.parentElement?.closest("script,style,textarea")) return;
      const source = node.data;
      if (source === originals.get(node)?.display) return;
      const display = obfuscate(source);
      if (display !== source) {
        originals.set(node, { source, display });
        node.data = display;
      } else originals.delete(node);
    } else if (node instanceof Element) {
      title(node);
      for (const child of node.childNodes) update(child);
    }
  }
  update(document.body);
  const observer = new MutationObserver((changes) => {
    for (const change of changes) {
      if (change.type === "characterData") update(change.target);
      else if (change.type === "attributes") title(change.target as Element);
      else for (const node of change.addedNodes) update(node);
    }
  });
  observer.observe(document.body, {
    subtree: true,
    characterData: true,
    childList: true,
    attributes: true,
    attributeFilter: ["title"],
  });
  return () => {
    observer.disconnect();
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
    );
    for (
      let node = walker.nextNode() as Text | null;
      node;
      node = walker.nextNode() as Text | null
    ) {
      const entry = originals.get(node);
      if (entry && node.data === entry.display) node.data = entry.source;
    }
    for (const el of document.querySelectorAll("[title]")) {
      const entry = titles.get(el);
      if (entry && el.getAttribute("title") === entry.display)
        el.setAttribute("title", entry.source);
    }
  };
}

export function useDesktopAppearance() {
  useEffect(() => {
    let active = true;
    let current: Appearance | undefined;
    let restore: (() => void) | undefined;
    const media = matchMedia("(prefers-color-scheme: light)");
    const root = document.documentElement;
    function apply(settings: Appearance) {
      current = settings;
      const mode =
        settings.mode === "auto"
          ? media.matches
            ? "light"
            : "dark"
          : settings.mode;
      const theme = themes[settings.theme] ?? themes.apex;
      for (const [token, key] of Object.entries(tokens)) {
        const prop = `--color-${token}`;
        if (settings.theme === "apex" && mode === "dark")
          root.style.removeProperty(prop);
        else root.style.setProperty(prop, theme[mode][key]);
      }
      root.style.colorScheme = mode;
      root.classList.toggle("apex-transparent", settings.transparent);
      root.classList.toggle("apex-obfuscated", settings.obfuscate);
      setObfuscationEnabled(settings.obfuscate);
      if (settings.obfuscate) restore ??= redactDisplay();
      else {
        restore?.();
        restore = undefined;
      }
    }
    const changed = (event: Event) =>
      apply((event as CustomEvent<Appearance>).detail);
    const system = () => {
      if (current) apply(current);
    };
    window.addEventListener("apex:appearance", changed);
    media.addEventListener("change", system);
    void api
      .desktopAppearance()
      .then((result) => {
        if (active && !current) apply(result);
      })
      .catch(console.error);
    return () => {
      active = false;
      restore?.();
      window.removeEventListener("apex:appearance", changed);
      media.removeEventListener("change", system);
    };
  }, []);
}
