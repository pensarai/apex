/**
 * Centralised obfuscation interception for the TUI's text-rendering layer.
 *
 * Instead of every component calling `obfuscate(...)` on the strings it
 * passes to `<text>`, we monkey-patch the two `TextNodeRenderable` entry
 * points that the @opentui/react reconciler funnels every JSX text leaf
 * through:
 *
 *   - `TextNodeRenderable.fromString(text)` — invoked by the host config's
 *     `createTextInstance`, i.e. every time a string child is mounted.
 *   - `TextNodeRenderable.prototype.children` setter — invoked by
 *     `commitTextUpdate`, i.e. every time a string child changes.
 *
 * Each patched node remembers its original (unobfuscated) text in a
 * symbol-keyed slot. On `/obfuscate` toggle, `refreshObfuscatedText`
 * walks the renderer's tree and re-feeds those originals through the
 * setter, which re-evaluates them against the new engine state. Without
 * the walker, only newly-committed text would honour the toggle —
 * existing rendered prose would lag because React's reconciler skips
 * `commitTextUpdate` when the string value hasn't changed.
 *
 * Notes:
 *   - `<textarea>` / `<input>` use a different renderable path that
 *     bypasses `TextNodeRenderable`, so the operator's own typing is
 *     never auto-obfuscated by this patch. PromptInput keeps its
 *     explicit obfuscation flow.
 *   - `<text content={styledText} />` flows through TextRenderable's
 *     content setter, not through here. Tool/result rendering already
 *     obfuscates StyledText upstream in `result-registry.ts`.
 */

import {
  TextNodeRenderable,
  TextRenderable,
  type CliRenderer,
  type BaseRenderable,
} from "@opentui/core";
import { obfuscate, isObfuscationEnabled } from "../../core/obfuscation";

const ORIGINAL = Symbol.for("pensar.obfuscation.originalChildren");

type Carrier = TextNodeRenderable & {
  [ORIGINAL]?: ReadonlyArray<string | TextNodeRenderable>;
};

let installed = false;

/**
 * Install the prototype patches. Idempotent — safe to call from both
 * test setup and the production entrypoint. Must run before any TUI
 * component renders so the very first frame goes through the patched
 * setter.
 */
export function installObfuscationTextPatch(): void {
  if (installed) return;
  installed = true;

  patchFromString();
  patchChildrenSetter();
}

function patchFromString(): void {
  const original = TextNodeRenderable.fromString.bind(TextNodeRenderable);
  TextNodeRenderable.fromString = function patchedFromString(
    text: string,
    options?: Parameters<typeof TextNodeRenderable.fromString>[1],
  ): TextNodeRenderable {
    const node = original(transform(text), options) as Carrier;
    node[ORIGINAL] = [text];
    return node;
  };
}

function patchChildrenSetter(): void {
  const descriptor = Object.getOwnPropertyDescriptor(
    TextNodeRenderable.prototype,
    "children",
  );
  if (!descriptor || !descriptor.set) {
    throw new Error(
      "Obfuscation patch: TextNodeRenderable.prototype.children setter not found.",
    );
  }
  const originalSetter = descriptor.set;
  Object.defineProperty(TextNodeRenderable.prototype, "children", {
    ...descriptor,
    set(
      this: Carrier,
      next: ReadonlyArray<string | TextNodeRenderable>,
    ) {
      this[ORIGINAL] = Array.isArray(next) ? [...next] : next;
      const transformed = next.map((child) =>
        typeof child === "string" ? transform(child) : child,
      );
      originalSetter.call(this, transformed);
    },
  });
}

function transform(text: string): string {
  if (!isObfuscationEnabled()) return text;
  return obfuscate(text);
}

/**
 * Walk the renderer's tree and re-emit every `TextNodeRenderable`'s
 * children from its stored originals. Each re-emit goes through the
 * patched `children` setter, which re-evaluates the strings against
 * the current obfuscation state.
 *
 * Call this whenever the engine's `enabled` flag flips so existing
 * text on screen retroactively reflects the new state.
 */
export function refreshObfuscatedText(renderer: CliRenderer): void {
  if (!installed) return;
  walk(renderer.root as unknown as BaseRenderable, (node) => {
    if (!(node instanceof TextNodeRenderable)) return;
    const carrier = node as Carrier;
    const original = carrier[ORIGINAL];
    if (!original || original.length === 0) return;
    // Going through the setter is intentional: it re-records originals
    // (idempotent — same array) and re-applies `transform`.
    node.children = [...original];
  });
}

function walk(
  node: BaseRenderable,
  fn: (node: BaseRenderable) => void,
): void {
  fn(node);

  // `<text>` keeps its TextNodeRenderable subtree on a side-channel
  // (`textNode`) because TextNodeRenderable extends BaseRenderable but
  // not Renderable, so it's invisible to Renderable.getChildren(). Cross
  // the boundary explicitly or we never visit the leaves where the
  // [ORIGINAL] markers live.
  if (node instanceof TextRenderable) {
    walk(node.textNode as unknown as BaseRenderable, fn);
  }

  const children = node.getChildren?.();
  if (!children) return;
  for (const child of children) walk(child, fn);
}
