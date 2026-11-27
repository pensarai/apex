import { runInNewContext } from "node:vm";
import type { BunPlugin } from "bun";
import ts from "typescript";
import { afterEach, expect, it, vi } from "vitest";
import { electrobunNativeCompat } from "./electrobun-native-compat";

afterEach(() => vi.unstubAllGlobals());

it("accepts decoded callback strings while retaining pointer-based native results", async () => {
  const onLoad = vi.fn();
  electrobunNativeCompat.setup({ onLoad } as unknown as Parameters<
    BunPlugin["setup"]
  >[0]);
  const [options, load] = onLoad.mock.calls[0];
  for (const path of [
    "/app/node_modules/electrobun/dist/api/bun/proc/native.ts",
    "C:\\app\\node_modules\\electrobun\\dist-win-x64\\api\\bun\\proc\\native.ts",
  ]) {
    expect(options.filter.test(path)).toBe(true);
  }
  vi.stubGlobal("Bun", {
    file: () => ({
      text: async () =>
        "function decode(value) { return new CString(value).toString(); }",
    }),
  });
  const result = await load({ path: "native.ts" });
  const decodedPointers: number[] = [];
  class CString {
    constructor(value: number) {
      if (typeof value !== "number") throw new Error("ptr must be a number");
      decodedPointers.push(value);
    }
    toString() {
      return "native pointer text";
    }
  }
  const code = ts.transpileModule(result.contents, {
    compilerOptions: { target: ts.ScriptTarget.ESNext },
  }).outputText;
  const decode = runInNewContext(`${code}\ndecode`, { CString }) as (
    value: unknown,
  ) => string;
  expect(decode('{"event":"ready"}')).toBe('{"event":"ready"}');
  expect(decode(new String("decoded callback"))).toBe("decoded callback");
  expect(decodedPointers).toEqual([]);
  expect(decode(42)).toBe("native pointer text");
  expect(decodedPointers).toEqual([42]);
});

it.each([
  ["Win32", "cef", 1.5, 1.5],
  ["Win32", "cef", 1, 1],
  ["Win32", "native", 1.5, 1],
  ["MacIntel", "cef", 2, 1],
])("converts %s %s frame and mask coordinates at %s device pixels per CSS pixel", async (platform, renderer, devicePixelRatio, scale) => {
  const onLoad = vi.fn();
  electrobunNativeCompat.setup({ onLoad } as unknown as Parameters<
    BunPlugin["setup"]
  >[0]);
  const [options, load] = onLoad.mock.calls[1];
  const path =
    "/app/node_modules/electrobun/dist-win-x64/api/bun/preload/.generated/compiled.ts";
  expect(options.filter.test(path)).toBe(true);
  const script = `
const rect = { x: 200, y: 100, width: 400, height: 300 };
const masksJson = '[{"x":10,"y":20,"width":100,"height":80}]';
const initial = {
  frame: { width: rect.width, height: rect.height, x: rect.x, y: rect.y },
  navigationRules: null
};
const resized = function () {
  return { frame: rect, masks: masksJson };
}.call({ renderer });
observe(initial.frame, resized.frame, resized.masks);`;
  vi.stubGlobal("Bun", {
    file: () => ({
      text: async () => `export const preloadScript = ${JSON.stringify(script)};
export const preloadScriptSandboxed = "sandboxed";`,
    }),
  });
  const result = await load({ path });
  const observe = vi.fn();
  expect(result.contents).toContain(
    'export const preloadScriptSandboxed = "sandboxed";',
  );
  const code = result.contents.replaceAll("export const", "const");
  const preload = runInNewContext(`${code}\npreloadScript`);
  runInNewContext(preload, {
    navigator: { platform },
    window: { devicePixelRatio },
    renderer,
    observe,
  });
  const frame = {
    x: 200 * scale,
    y: 100 * scale,
    width: 400 * scale,
    height: 300 * scale,
  };
  expect(observe).toHaveBeenCalledWith(
    frame,
    frame,
    JSON.stringify([
      { x: 10 * scale, y: 20 * scale, width: 100 * scale, height: 80 * scale },
    ]),
  );
});
