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
