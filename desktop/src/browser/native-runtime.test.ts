import { expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ create: vi.fn(() => 42) }));
vi.mock("bun:ffi", () => ({
  JSCallback: class {
    ptr = 101;
  },
}));
vi.mock("../../node_modules/electrobun/dist/api/bun/proc/native", () => ({
  native: { symbols: { initWebview: mocks.create } },
}));

it("removes privileged native callbacks from untrusted views even if the native sandbox flag is lost", async () => {
  await import("./native-runtime");
  const { native } = await import(
    "../../node_modules/electrobun/dist/api/bun/proc/native"
  );
  const args = Array.from({ length: 20 }, (_, index) => index);
  args[19] = 1;
  expect(native?.symbols.initWebview(...args)).toBe(42);
  expect(mocks.create.mock.calls.at(-1)).toEqual(
    args.map((value, index) => (index === 13 || index === 14 ? 101 : value)),
  );
  args[19] = 0;
  native?.symbols.initWebview(...args);
  expect(mocks.create.mock.calls.at(-1)).toEqual(args);
});
