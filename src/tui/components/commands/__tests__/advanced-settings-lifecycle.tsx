import { mock } from "bun:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act } from "react";
import type { Config } from "../../../../core/config/config";

const saved: Partial<Config>[] = [];
let closes = 0;
mock.module(join(import.meta.dirname, "../../../context/config.tsx"), () => ({
  useConfig: () => ({
    data: { strikeMode: false, findingPolicy: "native" },
    update: async (patch: Partial<Config>) => {
      saved.push(patch);
    },
  }),
}));

const { default: AdvancedSettings } = await import("../advanced-settings.tsx");
const { TerminalDimensionsProvider } = await import(
  "../../../context/dimensions"
);
const { registerBuiltinThemes, ThemeProvider } = await import("../../../theme");
registerBuiltinThemes();

const setup = await testRender(
  <ThemeProvider>
    <TerminalDimensionsProvider>
      <AdvancedSettings onClose={() => (closes += 1)} />
    </TerminalDimensionsProvider>
  </ThemeProvider>,
  { width: 80, height: 24, exitOnCtrlC: false },
);

const settle = async () => {
  for (let i = 0; i < 3; i++) await act(async () => {});
  await act(setup.renderOnce);
};
const frame = async () => {
  await settle();
  return setup.captureCharFrame();
};
const press = async (key: string) => {
  await act(async () => setup.mockInput.pressKey(key));
  await settle();
};

try {
  assert.ok((await frame()).includes("Apex judge"));
  assert.deepEqual(saved, []);

  await press("TAB");
  assert.ok((await frame()).includes("● Enabled"));

  await press("j");
  assert.ok((await frame()).includes("Off (report findings only)"));
  await press("ARROW_DOWN");
  await press("RETURN");
  assert.ok((await frame()).includes("Disabled ▾"));
  assert.deepEqual(saved, []);

  await press("RETURN");
  assert.deepEqual(saved, [{ strikeMode: true, findingPolicy: "external" }]);
  assert.equal(closes, 1);
} finally {
  await act(async () => setup.renderer.destroy());
}
