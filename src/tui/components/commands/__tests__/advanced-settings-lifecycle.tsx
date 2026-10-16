import { mock } from "bun:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act } from "react";
import type { Config } from "../../../../core/config/config";

const scenario = process.argv[2];
assert.ok(scenario === "native" || scenario === "external");

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

  await press("j");
  assert.ok(!(await frame()).includes("Apex judge (default)"));

  await press("TAB");
  assert.ok((await frame()).includes("● Enabled"));

  await press("j");
  const findingSelectFrame = await frame();
  assert.ok(
    findingSelectFrame.includes("Off (report findings only)"),
    findingSelectFrame,
  );
  await press("ARROW_DOWN");
  await press("RETURN");
  assert.ok((await frame()).includes("Disabled ▾"));
  assert.deepEqual(saved, []);

  if (scenario === "native") {
    await press("TAB");
    const strikeOffFrame = await frame();
    assert.ok(strikeOffFrame.includes("○ Disabled"));
    assert.ok(strikeOffFrame.includes("Apex judge"));
    assert.ok(!strikeOffFrame.includes("Disabled ▾"));
    await press("j");
    assert.ok(!(await frame()).includes("Apex judge (default)"));
  }

  await press("RETURN");
  assert.deepEqual(saved, [
    scenario === "native"
      ? { strikeMode: false, findingPolicy: "native" }
      : { strikeMode: true, findingPolicy: "external" },
  ]);
  assert.equal(closes, 1);
} finally {
  await act(async () => setup.renderer.destroy());
}
