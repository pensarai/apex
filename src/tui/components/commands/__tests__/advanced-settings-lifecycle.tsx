import { mock } from "bun:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act } from "react";
import type { Config } from "../../../../core/config/config";

const scenario = process.argv[2];
assert.ok(
  scenario === "native" || scenario === "external" || scenario === "compact",
);
const compact = scenario === "compact";

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
  {
    width: compact ? 60 : 80,
    height: compact ? 18 : 24,
    exitOnCtrlC: false,
  },
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
  const initialFrame = await frame();
  assert.ok(initialFrame.includes("Strike Mode"), initialFrame);
  assert.ok(initialFrame.includes("❯ Strike Mode"), initialFrame);
  assert.ok(initialFrame.includes("Save settings"), initialFrame);
  assert.ok(!initialFrame.includes("Finding judge"), initialFrame);
  assert.ok(!initialFrame.includes("Judge off"), initialFrame);
  assert.deepEqual(saved, []);

  await press("TAB");
  const strikeOnFrame = await frame();
  assert.ok(strikeOnFrame.includes("● Enabled"), strikeOnFrame);
  assert.ok(strikeOnFrame.includes("❯ Strike Mode"), strikeOnFrame);
  assert.ok(strikeOnFrame.includes("Finding judge"), strikeOnFrame);
  assert.ok(strikeOnFrame.includes("Apex judge"), strikeOnFrame);
  assert.ok(!strikeOnFrame.includes("[J]"), strikeOnFrame);
  if (compact) {
    assert.ok(strikeOnFrame.includes("Save settings"), strikeOnFrame);
  }

  await press("j");
  assert.ok(!(await frame()).includes("Off (report findings only)"));

  await press("ARROW_DOWN");
  const judgeFocusedFrame = await frame();
  assert.ok(judgeFocusedFrame.includes("❯ Finding judge"), judgeFocusedFrame);
  await press("RETURN");
  const findingSelectFrame = await frame();
  if (compact) {
    assert.ok(
      findingSelectFrame.includes("Apex judge (default)"),
      findingSelectFrame,
    );
    assert.ok(findingSelectFrame.includes("Save settings"), findingSelectFrame);
  }
  assert.ok(
    findingSelectFrame.includes("Off (report findings only)"),
    findingSelectFrame,
  );
  await press("ARROW_DOWN");
  const offFocusedFrame = await frame();
  assert.ok(
    offFocusedFrame.includes("❯ Off (report findings only)"),
    offFocusedFrame,
  );
  await press("RETURN");
  assert.ok((await frame()).includes("Disabled ▾"));
  assert.deepEqual(saved, []);

  if (scenario === "native") {
    await press("TAB");
    const strikeOffFrame = await frame();
    assert.ok(strikeOffFrame.includes("○ Disabled"));
    assert.ok(!strikeOffFrame.includes("Finding judge"), strikeOffFrame);
    assert.ok(!strikeOffFrame.includes("Judge off"), strikeOffFrame);
    assert.ok(!strikeOffFrame.includes("Disabled ▾"));
    assert.ok(strikeOffFrame.includes("❯ Strike Mode"), strikeOffFrame);
  }

  await press("ARROW_DOWN");
  const saveFocusedFrame = await frame();
  assert.ok(saveFocusedFrame.includes("❯ Save settings"), saveFocusedFrame);
  await press("ARROW_UP");
  const previousFocusedFrame = await frame();
  assert.ok(
    previousFocusedFrame.includes(
      scenario === "native" ? "❯ Strike Mode" : "❯ Finding judge",
    ),
    previousFocusedFrame,
  );
  await press("ARROW_DOWN");
  assert.ok((await frame()).includes("❯ Save settings"));
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
