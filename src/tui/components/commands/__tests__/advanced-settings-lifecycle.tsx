import { mock } from "bun:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act } from "react";
import type { Config } from "../../../../core/config/config";

const scenario = process.argv[2];
assert.ok(
  scenario === "native" ||
    scenario === "external" ||
    scenario === "compact" ||
    scenario === "lance" ||
    scenario === "lance-compact" ||
    scenario === "resume-lance",
);
const compact = scenario === "compact" || scenario === "lance-compact";

const saved: Partial<Config>[] = [];
let closes = 0;
mock.module(join(import.meta.dirname, "../../../context/config.tsx"), () => ({
  useConfig: () => ({
    data: {
      strikeMode: false,
      lanceMode: scenario === "resume-lance",
      findingPolicy: scenario === "resume-lance" ? "external" : "native",
    },
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
  assert.ok(initialFrame.includes("❯ Mode"), initialFrame);
  assert.ok(!initialFrame.includes("Strike Mode"), initialFrame);
  assert.ok(!initialFrame.includes("Lance Mode"), initialFrame);
  assert.ok(initialFrame.includes("Save settings"), initialFrame);
  assert.deepEqual(saved, []);
  const lance =
    scenario === "lance" ||
    scenario === "lance-compact" ||
    scenario === "resume-lance";
  let policy: "native" | "external" =
    scenario === "resume-lance" ? "external" : "native";

  if (scenario !== "resume-lance") {
    await press("TAB");
    assert.ok((await frame()).includes("Strike ▾"));
    if (lance) {
      await press("RETURN");
      const choices = await frame();
      assert.ok(choices.includes("Standard"), choices);
      assert.ok(choices.includes("Lance"), choices);
      assert.ok(choices.includes("Save settings"), choices);
      await press("ARROW_DOWN");
      await press("RETURN");
    }
  }
  const selectedFrame = await frame();
  assert.ok(
    selectedFrame.includes(lance ? "Lance ▾" : "Strike ▾"),
    selectedFrame,
  );
  assert.ok(selectedFrame.includes("Finding judge"), selectedFrame);
  assert.ok(
    selectedFrame.includes(
      lance ? "minimal offensive-capability" : "Focused research",
    ),
    selectedFrame,
  );
  assert.ok(selectedFrame.includes("Save settings"), selectedFrame);

  await press("ARROW_DOWN");
  assert.ok((await frame()).includes("❯ Finding judge"));
  await press("TAB");
  policy = policy === "native" ? "external" : "native";
  assert.ok(
    (await frame()).includes(
      policy === "native" ? "Apex judge ▾" : "Disabled ▾",
    ),
  );
  await press("RETURN");
  const judgeChoices = await frame();
  assert.ok(judgeChoices.includes("Enabled (Apex judge)"), judgeChoices);
  assert.ok(judgeChoices.includes("Save settings"), judgeChoices);
  await press("ARROW_DOWN");
  await press("RETURN");
  policy = policy === "native" ? "external" : "native";

  // Switching modes must not reset an independently selected judge policy.
  await press("ARROW_UP");
  await press("TAB");
  await press("TAB");
  await press("TAB");
  const restoredFrame = await frame();
  assert.ok(
    restoredFrame.includes(lance ? "Lance ▾" : "Strike ▾"),
    restoredFrame,
  );
  assert.ok(
    restoredFrame.includes(policy === "native" ? "Apex judge ▾" : "Disabled ▾"),
    restoredFrame,
  );

  if (
    scenario === "external" ||
    scenario === "compact" ||
    scenario === "lance-compact"
  ) {
    await press("ARROW_DOWN");
    await press("TAB");
    policy = "external";
  } else {
    await press("ARROW_DOWN");
  }
  await press("ARROW_DOWN");
  assert.ok((await frame()).includes("❯ Save settings"));
  const beforeSave = await frame();
  await press("TAB");
  assert.equal(await frame(), beforeSave);
  assert.deepEqual(saved, []);
  await press("RETURN");
  assert.deepEqual(saved, [
    { strikeMode: !lance, lanceMode: lance, findingPolicy: policy },
  ]);
  assert.equal(closes, 1);
} finally {
  await act(async () => setup.renderer.destroy());
}
