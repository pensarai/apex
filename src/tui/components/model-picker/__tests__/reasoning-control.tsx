import { mock } from "bun:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act, useState } from "react";
import { getModelInfo, type ReasoningSetting } from "../../../../core/ai";
import type { Config } from "../../../../core/config/config";

const scenario = process.argv[2];
const selected = getModelInfo(
  scenario === "toggle"
    ? "claude-sonnet-4-5"
    : scenario === "unknown"
      ? "gpt-4o"
      : scenario === "inference"
        ? "inference:deepseek-v4.1-flash-1017-cyber"
        : "claude-opus-5-5",
);
const config: Config =
  scenario === "inference"
    ? {
        inferenceAPIKey: "test",
        responsibleUseAccepted: true,
      }
    : {
        anthropicAPIKey: "test",
        openAiAPIKey: "test",
        responsibleUseAccepted: true,
      };
if (scenario !== "inference")
  mock.module(
    join(import.meta.dirname, "../../../../core/providers/utils.ts"),
    () => ({ getAvailableModels: () => [selected] }),
  );
mock.module(join(import.meta.dirname, "../../../context/config.tsx"), () => ({
  useConfig: () => ({ data: config, update: async () => {} }),
}));
const { ModelPicker } = await import("../ModelPicker");
const { ThemeProvider, registerBuiltinThemes } = await import("../../../theme");
registerBuiltinThemes();
const changed: ReasoningSetting[] = [];
const selections: string[] = [];
function Harness() {
  const [reasoning, setReasoning] = useState<ReasoningSetting>("default");
  return (
    <ThemeProvider>
      <ModelPicker
        config={config}
        selectedModel={
          scenario === "inference" ? getModelInfo("gpt-4o") : selected
        }
        onSelectModel={(model) => selections.push(model.id)}
        reasoning={reasoning}
        onReasoningChange={(next) => {
          changed.push(next);
          setReasoning(next);
        }}
      />
    </ThemeProvider>
  );
}
const setup = await testRender(<Harness />, {
  width: scenario === "compact" ? 60 : 100,
  height: scenario === "compact" ? 18 : 28,
  exitOnCtrlC: false,
});
async function frame() {
  for (let i = 0; i < 3; i++) await act(async () => {});
  await act(setup.renderOnce);
  return setup.captureCharFrame();
}
try {
  const initial = await frame();
  assert.ok(
    initial.includes(
      scenario === "inference" ? "Inference.net" : selected.name,
    ),
    initial,
  );
  if (scenario === "unknown" || scenario === "inference") {
    assert.ok(!initial.includes("Effort:"), initial);
    assert.ok(!initial.includes("Extended Thinking:"), initial);
    await act(async () => setup.mockInput.pressKey("ARROW_LEFT"));
    await frame();
    await act(async () => setup.mockInput.pressKey("ARROW_RIGHT"));
    await frame();
    assert.deepEqual(changed, []);
    if (scenario === "inference") {
      assert.ok(initial.includes("Inference.net"), initial);
      await act(async () => setup.mockInput.typeText("inference.net cyber"));
      const search = await frame();
      assert.ok(search.includes("Results (1)"), search);
      assert.ok(search.includes(selected.name), search);
      await act(async () => setup.mockInput.pressKey("RETURN"));
      await frame();
      assert.deepEqual(selections, [selected.id]);
    }
  } else {
    assert.ok(
      initial.includes(
        scenario === "toggle"
          ? "Extended Thinking: default"
          : "Effort: default",
      ),
      initial,
    );
    assert.ok(
      !initial.includes(
        scenario === "toggle" ? "Effort:" : "Extended Thinking:",
      ),
      initial,
    );
    const firstChoice = scenario === "toggle" ? "enabled" : "low";
    const lastChoice = scenario === "toggle" ? "disabled" : "max";
    await act(async () => setup.mockInput.pressKey("ARROW_RIGHT"));
    const next = await frame();
    assert.deepEqual(changed, [firstChoice]);
    assert.ok(
      next.includes(
        scenario === "toggle" ? "Extended Thinking: enabled" : "Effort: low",
      ),
      next,
    );
    await act(async () => setup.mockInput.pressKey("ARROW_LEFT"));
    await frame();
    await act(async () => setup.mockInput.pressKey("ARROW_LEFT"));
    await frame();
    await act(async () => setup.mockInput.pressKey("ARROW_RIGHT"));
    await frame();
    assert.deepEqual(changed, [firstChoice, "default", lastChoice, "default"]);

    await act(async () => setup.mockInput.pressKey("ARROW_UP"));
    await frame();
    await act(async () => setup.mockInput.pressKey("RETURN"));
    const collapsed = await frame();
    assert.ok(!collapsed.includes(selected.name), collapsed);
    await act(async () => setup.mockInput.pressKey("RETURN"));
    const expanded = await frame();
    assert.ok(expanded.includes(selected.name), expanded);

    await act(async () => setup.mockInput.typeText("claude "));
    const search = await frame();
    assert.ok(search.includes("Search claude"), search);
    assert.ok(search.includes("Results (1)"), search);
    await act(async () => setup.mockInput.pressKey("ARROW_LEFT"));
    await frame();
    await act(async () => setup.mockInput.typeText("s"));
    const afterArrows = await frame();
    assert.ok(afterArrows.includes("Search claude s"), afterArrows);
    await act(async () => setup.mockInput.pressKey("ARROW_RIGHT"));
    await frame();
    assert.deepEqual(changed, [
      firstChoice,
      "default",
      lastChoice,
      "default",
      lastChoice,
      "default",
    ]);

    await act(async () => setup.mockInput.pressKey("ARROW_UP"));
    const focused = await frame();
    assert.ok(
      focused.includes(
        scenario === "toggle" ? "❯ Extended Thinking:" : "❯ Effort:",
      ),
      focused,
    );
    await act(async () => setup.mockInput.pressKey(" "));
    const updated = await frame();
    assert.equal(changed.at(-1), firstChoice);
    assert.ok(
      updated.includes(
        scenario === "toggle" ? "Extended Thinking: enabled" : "Effort: low",
      ),
      updated,
    );
  }
  if (process.env.APEX_TEST_FRAME_DIR) {
    mkdirSync(process.env.APEX_TEST_FRAME_DIR, { recursive: true });
    writeFileSync(
      join(process.env.APEX_TEST_FRAME_DIR, `${scenario}.txt`),
      await frame(),
    );
  }
} finally {
  await act(async () => setup.renderer.destroy());
}
