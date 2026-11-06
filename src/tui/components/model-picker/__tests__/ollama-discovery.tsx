import { mock } from "bun:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act } from "react";
import type { Config } from "../../../../core/config/config";

const updates: Partial<Config>[] = [];
mock.module(
  join(import.meta.dirname, "../../../../core/config/index.ts"),
  () => ({
    config: {
      update: async (value: Partial<Config>) => {
        updates.push(value);
      },
    },
  }),
);

const { ConfigProvider, useConfig } = await import("../../../context/config");
const { AgentProvider, useAgent } = await import("../../../context/agent");
const { ModelPicker } = await import("../ModelPicker");
const { ThemeProvider, registerBuiltinThemes } = await import("../../../theme");
registerBuiltinThemes();

let online = false;
let currentConfig: Config | undefined;
let selectedId = "";
const upstreamId = "hf.co/webAI-Official/TwIL-8B:TwIL-8B-Q4_K_M-balanced.gguf";
const server = createServer((_req, res) => {
  res.setHeader("content-type", "application/json");
  res.end(
    JSON.stringify({
      models: online ? [{ name: upstreamId, context_length: 32_768 }] : [],
    }),
  );
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
process.env.OLLAMA_HOST = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

function Picker() {
  const config = useConfig();
  const { model, setModel } = useAgent();
  currentConfig = config.data;
  selectedId = model.id;
  return (
    <ModelPicker
      config={config.data}
      selectedModel={model}
      onSelectModel={setModel}
    />
  );
}

const setup = await testRender(
  <ConfigProvider
    config={{ responsibleUseAccepted: true, inceptionAPIKey: "fake-key" }}
  >
    <AgentProvider>
      <ThemeProvider>
        <Picker />
      </ThemeProvider>
    </AgentProvider>
  </ConfigProvider>,
  { width: 100, height: 28, exitOnCtrlC: false },
);

async function frame() {
  for (let i = 0; i < 3; i++) await act(async () => {});
  await act(setup.renderOnce);
  return setup.captureCharFrame();
}

async function waitFor(predicate: () => boolean) {
  const deadline = Date.now() + 7_000;
  while (!predicate() && Date.now() < deadline) {
    await act(async () => {
      await Bun.sleep(50);
    });
    await frame();
  }
  assert.ok(predicate(), await frame());
}

try {
  assert.ok(!(await frame()).includes("Ollama (local)"));
  await waitFor(() => currentConfig?.ollama?.models.length === 0);
  online = true;
  await waitFor(() => !!currentConfig?.ollama?.models.length);
  const discoveredFrame = await frame();
  assert.ok(discoveredFrame.includes("Ollama (local)"), discoveredFrame);
  await act(async () => setup.mockInput.typeText("TwIL"));
  assert.ok((await frame()).includes("TwIL-8B"));
  await act(async () => setup.mockInput.pressKey("RETURN"));
  await frame();
  assert.equal(selectedId, `ollama:${upstreamId}`);
  assert.equal(updates.at(-1)?.selectedModelId, selectedId);
  assert.deepEqual(updates.at(-1)?.recentModelIds, [selectedId]);
  assert.equal(updates.at(-1)?.ollama, undefined);
  online = false;
  await waitFor(() => currentConfig?.ollama?.models.length === 0);
  assert.equal(selectedId, `ollama:${upstreamId}`);
  assert.ok(!(await frame()).includes("TwIL-8B"));
} finally {
  await act(async () => setup.renderer.destroy());
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
    server.closeAllConnections();
  });
}
