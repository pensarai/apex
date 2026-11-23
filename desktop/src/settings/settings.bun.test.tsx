import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { config } from "../../../src/core/config";
import { createSettingsHost, settingsSnapshot } from "./host";

let directory: string;
let home: ReturnType<typeof spyOn>;
let fetchSpy: ReturnType<typeof spyOn>;
const host = createSettingsHost({ requireAcceptance() {}, openExternal() {} });
beforeEach(async () => {
  directory = await mkdtemp(join(os.tmpdir(), "apex-desktop-settings-"));
  home = spyOn(os, "homedir").mockReturnValue(directory);
  fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(null, { status: 503 }),
  );
  await config.init();
});
afterEach(async () => {
  home.mockRestore();
  fetchSpy.mockRestore();
  host.dispose();
  await rm(directory, { recursive: true, force: true });
});
test("saved credentials and sensitive header values stay in the host", () => {
  const data = settingsSnapshot({
    responsibleUseAccepted: true,
    anthropicAPIKey: "fake-api-key-secret",
    refreshToken: "fake-refresh-token",
    accessToken: "fake-access-token",
    daytonaAPIKey: "fake-daytona-key",
    defaultHeaders: { Authorization: "Bearer fake-password-value" },
  });
  const payload = JSON.stringify(data);
  for (const secret of [
    "fake-api-key-secret",
    "fake-refresh-token",
    "fake-access-token",
    "fake-daytona-key",
    "fake-password-value",
  ])
    expect(payload).not.toContain(secret);
  expect(data.services.daytonaAPIKey).toBe(true);
});
test("OpenAI key replacement overrides the environment and removal reveals its source", async () => {
  const previous = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = "fixture-environment-key";
  fetchSpy.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === "https://api.openai.com/v1/models") {
      expect(new Headers(init?.headers).get("Authorization")).toBe(
        "Bearer fixture-replacement-key",
      );
      return Response.json({ data: [] });
    }
    return new Response(null, { status: 503 });
  });
  const openai = (data: ReturnType<typeof settingsSnapshot>) =>
    data.providers.find((provider) => provider.id === "openai");
  try {
    expect(openai(await host.requests.desktopSettings())).toMatchObject({
      configured: true,
      keySource: "environment",
      environmentVariable: "OPENAI_API_KEY",
    });
    await config.update({ openAiAPIKey: "fixture-original-key" });
    const saved = await host.requests.changeSettings({
      kind: "provider",
      id: "openai",
      key: "  fixture-replacement-key  ",
    });
    expect(openai(saved)?.keySource).toBe("saved");
    expect((await config.getStored()).openAiAPIKey).toBe(
      "fixture-replacement-key",
    );
    expect((await config.get()).openAiAPIKey).toBe("fixture-replacement-key");
    expect(openai(await host.requests.desktopSettings())?.keySource).toBe(
      "saved",
    );
    const removed = await host.requests.changeSettings({
      kind: "provider",
      id: "openai",
      key: null,
    });
    expect((await config.getStored()).openAiAPIKey).toBeNull();
    expect((await config.get()).openAiAPIKey).toBe("fixture-environment-key");
    expect(openai(removed)).toMatchObject({
      configured: true,
      keySource: "environment",
    });
    for (const snapshot of [saved, removed]) {
      expect(JSON.stringify(snapshot)).not.toContain("fixture-replacement-key");
      expect(JSON.stringify(snapshot)).not.toContain("fixture-environment-key");
    }
    delete process.env.OPENAI_API_KEY;
    const disconnected = openai(await host.requests.desktopSettings());
    expect(disconnected?.configured).toBe(false);
    expect(disconnected?.keySource).toBeUndefined();
  } finally {
    if (previous === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = previous;
  }
});
test("a rejected OpenAI replacement preserves the saved key and reports the failure", async () => {
  await config.update({ openAiAPIKey: "fixture-original-key" });
  fetchSpy.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === "https://api.openai.com/v1/models") {
      expect(new Headers(init?.headers).get("Authorization")).toBe(
        "Bearer fixture-rejected-key",
      );
      return Response.json(
        { error: { message: "Missing scopes: api.model.read" } },
        { status: 401 },
      );
    }
    return new Response(null, { status: 503 });
  });
  await expect(
    host.requests.changeSettings({
      kind: "provider",
      id: "openai",
      key: "fixture-rejected-key",
    }),
  ).rejects.toThrow(
    "New key was not saved: OpenAI key verification (GET /v1/models) returned HTTP 401: Missing scopes: api.model.read. Existing credentials are unchanged.",
  );
  expect((await config.getStored()).openAiAPIKey).toBe("fixture-original-key");
  const next = await host.requests.desktopSettings();
  expect(
    next.providers.find((provider) => provider.id === "openai")?.keySource,
  ).toBe("saved");
  expect(JSON.stringify(next)).not.toContain("fixture-original-key");
});
test("serialized edits preserve unrelated settings and case-insensitive header names", async () => {
  const [first, , last] = await Promise.all([
    host.requests.changeSettings({
      kind: "header",
      name: "X-Target",
      value: "one",
    }),
    host.requests.changeSettings({
      kind: "advanced",
      value: {
        mode: "lance",
        findingPolicy: "external",
        budget: { kind: "time", limit: 5000 },
        surface: false,
      },
    }),
    host.requests.changeSettings({
      kind: "header",
      name: "x-target",
      value: "two",
    }),
  ]);
  expect(first.headers).toContainEqual({ name: "X-Target", display: "one" });
  expect(last.headers).toContainEqual({ name: "x-target", display: "two" });
  const stored = JSON.parse(
    await readFile(join(directory, ".pensar", "config.json"), "utf8"),
  );
  expect(stored.defaultHeaders["X-Target"]).toBeUndefined();
  expect(stored.defaultHeaders["x-target"]).toBe("two");
  expect(stored.lanceMode).toBe(true);
  expect(stored.lanceBudget).toEqual({ kind: "time", limit: 5000 });
  await expect(
    host.requests.changeSettings({
      kind: "advanced",
      value: {
        mode: "lance",
        findingPolicy: "external",
        budget: { kind: "time", limit: 1 },
        surface: false,
      },
    }),
  ).rejects.toThrow();
});
test("model selections persist recent history and supported effort", async () => {
  await config.update({ openAiAPIKey: "fixture" });
  const first = await host.requests.desktopSettings();
  const model = first.models.find(
    (m) => m.provider === "openai" && m.choices.includes("high"),
  );
  if (!model) throw new Error("Missing OpenAI model with effort control");
  const next = await host.requests.changeSettings({
    kind: "model",
    id: model.id,
    reasoning: "high",
  });
  expect(next.selected).toBe(model.id);
  expect(next.recent[0]).toBe(model.id);
  expect(next.models.find((m) => m.id === model.id)?.reasoning).toBe("high");
});
test("editing a custom model keeps hidden headers host-side and excludes environment providers from disk", async () => {
  const previous = process.env.APEX_CUSTOM_PROVIDERS;
  const base = {
    baseUrl: "https://inference.example/v1",
    models: [{ id: "demo", contextLength: 8000, maxOutputTokens: 2000 }],
  };
  process.env.APEX_CUSTOM_PROVIDERS = JSON.stringify({ envOnly: base });
  try {
    const current = await host.requests.changeSettings({
      kind: "custom",
      id: "private",
      definition: JSON.stringify({
        ...base,
        headers: { "X-Private": "secret-placeholder" },
      }),
    });
    expect(JSON.stringify(current)).not.toContain("secret-placeholder");
    await host.requests.changeSettings({
      kind: "custom",
      id: "private",
      definition: JSON.stringify({ ...base, name: "Edited" }),
    });
    const saved = JSON.parse(
      await readFile(join(directory, ".pensar", "config.json"), "utf8"),
    );
    expect(saved.customProviders.private.headers).toEqual({
      "X-Private": "secret-placeholder",
    });
    expect(saved.customProviders.envOnly).toBeUndefined();
    await host.requests.changeSettings({
      kind: "custom",
      id: "private",
      definition: JSON.stringify({
        ...base,
        baseUrl: "https://new.example/v1",
      }),
    });
    expect(
      (await config.get()).customProviders?.private?.headers,
    ).toBeUndefined();
    await expect(
      host.requests.changeSettings({
        kind: "custom",
        id: "envOnly",
        definition: null,
      }),
    ).rejects.toThrow("managed");
    await host.requests.changeSettings({
      kind: "custom",
      id: "private",
      definition: null,
    });
    expect((await config.get()).customProviders?.private).toBeUndefined();
  } finally {
    if (previous === undefined) delete process.env.APEX_CUSTOM_PROVIDERS;
    else process.env.APEX_CUSTOM_PROVIDERS = previous;
  }
});

test("device authorization selects its workspace and keeps tokens outside the renderer", async () => {
  const opened: string[] = [];
  const session = createSettingsHost({
    requireAcceptance() {},
    openExternal: (url) => opened.push(url),
  });
  const w = {
    id: "ws_a",
    name: "QA",
    slug: "qa",
    hasPaymentMethod: true,
    balance: 4,
  };
  const responses = [
    { workosClientId: "test" },
    {
      device_code: "private-device-value",
      user_code: "QA-TEST",
      verification_uri_complete: "https://auth.example/device",
      interval: 0,
      expires_in: 30,
    },
    {
      access_token: "private-token-value",
      refresh_token: "private-refresh-value",
    },
    { workspaces: [w] },
    {
      confirmed: true,
      workspace: w,
      billing: { hasPaymentMethod: true, balance: 4, ready: true },
      signingKey: "private-signing-value",
    },
  ];
  for (const value of responses)
    fetchSpy.mockResolvedValueOnce(Response.json(value));
  try {
    await session.requests.accountAction({ action: "login" });
    let state = await session.requests.accountStatus();
    for (
      let i = 0;
      i < 80 && state.stage !== "connected" && state.stage !== "error";
      i++
    ) {
      expect(JSON.stringify(state)).not.toContain("private-");
      await Bun.sleep(3);
      state = await session.requests.accountStatus();
    }
    expect(opened).toEqual(["https://auth.example/device"]);
    expect(state).toEqual({
      stage: "connected",
      workspace: "QA",
      balance: 4,
      billingReady: true,
      canSwitch: true,
    });
    const stored = JSON.parse(
      await readFile(join(directory, ".pensar", "config.json"), "utf8"),
    );
    expect(stored.workspaceId).toBe("ws_a");
    expect(stored.gatewaySigningKey).toBe("private-signing-value");
    await session.requests.accountAction({ action: "disconnect" });
    expect((await config.get()).accessToken).toBeNull();
  } finally {
    session.dispose();
  }
});
test("cancelling a pending device flow ignores a late response", async () => {
  const opened: string[] = [];
  const session = createSettingsHost({
    requireAcceptance() {},
    openExternal: (url) => opened.push(url),
  });
  const delayed = Promise.withResolvers<Response>();
  fetchSpy
    .mockResolvedValueOnce(Response.json({ workosClientId: "test" }))
    .mockReturnValueOnce(delayed.promise);
  try {
    await session.requests.accountAction({ action: "login" });
    await session.requests.accountAction({ action: "cancel" });
    delayed.resolve(
      Response.json({
        device_code: "private",
        user_code: "QA",
        verification_uri_complete: "https://auth.example",
        expires_in: 30,
        interval: 0,
      }),
    );
    await Bun.sleep(5);
    expect(await session.requests.accountStatus()).toEqual({ stage: "idle" });
    expect(opened).toEqual([]);
    const stored = JSON.parse(
      await readFile(join(directory, ".pensar", "config.json"), "utf8"),
    );
    expect(stored.accessToken).toBeUndefined();
  } finally {
    session.dispose();
  }
});
