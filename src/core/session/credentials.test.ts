import {
  chmod,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { resolveEffectiveHeaders } from "../http/targetHeaders";
import { sessions } from "./index";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "apex-session-credentials-"));
  vi.stubEnv("PENSAR_DATA_DIR", root);
});
afterEach(async () => {
  vi.unstubAllEnvs();
  await rm(root, { recursive: true, force: true });
});

it("preserves both accounts and keeps secrets out of credential references after resume", async () => {
  const target = "https://app.example.test";
  const created = await sessions.create({
    name: "test",
    targets: [target],
    inheritEnvironmentConfig: false,
    config: {
      authCredentials: {
        username: "tester",
        password: "not-for-the-model",
        context: "Use the staging login form.",
      },
    },
  });
  const id = created.credentialManager?.listReferences()[0].id;
  expect(id).toBeDefined();
  const path = join(root, "sessions", created.id, "session.json");
  expect((await stat(path)).mode & 0o777).toBe(0o600);
  await chmod(path, 0o644);
  const key = "test-key-value";
  const saved = await sessions.addCredential(created.id, {
    apiKey: key,
    tokens: { customHeaders: { "X-API-Key": key } },
  });
  const keyId = saved.credentialManager?.listReferences()[1].id;
  await sessions.updateSessionHeaders(created.id, { "X-Test": "yes" });
  const resumed = await sessions.get(created.id);
  expect(resumed.credentialManager?.resolve(id ?? "")?.password).toBe(
    "not-for-the-model",
  );
  expect(resumed.credentialManager?.resolve(keyId ?? "")?.apiKey).toBe(key);
  expect(resumed.credentialManager?.formatForPrompt()).toContain(
    "Use the staging login form.",
  );
  expect(resumed.credentialManager?.formatForPrompt()).not.toMatch(
    /not-for-the-model|test-key-value/,
  );
  expect(resolveEffectiveHeaders(resumed, target)).toEqual({
    "X-Test": "yes",
    "X-API-Key": key,
  });
  expect(
    resolveEffectiveHeaders(resumed, "https://outside.example.test"),
  ).toEqual({});
  expect((await stat(path)).mode & 0o777).toBe(0o600);
});

it("keeps a legacy single account resolvable while two additions are saved", async () => {
  const session = await sessions.create({
    name: "legacy",
    targets: [],
    inheritEnvironmentConfig: false,
  });
  const path = join(root, "sessions", session.id, "session.json");
  const legacy = JSON.parse(await readFile(path, "utf8"));
  legacy.config.authCredentials = { username: "legacy", password: "old-value" };
  await writeFile(path, JSON.stringify(legacy));
  const originalId = (
    await sessions.get(session.id)
  ).credentialManager?.listReferences()[0].id;
  await Promise.all(
    ["second", "third"].map((role) =>
      sessions.addCredential(session.id, { role, context: "Use SSO." }),
    ),
  );
  const resumed = await sessions.get(session.id);
  expect(resumed.credentialManager?.resolve(originalId ?? "")?.username).toBe(
    "legacy",
  );
  expect(
    resumed.credentialManager?.listReferences().map((ref) => ref.role),
  ).toEqual(expect.arrayContaining(["second", "third"]));
  expect(resumed.credentialManager?.size).toBe(3);
});
