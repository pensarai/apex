import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CredentialStoreUnavailableError,
  createCredentialStore,
} from "./credential-store";

const temporaryDirectories: string[] = [];

async function temporaryHome(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "apex-credentials-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("credential store", () => {
  it("uses the native credential store when available", async () => {
    const homeDir = await temporaryHome();
    let password: string | undefined;
    const store = createCredentialStore({
      homeDir,
      nativeSecrets: {
        delete: async () => {
          password = undefined;
          return true;
        },
        get: async () => password ?? null,
        set: async ({ value }) => {
          password = value;
        },
      },
    });

    await expect(store.save("refresh-token")).resolves.toBe("os-vault");
    await expect(store.load()).resolves.toEqual({
      backend: "os-vault",
      refreshToken: "refresh-token",
    });

    await store.clear();
    await expect(store.load()).resolves.toBeNull();
  });

  it("falls back to a private file when the native store is unavailable", async () => {
    const homeDir = await temporaryHome();
    const unavailable = async () => {
      throw new Error("secret service unavailable");
    };
    const store = createCredentialStore({
      homeDir,
      nativeSecrets: {
        delete: unavailable,
        get: unavailable,
        set: unavailable,
      },
    });

    await expect(store.save("refresh-token")).resolves.toBe("secure-file");
    await expect(store.load()).resolves.toEqual({
      backend: "secure-file",
      refreshToken: "refresh-token",
    });

    const pensarDir = path.join(homeDir, ".pensar");
    const authFile = path.join(pensarDir, "auth.json");
    expect(JSON.parse(await readFile(authFile, "utf8"))).toEqual({
      refreshToken: "refresh-token",
    });
    if (process.platform !== "win32") {
      expect((await stat(pensarDir)).mode & 0o777).toBe(0o700);
      expect((await stat(authFile)).mode & 0o777).toBe(0o600);
    }
  });

  it("does not confuse a temporarily unavailable OS vault with logout", async () => {
    const homeDir = await temporaryHome();
    const store = createCredentialStore({
      homeDir,
      nativeSecrets: {
        delete: async () => false,
        get: async () => {
          throw new Error("credential vault locked");
        },
        set: async () => {},
      },
    });

    await expect(store.load()).rejects.toBeInstanceOf(
      CredentialStoreUnavailableError,
    );
  });

  it("removes the fallback after the native store becomes available", async () => {
    const homeDir = await temporaryHome();
    const fallbackStore = createCredentialStore({
      homeDir,
      nativeSecrets: {
        delete: async () => false,
        get: async () => {
          throw new Error("credential vault locked");
        },
        set: async () => {
          throw new Error("credential vault locked");
        },
      },
    });
    await fallbackStore.save("old-token");

    let password: string | undefined;
    const nativeStore = createCredentialStore({
      homeDir,
      nativeSecrets: {
        delete: async () => true,
        get: async () => password ?? null,
        set: async ({ value }) => {
          password = value;
        },
      },
    });

    await expect(nativeStore.save("new-token")).resolves.toBe("os-vault");
    await expect(nativeStore.load()).resolves.toEqual({
      backend: "os-vault",
      refreshToken: "new-token",
    });
    await expect(
      readFile(path.join(homeDir, ".pensar", "auth.json"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
