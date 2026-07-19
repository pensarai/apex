import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { createLogger } from "../logger/structured";
import { scopedLogger } from "../util/lazyLogger";

const SERVICE = "dev.pensar.apex";
const ACCOUNT = "workos-refresh-token";
const log = scopedLogger(() => createLogger("auth:credential-store"));

export type CredentialBackend = "os-vault" | "secure-file";

export interface StoredRefreshToken {
  backend: CredentialBackend;
  refreshToken: string;
}

export interface AuthCredentialStore {
  clear(): Promise<void>;
  load(): Promise<StoredRefreshToken | null>;
  save(refreshToken: string): Promise<CredentialBackend>;
}

export class CredentialStoreUnavailableError extends Error {
  constructor(options?: ErrorOptions) {
    super("The operating system credential store is unavailable", options);
    this.name = "CredentialStoreUnavailableError";
  }
}

interface NativeSecrets {
  delete(options: { name: string; service: string }): Promise<boolean>;
  get(options: { name: string; service: string }): Promise<string | null>;
  set(options: { name: string; service: string; value: string }): Promise<void>;
}

interface KeyringEntry {
  deleteCredential(): Promise<boolean>;
  getPassword(): Promise<string | undefined>;
  setPassword(password: string): Promise<void>;
}

interface KeyringModule {
  AsyncEntry: new (service: string, account: string) => KeyringEntry;
}

interface CredentialStoreOptions {
  homeDir?: string;
  nativeSecrets?: NativeSecrets;
}

let nodeSecrets: NativeSecrets | null = null;

function getNativeSecrets(options: CredentialStoreOptions): NativeSecrets {
  if (options.nativeSecrets) return options.nativeSecrets;
  if (typeof Bun !== "undefined" && Bun.secrets) return Bun.secrets;
  if (nodeSecrets) return nodeSecrets;

  const require = createRequire(import.meta.url);
  const { AsyncEntry } = require("@napi-rs/keyring") as KeyringModule;
  const entry = new AsyncEntry(SERVICE, ACCOUNT);
  nodeSecrets = {
    delete: () => entry.deleteCredential(),
    get: async () => (await entry.getPassword()) ?? null,
    set: ({ value }) => entry.setPassword(value),
  };
  return nodeSecrets;
}

function isMissingEntryError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /no entry|not found|no matching/i.test(message);
}

export function createCredentialStore(
  options: CredentialStoreOptions = {},
): AuthCredentialStore {
  const homeDir = options.homeDir ?? os.homedir();
  const pensarDir = path.join(homeDir, ".pensar");
  const fallbackPath = path.join(pensarDir, "auth.json");

  const ensurePrivateDirectory = async () => {
    await mkdir(pensarDir, { recursive: true, mode: 0o700 });
    await chmod(pensarDir, 0o700).catch(() => {});
  };

  const loadFallback = async (): Promise<string | null> => {
    try {
      const raw = JSON.parse(await readFile(fallbackPath, "utf8")) as {
        refreshToken?: unknown;
      };
      await chmod(fallbackPath, 0o600).catch(() => {});
      return typeof raw.refreshToken === "string" && raw.refreshToken
        ? raw.refreshToken
        : null;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return null;
      log.warn("Unable to read secure auth fallback", { error: String(error) });
      return null;
    }
  };

  const saveFallback = async (refreshToken: string) => {
    await ensurePrivateDirectory();
    const temporaryPath = `${fallbackPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      await writeFile(temporaryPath, JSON.stringify({ refreshToken }), {
        encoding: "utf8",
        mode: 0o600,
      });
      await chmod(temporaryPath, 0o600).catch(() => {});
      await rename(temporaryPath, fallbackPath);
      await chmod(fallbackPath, 0o600).catch(() => {});
    } finally {
      await rm(temporaryPath, { force: true }).catch(() => {});
    }
  };

  const clearFallback = async () => {
    await rm(fallbackPath, { force: true }).catch(() => {});
  };

  return {
    async load() {
      let nativeStoreError: unknown;
      try {
        const refreshToken = await getNativeSecrets(options).get({
          service: SERVICE,
          name: ACCOUNT,
        });
        if (refreshToken) return { backend: "os-vault", refreshToken };
      } catch (error) {
        if (!isMissingEntryError(error)) {
          nativeStoreError = error;
          log.warn(
            "Native credential store unavailable; checking secure file fallback",
            { error: String(error) },
          );
        }
      }

      const refreshToken = await loadFallback();
      if (refreshToken) return { backend: "secure-file", refreshToken };
      if (nativeStoreError) {
        throw new CredentialStoreUnavailableError({
          cause: nativeStoreError,
        });
      }
      return null;
    },

    async save(refreshToken) {
      if (!refreshToken) throw new Error("Cannot store an empty refresh token");

      try {
        await getNativeSecrets(options).set({
          service: SERVICE,
          name: ACCOUNT,
          value: refreshToken,
        });
        await clearFallback();
        return "os-vault";
      } catch (error) {
        log.warn("Native credential store unavailable; using secure file", {
          error: String(error),
        });
        try {
          await getNativeSecrets(options).delete({
            service: SERVICE,
            name: ACCOUNT,
          });
        } catch {
          // Ignore errors clearing vault - already in fallback mode
        }
        await saveFallback(refreshToken);
        return "secure-file";
      }
    },

    async clear() {
      try {
        await getNativeSecrets(options).delete({
          service: SERVICE,
          name: ACCOUNT,
        });
      } catch (error) {
        if (!isMissingEntryError(error)) {
          log.warn("Unable to clear native auth credential", {
            error: String(error),
          });
        }
      }
      await clearFallback();
    },
  };
}

export const authCredentialStore = createCredentialStore();
