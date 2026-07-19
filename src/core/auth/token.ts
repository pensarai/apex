// Importing through the api barrel would cycle. Use the leaf constants
// module directly.
import { getPensarApiUrl } from "../api/constants";
import { config } from "../config";
import { createLogger } from "../logger/structured";
import { scopedLogger } from "../util/lazyLogger";
import {
  type AuthCredentialStore,
  authCredentialStore,
  type CredentialBackend,
  CredentialStoreUnavailableError,
  type StoredRefreshToken,
} from "./credential-store";
import { withAuthRefreshLock } from "./refresh-lock";
import type { ValidToken } from "./types";

const log = scopedLogger(() => createLogger("auth:token"));

export interface WorkOSSessionTokens {
  accessToken: string;
  refreshToken: string;
}

export interface TokenConfig {
  accessToken?: string | null;
  credentialBackend?: CredentialBackend | null;
  pensarAPIKey?: string | null;
  refreshToken?: string | null;
  workosSession?: boolean;
}

export interface EnsureValidTokenOptions {
  forceRefresh?: boolean;
  rejectedToken?: string;
}

interface TokenManagerOptions {
  fetch?: typeof fetch;
  getClientId?: () => Promise<string | null>;
  store?: AuthCredentialStore;
  updateConfig?: (next: Partial<TokenConfig>) => Promise<void>;
  withRefreshLock?: <T>(action: () => Promise<T>) => Promise<T>;
}

export class AuthSessionExpiredError extends Error {
  constructor(
    message = "Your Pensar Console session expired. Run /login to reconnect.",
  ) {
    super(message);
    this.name = "AuthSessionExpiredError";
  }
}

export class AuthRefreshError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuthRefreshError";
  }
}

/** Decode a JWT payload for local expiry scheduling only. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], "base64url").toString("utf-8");
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

/** Return true when an access token is expired or within the refresh buffer. */
export function isTokenExpired(
  token: string,
  bufferSeconds: number = 60,
): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== "number") return true;

  const nowSeconds = Math.floor(Date.now() / 1000);
  return payload.exp - nowSeconds < bufferSeconds;
}

let cachedClientId: string | null = null;

async function fetchWorkOSClientId(): Promise<string | null> {
  if (cachedClientId) return cachedClientId;

  try {
    const response = await fetch(`${getPensarApiUrl()}/api/cli/config`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return null;
    const data = (await response.json()) as { workosClientId: string };
    cachedClientId = data.workosClientId;
    return cachedClientId;
  } catch {
    return null;
  }
}

export class WorkOSTokenManager {
  private accessToken: string | null = null;
  private migrationPromise: Promise<void> | null = null;
  private refreshPromise: Promise<ValidToken> | null = null;
  private readonly fetchImpl: typeof fetch;
  private readonly getClientId: () => Promise<string | null>;
  private readonly store: AuthCredentialStore;
  private readonly updateConfig: (next: Partial<TokenConfig>) => Promise<void>;
  private readonly withRefreshLock: <T>(action: () => Promise<T>) => Promise<T>;

  constructor(options: TokenManagerOptions = {}) {
    this.fetchImpl = options.fetch ?? fetch;
    this.getClientId = options.getClientId ?? fetchWorkOSClientId;
    this.store = options.store ?? authCredentialStore;
    this.updateConfig = options.updateConfig ?? ((next) => config.update(next));
    this.withRefreshLock = options.withRefreshLock ?? withAuthRefreshLock;
  }

  async saveSession(tokens: WorkOSSessionTokens): Promise<CredentialBackend> {
    return this.withRefreshLock(async () => {
      this.refreshPromise = null;
      const backend = await this.store.save(tokens.refreshToken);
      this.accessToken = tokens.accessToken;
      try {
        await this.updateConfig({
          accessToken: null,
          refreshToken: null,
          workosSession: true,
          credentialBackend: backend,
        });
      } catch (error) {
        await this.clearSessionUnlocked();
        throw error;
      }
      return backend;
    });
  }

  private async clearSessionUnlocked(): Promise<void> {
    this.refreshPromise = null;
    this.accessToken = null;
    await this.store.clear();
    await this.updateConfig({
      accessToken: null,
      refreshToken: null,
      workosSession: false,
      credentialBackend: null,
    });
  }

  async clearSession(): Promise<void> {
    return this.withRefreshLock(() => this.clearSessionUnlocked());
  }

  async ensureValidToken(
    current: TokenConfig,
    options: EnsureValidTokenOptions = {},
  ): Promise<ValidToken | null> {
    await this.migrateLegacyTokens(current);

    if (
      options.forceRefresh &&
      options.rejectedToken &&
      this.accessToken &&
      this.accessToken !== options.rejectedToken &&
      !isTokenExpired(this.accessToken)
    ) {
      return { token: this.accessToken, type: "workos" };
    }

    if (
      !options.forceRefresh &&
      this.accessToken &&
      !isTokenExpired(this.accessToken)
    ) {
      return { token: this.accessToken, type: "workos" };
    }

    let stored: StoredRefreshToken | null;
    try {
      stored = await this.store.load();
    } catch (error) {
      if (error instanceof CredentialStoreUnavailableError) {
        throw new AuthRefreshError(
          "Unable to access secure Pensar credentials. Unlock your system credential store and try again.",
          { cause: error },
        );
      }
      throw error;
    }
    if (stored) {
      try {
        return await this.refreshAccessToken(options);
      } catch (error) {
        if (error instanceof AuthSessionExpiredError && current.pensarAPIKey) {
          return { token: current.pensarAPIKey, type: "legacy" };
        }
        throw error;
      }
    }

    if (current.accessToken && !isTokenExpired(current.accessToken)) {
      this.accessToken = current.accessToken;
      return { token: current.accessToken, type: "workos" };
    }

    if (current.workosSession) {
      await this.updateConfig({
        workosSession: false,
        credentialBackend: null,
      });
      if (!current.pensarAPIKey) throw new AuthSessionExpiredError();
    }

    if (current.pensarAPIKey) {
      return { token: current.pensarAPIKey, type: "legacy" };
    }

    return null;
  }

  private async migrateLegacyTokens(current: TokenConfig): Promise<void> {
    const legacyRefreshToken = current.refreshToken;
    if (!legacyRefreshToken) {
      if (current.accessToken && !this.accessToken) {
        this.accessToken = current.accessToken;
      }
      return;
    }
    if (current.workosSession !== undefined) {
      return;
    }
    if (this.migrationPromise) return this.migrationPromise;

    this.migrationPromise = this.withRefreshLock(async () => {
      const existing = await this.store.load().catch((error) => {
        if (error instanceof CredentialStoreUnavailableError) return null;
        throw error;
      });
      const backend =
        existing?.backend ?? (await this.store.save(legacyRefreshToken));
      if (current.accessToken && !isTokenExpired(current.accessToken)) {
        this.accessToken = current.accessToken;
      }
      await this.updateConfig({
        accessToken: null,
        refreshToken: null,
        workosSession: true,
        credentialBackend: backend,
      });
      log.info("Migrated WorkOS refresh token out of config", { backend });
    }).finally(() => {
      this.migrationPromise = null;
    });

    return this.migrationPromise;
  }

  private async refreshAccessToken(
    options: EnsureValidTokenOptions,
  ): Promise<ValidToken> {
    if (this.refreshPromise) return this.refreshPromise;

    this.refreshPromise = this.withRefreshLock(async () => {
      if (
        options.forceRefresh &&
        options.rejectedToken &&
        this.accessToken &&
        this.accessToken !== options.rejectedToken &&
        !isTokenExpired(this.accessToken)
      ) {
        return { token: this.accessToken, type: "workos" as const };
      }

      if (
        !options.forceRefresh &&
        this.accessToken &&
        !isTokenExpired(this.accessToken)
      ) {
        return { token: this.accessToken, type: "workos" as const };
      }

      let stored: StoredRefreshToken | null;
      try {
        stored = await this.store.load();
      } catch (error) {
        if (error instanceof CredentialStoreUnavailableError) {
          throw new AuthRefreshError(
            "Unable to access secure Pensar credentials. Unlock your system credential store and try again.",
            { cause: error },
          );
        }
        throw error;
      }
      if (!stored) {
        await this.updateConfig({
          workosSession: false,
          credentialBackend: null,
        });
        throw new AuthSessionExpiredError();
      }

      const clientId = await this.getClientId();
      if (!clientId) {
        throw new AuthRefreshError(
          "Unable to refresh Pensar authentication. Check your connection and try again.",
        );
      }

      let response: Response;
      try {
        response = await this.fetchImpl(
          "https://api.workos.com/user_management/authenticate",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            signal: AbortSignal.timeout(15_000),
            body: JSON.stringify({
              client_id: clientId,
              grant_type: "refresh_token",
              refresh_token: stored.refreshToken,
            }),
          },
        );
      } catch (error) {
        throw new AuthRefreshError(
          "Unable to refresh Pensar authentication. Check your connection and try again.",
          { cause: error },
        );
      }

      if (response.status === 400 || response.status === 401) {
        await this.clearSessionUnlocked();
        throw new AuthSessionExpiredError();
      }
      if (!response.ok) {
        throw new AuthRefreshError(
          `Unable to refresh Pensar authentication (${response.status}). Try again shortly.`,
        );
      }

      let data: Partial<{
        access_token: string;
        refresh_token: string;
      }>;
      try {
        data = (await response.json()) as typeof data;
      } catch (error) {
        throw new AuthRefreshError(
          "WorkOS returned an invalid token refresh response.",
          { cause: error },
        );
      }
      if (!data.access_token || !data.refresh_token) {
        throw new AuthRefreshError(
          "WorkOS returned an incomplete token refresh response.",
        );
      }

      const backend = await this.store.save(data.refresh_token);
      this.accessToken = data.access_token;
      await this.updateConfig({
        accessToken: null,
        refreshToken: null,
        workosSession: true,
        credentialBackend: backend,
      });
      return { token: data.access_token, type: "workos" as const };
    }).finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }
}

const tokenManager = new WorkOSTokenManager();

export function ensureValidToken(
  current: TokenConfig,
  options?: EnsureValidTokenOptions,
): Promise<ValidToken | null> {
  return tokenManager.ensureValidToken(current, options);
}

export function saveWorkOSSession(
  tokens: WorkOSSessionTokens,
): Promise<CredentialBackend> {
  return tokenManager.saveSession(tokens);
}

export function clearWorkOSSession(): Promise<void> {
  return tokenManager.clearSession();
}
