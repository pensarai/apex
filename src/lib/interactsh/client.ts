// ---------------------------------------------------------------------------
// Interactsh client
//
// Implements the interactsh REST+crypto protocol for OOB interaction
// detection. No external dependencies beyond Node.js crypto + native fetch.
// ---------------------------------------------------------------------------

import type {
  InteractshConfig,
  InteractshSession,
  Interaction,
} from "./types";
import { DEFAULTS } from "./types";
import {
  generateRsaKeyPair,
  generateCorrelationId,
  generateSecretKey,
  rsaDecrypt,
  aesDecrypt,
} from "./crypto";

export class InteractshClient {
  private readonly config: {
    serverUrl: string;
    authToken?: string;
    correlationIdLength: number;
    rsaKeySize: number;
  };

  private session: InteractshSession | null = null;

  constructor(config?: InteractshConfig) {
    const serverUrl = (
      config?.serverUrl ?? DEFAULTS.serverUrl
    ).replace(/\/+$/, "");

    this.config = {
      serverUrl,
      authToken: config?.authToken,
      correlationIdLength:
        config?.correlationIdLength ?? DEFAULTS.correlationIdLength,
      rsaKeySize: config?.rsaKeySize ?? DEFAULTS.rsaKeySize,
    };
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /** Whether the client has an active registration. */
  get isRegistered(): boolean {
    return this.session !== null;
  }

  /** The base interaction URL (available after register()). */
  get interactionUrl(): string | null {
    return this.session?.interactionUrl ?? null;
  }

  /** The correlation ID (available after register()). */
  get correlationId(): string | null {
    return this.session?.correlationId ?? null;
  }

  /**
   * Register with the interactsh server.
   *
   * Generates an RSA keypair and correlation ID, then POSTs to `/register`.
   * After success the client is ready to generate payload URLs and poll.
   */
  async register(
    abortSignal?: AbortSignal,
  ): Promise<{ interactionUrl: string; correlationId: string }> {
    if (this.session) {
      throw new Error("Already registered — call deregister() first");
    }

    const { publicKey, privateKey, publicKeyDer } = generateRsaKeyPair(
      this.config.rsaKeySize,
    );
    const correlationId = generateCorrelationId(
      this.config.correlationIdLength,
    );
    const secretKey = generateSecretKey();

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.config.authToken) {
      headers["Authorization"] = this.config.authToken;
    }

    const response = await fetch(`${this.config.serverUrl}/register`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        "public-key": publicKeyDer.toString("base64"),
        "secret-key": secretKey,
        "correlation-id": correlationId,
      }),
      signal: abortSignal,
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(
        `Interactsh registration failed (${response.status}): ${body}`,
      );
    }

    // Extract the interaction domain from the server URL
    const interactionDomain = new URL(this.config.serverUrl).hostname;
    const interactionUrl = `${correlationId}.${interactionDomain}`;

    this.session = {
      correlationId,
      secretKey,
      interactionDomain,
      privateKey,
      publicKey,
      interactionUrl,
    };

    return { interactionUrl, correlationId };
  }

  /**
   * Generate a unique payload URL for a specific injection point.
   *
   * The optional `label` is prepended as a subdomain so you can attribute
   * which injection point triggered the interaction when polling.
   *
   * @example
   *   client.generatePayloadUrl("ssrf1")
   *   // → "ssrf1.abc123...xyz.oast.pro"
   */
  generatePayloadUrl(label?: string): string {
    if (!this.session) {
      throw new Error("Not registered — call register() first");
    }
    if (label) {
      return `${label}.${this.session.interactionUrl}`;
    }
    return this.session.interactionUrl;
  }

  /**
   * Poll for new interactions.
   *
   * Returns an array of decrypted {@link Interaction} objects received since
   * the last poll (or since registration if this is the first poll).
   */
  async poll(abortSignal?: AbortSignal): Promise<Interaction[]> {
    if (!this.session) {
      throw new Error("Not registered — call register() first");
    }

    const headers: Record<string, string> = {};
    if (this.config.authToken) {
      headers["Authorization"] = this.config.authToken;
    }

    const url = `${this.config.serverUrl}/poll?id=${this.session.correlationId}&secret=${this.session.secretKey}`;

    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: abortSignal,
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(
        `Interactsh poll failed (${response.status}): ${body}`,
      );
    }

    const result = (await response.json()) as {
      data: string[] | null;
      aes_key: string;
      extra: number;
    };

    if (!result.data || result.data.length === 0) {
      return [];
    }

    return this.decryptInteractions(result.data, result.aes_key);
  }

  /**
   * Deregister from the interactsh server and clean up.
   *
   * Safe to call multiple times — no-ops if not registered.
   */
  async deregister(): Promise<void> {
    if (!this.session) return;

    const { correlationId, secretKey } = this.session;
    this.session = null;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.config.authToken) {
      headers["Authorization"] = this.config.authToken;
    }

    try {
      await fetch(`${this.config.serverUrl}/deregister`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          "secret-key": secretKey,
          "correlation-id": correlationId,
        }),
      });
    } catch {
      // Best-effort cleanup — swallow errors
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Decrypt poll response data.
   *
   * Each entry in `data` is base64-encoded, AES-256-CFB encrypted JSON.
   * The `aesKey` is base64-encoded, RSA-OAEP encrypted with the client's
   * public key. We decrypt the AES key first, then each data entry.
   */
  private decryptInteractions(
    data: string[],
    aesKeyEncrypted: string,
  ): Interaction[] {
    const aesKey = rsaDecrypt(
      Buffer.from(aesKeyEncrypted, "base64"),
      this.session!.privateKey,
    );

    const interactions: Interaction[] = [];

    for (const entry of data) {
      try {
        const encrypted = Buffer.from(entry, "base64");
        const decrypted = aesDecrypt(encrypted, aesKey);
        const parsed = JSON.parse(decrypted.toString("utf-8")) as Interaction;
        interactions.push(parsed);
      } catch {
        // Skip entries that fail to decrypt/parse — server may include
        // malformed data or the protocol version may differ slightly.
      }
    }

    return interactions;
  }
}
