/**
 * In-memory credential manager.
 *
 * Stores full credentials keyed by a generated ID.
 * Agents only ever receive {@link CredentialReference} objects;
 * secrets are resolved at tool-execution time via {@link resolve}.
 */

import { randomBytes } from "crypto";
import type { AuthCredentials } from "../session";
import type {
  CredentialReference,
  CredentialType,
  StoredCredential,
} from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateCredentialId(): string {
  return `cred_${randomBytes(8).toString("hex")}`;
}

function inferType(
  cred: Omit<StoredCredential, "id" | "type">,
): CredentialType {
  const hasPwd = !!cred.password;
  const hasApiKey = !!cred.apiKey;
  const hasBearer = !!cred.tokens?.bearerToken;
  const hasHeaders =
    !!cred.tokens?.customHeaders &&
    Object.keys(cred.tokens.customHeaders).length > 0;
  const hasCookies = !!cred.tokens?.cookies;

  const count =
    (hasPwd ? 1 : 0) +
    (hasApiKey ? 1 : 0) +
    (hasBearer ? 1 : 0) +
    (hasHeaders ? 1 : 0) +
    (hasCookies ? 1 : 0);

  if (count > 1) return "composite";
  if (hasPwd) return "username-password";
  if (hasApiKey) return "api-key";
  if (hasBearer) return "bearer-token";
  if (hasHeaders) return "custom-headers";
  if (hasCookies) return "cookies";
  return "username-password";
}

function toReference(stored: StoredCredential): CredentialReference {
  const ref: CredentialReference = {
    id: stored.id,
    type: stored.type,
  };
  if (stored.label) ref.label = stored.label;
  if (stored.role) ref.role = stored.role;
  if (stored.username) ref.username = stored.username;
  if (stored.loginUrl) ref.loginUrl = stored.loginUrl;
  if (stored.tokens?.customHeaders) {
    ref.customHeaderKeys = Object.keys(stored.tokens.customHeaders);
  }
  const ctx = stored.metadata?.context;
  if (typeof ctx === "string" && ctx) ref.context = ctx;
  return ref;
}

// ---------------------------------------------------------------------------
// CredentialManager
// ---------------------------------------------------------------------------

export class CredentialManager {
  private readonly store = new Map<string, StoredCredential>();

  /**
   * Return the ID of an existing credential whose meaningful secret
   * fields match `candidate`, or `undefined` if no match is found.
   */
  private findDuplicate(
    candidate: Omit<StoredCredential, "id" | "type">,
  ): string | undefined {
    for (const [id, existing] of this.store) {
      if (
        existing.username === candidate.username &&
        existing.password === candidate.password &&
        existing.apiKey === candidate.apiKey &&
        existing.loginUrl === candidate.loginUrl &&
        existing.tokens?.bearerToken === candidate.tokens?.bearerToken &&
        existing.tokens?.cookies === candidate.tokens?.cookies &&
        existing.tokens?.sessionToken === candidate.tokens?.sessionToken &&
        JSON.stringify(existing.tokens?.customHeaders) ===
          JSON.stringify(candidate.tokens?.customHeaders)
      ) {
        return id;
      }
    }
    return undefined;
  }

  /**
   * Store a credential and return its generated ID.
   *
   * If `input.id` is provided it will be used as-is (useful for
   * deterministic IDs in tests); otherwise a random ID is generated.
   */
  add(
    input: Omit<StoredCredential, "id" | "type"> & {
      id?: string;
      type?: CredentialType;
    },
  ): string {
    const id = input.id ?? generateCredentialId();
    const type = input.type ?? inferType(input);

    const stored: StoredCredential = { ...input, id, type };
    this.store.set(id, stored);
    return id;
  }

  /**
   * Convenience method: convert an {@link AuthCredentials} object (the
   * legacy session-level format) into a stored credential and return
   * the ID.  If an equivalent credential already exists (same username,
   * password, apiKey, loginUrl, and tokens), returns the existing ID
   * instead of creating a duplicate.
   */
  addFromAuthCredentials(
    creds: AuthCredentials,
    extra?: { label?: string; role?: string },
  ): string {
    const candidate = {
      username: creds.username,
      password: creds.password,
      apiKey: creds.apiKey,
      loginUrl: creds.loginUrl,
      additionalFields: creds.additionalFields,
      tokens: creds.tokens,
      label: extra?.label,
      role: extra?.role ?? creds.role,
      metadata: creds.context ? { context: creds.context } : undefined,
    };

    const existingId = this.findDuplicate(candidate);
    if (existingId) return existingId;

    return this.add(candidate);
  }

  /**
   * Resolve a credential ID to the full {@link StoredCredential}.
   * Returns `undefined` if the ID is unknown.
   *
   * This is the **only** way to access secrets and should only be
   * called inside tool execution code — never in prompt builders.
   */
  resolve(credentialId: string): StoredCredential | undefined {
    return this.store.get(credentialId);
  }

  /**
   * Return the safe {@link CredentialReference} for a stored credential.
   */
  getReference(credentialId: string): CredentialReference | undefined {
    const stored = this.store.get(credentialId);
    if (!stored) return undefined;
    return toReference(stored);
  }

  /**
   * List all stored credential references (safe for agent prompts).
   */
  listReferences(): CredentialReference[] {
    return Array.from(this.store.values()).map(toReference);
  }

  /**
   * Return stored credentials that have customHeaders set, with the
   * header values intact. Consumed ONLY by the target-HTTP header
   * resolver (`src/core/http/targetHeaders.ts`) to merge per-credential
   * headers into outbound requests at the credential layer
   * (INV-precedence-deterministic). Other consumers should use
   * `listReferences()` which returns only key names.
   */
  listCredentialsWithHeaders(): Array<{
    tokens: { customHeaders: Record<string, string> };
  }> {
    const out: Array<{ tokens: { customHeaders: Record<string, string> } }> =
      [];
    for (const stored of this.store.values()) {
      const headers = stored.tokens?.customHeaders;
      if (headers && Object.keys(headers).length > 0) {
        out.push({ tokens: { customHeaders: { ...headers } } });
      }
    }
    return out;
  }

  /**
   * Remove a credential from the store.
   * Returns `true` if the credential existed and was removed.
   */
  remove(credentialId: string): boolean {
    return this.store.delete(credentialId);
  }

  /** Number of credentials currently stored. */
  get size(): number {
    return this.store.size;
  }

  /** Remove all stored credentials. */
  clear(): void {
    this.store.clear();
  }

  /**
   * Convert a stored credential back to the legacy {@link AuthCredentials}
   * format. Useful for interop with code that still expects the old shape.
   */
  toAuthCredentials(credentialId: string): AuthCredentials | undefined {
    const stored = this.resolve(credentialId);
    if (!stored) return undefined;

    const result: AuthCredentials = {};
    if (stored.username) result.username = stored.username;
    if (stored.password) result.password = stored.password;
    if (stored.apiKey) result.apiKey = stored.apiKey;
    if (stored.loginUrl) result.loginUrl = stored.loginUrl;
    if (stored.additionalFields)
      result.additionalFields = stored.additionalFields;
    if (stored.tokens) result.tokens = { ...stored.tokens };
    return result;
  }

  /**
   * Format credential references into a prompt-safe block.
   * Suitable for injection into agent system/user prompts.
   */
  formatForPrompt(): string {
    const refs = this.listReferences();
    if (refs.length === 0) return "";

    const lines = refs.map((ref) => {
      const parts: string[] = [`- Credential ID: ${ref.id}`];
      if (ref.label) parts.push(`  Label: ${ref.label}`);
      parts.push(`  Type: ${ref.type}`);
      if (ref.role) parts.push(`  Role: ${ref.role}`);
      if (ref.username) parts.push(`  Username: ${ref.username}`);
      if (ref.loginUrl) parts.push(`  Login URL: ${ref.loginUrl}`);
      if (ref.customHeaderKeys?.length) {
        parts.push(`  Header keys: ${ref.customHeaderKeys.join(", ")}`);
      }
      if (ref.context) parts.push(`  Context: ${ref.context}`);
      return parts.join("\n");
    });

    return `<available_credentials>
The following credentials are available. To use a credential, pass its ID to the appropriate tool.
Do NOT ask the user for passwords or secrets — they are resolved automatically from the credential ID.

${lines.join("\n\n")}
</available_credentials>`;
  }
}
