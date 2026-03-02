/**
 * Credential management types.
 *
 * Separates sensitive credential data from the metadata
 * that agents are allowed to see. Agents work with
 * {@link CredentialReference} objects (id + descriptive metadata)
 * while the actual secrets live only inside the
 * {@link CredentialManager} and are resolved at tool-execution time.
 */

/**
 * Discriminator for credential storage format.
 */
export type CredentialType =
  | "username-password"
  | "api-key"
  | "bearer-token"
  | "custom-headers"
  | "cookies"
  | "composite";

/**
 * Full credential record stored in the manager.
 * Contains the actual secrets — never exposed to the agent.
 */
export interface StoredCredential {
  /** Unique identifier assigned on storage */
  id: string;

  /** Human-readable label (e.g. "admin account", "staging API key") */
  label?: string;

  /** Credential type discriminator */
  type: CredentialType;

  /** Role associated with the credential (e.g. "admin", "user", "readonly") */
  role?: string;

  /** Username / email (non-secret, also surfaced in the reference) */
  username?: string;

  /** Login URL hint */
  loginUrl?: string;

  // -- secret fields (never exposed to agent) --------------------------------

  /** Password */
  password?: string;

  /** API key */
  apiKey?: string;

  /** Pre-existing tokens */
  tokens?: {
    bearerToken?: string;
    cookies?: string;
    sessionToken?: string;
    customHeaders?: Record<string, string>;
  };

  /** Extra form fields (e.g. CSRF tokens, account IDs) */
  additionalFields?: Record<string, string>;

  /** Arbitrary metadata consumers can attach */
  metadata?: Record<string, unknown>;
}

/**
 * The sanitised view of a credential that is safe to include in prompts.
 * Contains enough information for the agent to decide *which* credential
 * to use, but none of the actual secrets.
 */
export interface CredentialReference {
  /** The credential ID the agent must pass back to use this credential */
  id: string;

  /** Human-readable label */
  label?: string;

  /** Credential type */
  type: CredentialType;

  /** Role (e.g. "admin", "user") */
  role?: string;

  /** Username / email — non-secret context */
  username?: string;

  /** Login URL hint */
  loginUrl?: string;

  /** Names of custom header keys (values redacted) */
  customHeaderKeys?: string[];

  /** Usage context / notes about when and how to use this credential */
  context?: string;
}
