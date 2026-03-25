// ---------------------------------------------------------------------------
// Interactsh client types
// ---------------------------------------------------------------------------

/** Configuration for the interactsh client. */
export interface InteractshConfig {
  /** Server base URL (default: "https://oast.pro"). */
  serverUrl?: string;
  /** Auth token for self-hosted servers. */
  authToken?: string;
  /** Length of the correlation ID (default: 20). */
  correlationIdLength?: number;
  /** RSA key size in bits (default: 2048). */
  rsaKeySize?: number;
}

/** Internal session state after successful registration. */
export interface InteractshSession {
  /** Correlation ID used to identify this client session. */
  correlationId: string;
  /** Secret key used for polling. */
  secretKey: string;
  /** Base interaction domain (e.g., "oast.pro"). */
  interactionDomain: string;
  /** RSA private key PEM -- kept in memory, never exposed to the agent. */
  privateKey: string;
  /** RSA public key PEM. */
  publicKey: string;
  /** Full base interaction URL (e.g., "abc123...xyz.oast.pro"). */
  interactionUrl: string;
}

/** Protocols captured by the interactsh server. */
export type InteractionProtocol =
  | "dns"
  | "http"
  | "smtp"
  | "ldap"
  | "ftp"
  | "smb"
  | "responder";

/** A single captured OOB interaction. */
export interface Interaction {
  /** Protocol of the interaction. */
  protocol: InteractionProtocol;
  /** Unique ID of the interaction. */
  "unique-id": string;
  /** Full interaction identifier (subdomain that was contacted). */
  "full-id": string;
  /** Raw request data (HTTP headers/body, DNS query, etc.). */
  "raw-request": string;
  /** Raw response data. */
  "raw-response": string;
  /** Remote address of the interacting party. */
  "remote-address": string;
  /** ISO 8601 timestamp of the interaction. */
  timestamp: string;
  /** DNS query type (e.g., "A", "AAAA", "CNAME"). */
  "q-type"?: string;
}

/** Defaults applied when config values are omitted. */
export const DEFAULTS = {
  serverUrl: "https://oast.pro",
  correlationIdLength: 20,
  rsaKeySize: 2048,
} as const;

/** Character set used to generate correlation IDs (matches interactsh-go). */
export const CORRELATION_CHARSET =
  "abcdefghijklmnopqrstuvwxyz0123456789" as const;
