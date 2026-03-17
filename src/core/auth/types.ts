/**
 * Shared types for Pensar Console authentication.
 *
 * These cover the WorkOS device-flow, the legacy device-code flow,
 * workspace management, and token lifecycle.
 */

// ---------------------------------------------------------------------------
// WorkOS device-code flow
// ---------------------------------------------------------------------------

export interface WorkOSDeviceResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

// ---------------------------------------------------------------------------
// Legacy device-code flow (backward compat with older backends)
// ---------------------------------------------------------------------------

export interface LegacyDeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

export interface LegacyTokenResponse {
  status: "pending" | "complete" | "expired" | "not_found";
  apiKey?: string;
  workspace?: { id: string; name: string; slug: string };
  credits?: { balance: number };
  signingKey?: string;
  gatewayUrl?: string;
}

// ---------------------------------------------------------------------------
// Workspaces
// ---------------------------------------------------------------------------

export interface WorkspaceInfo {
  id: string;
  name: string;
  slug: string;
  balance: number;
  hasPaymentMethod: boolean;
}

export interface SelectWorkspaceResponse {
  confirmed: boolean;
  workspace: { id: string; name: string; slug: string };
  billing: { balance: number; hasPaymentMethod: boolean; ready: boolean };
  billingUrl?: string;
  signingKey?: string;
  gatewayUrl?: string;
}

// ---------------------------------------------------------------------------
// Device-flow start result (discriminated union)
// ---------------------------------------------------------------------------

export type DeviceFlowInfo =
  | {
      mode: "workos";
      clientId: string;
      deviceInfo: WorkOSDeviceResponse;
    }
  | {
      mode: "legacy";
      deviceInfo: LegacyDeviceCodeResponse;
    };

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

export interface ValidToken {
  token: string;
  type: "workos" | "legacy";
}
