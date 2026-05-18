export { disconnect, isConnected } from "./connection";
export {
  pollLegacyToken,
  pollWorkOSToken,
  startDeviceFlow,
} from "./device-flow";
export type { GatewayValidateResult } from "./gateway";
export { validateGateway } from "./gateway";
export { signGatewayRequest } from "./signing";
export { ensureValidToken, isTokenExpired } from "./token";
export type {
  DeviceFlowInfo,
  FetchWorkspacesResponse,
  LegacyDeviceCodeResponse,
  LegacyTokenResponse,
  SelectWorkspaceResponse,
  ValidToken,
  WorkOSDeviceResponse,
  WorkspaceInfo,
} from "./types";

export { signGatewayRequest } from "./signing";

export {
  isTokenExpired,
  fetchWorkOSClientId,
  refreshAccessToken,
  ensureValidToken,
  ensureValidTokenOrThrow,
  ApexAuthError,
  isApexAuthError,
} from "./token";
export type { ApexAuthReason, EnsureValidTokenOptions } from "./token";

export {
  startDeviceFlow,
  pollWorkOSToken,
  pollLegacyToken,
} from "./device-flow";

export {
  fetchWorkspaces,
  pollForWorkspaceCreation,
  selectWorkspace,
} from "./workspaces";
