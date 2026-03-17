export type {
  WorkOSDeviceResponse,
  LegacyDeviceCodeResponse,
  LegacyTokenResponse,
  WorkspaceInfo,
  FetchWorkspacesResponse,
  SelectWorkspaceResponse,
  DeviceFlowInfo,
  ValidToken,
} from "./types";

export { signGatewayRequest } from "./signing";

export {
  isTokenExpired,
  fetchWorkOSClientId,
  refreshAccessToken,
  ensureValidToken,
} from "./token";

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

export { isConnected, disconnect } from "./connection";
